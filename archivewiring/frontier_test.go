package archivewiring

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/engineapi"
	"github.com/unicitynetwork/bft-core/frontier"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-go-base/types"
)

type fixtureAvailability struct{ stores map[string]*archive.Store }

type digestAvailability struct {
	copies map[string]map[[32]byte][32]byte
}

func (a digestAvailability) VerifyAvailable(name string, q archive.Request, want [32]byte) error {
	if a.copies[name][q.BlockHash] != want {
		return frontier.ErrUnavailable
	}
	return nil
}

func (a fixtureAvailability) VerifyAvailable(name string, q archive.Request, want [32]byte) error {
	s := a.stores[name]
	if s == nil {
		return frontier.ErrUnavailable
	}
	r, err := s.Get(q)
	if err != nil {
		return err
	}
	got, err := archive.ManifestDigest(q, r)
	if err != nil || got != want {
		return frontier.ErrUnavailable
	}
	return nil
}

func TestCertifiedBindingAuthenticatesArchiveRolesAndHeader(t *testing.T) {
	f := newWiringFixture(t, 1)
	q, record := f.record(t, 0)
	request, err := archive.EncodeRequest(q)
	require.NoError(t, err)
	digest, err := archive.ManifestDigest(q, record)
	require.NoError(t, err)
	var state [32]byte
	copy(state[:], f.entries[0].Candidate.StateRoot)
	r := frontier.Record{Sequence: 1, Round: f.entries[0].ResultingUC.GetRootRoundNumber(), Height: 1, StateRoot: state, Subject: q, Acks: [2]frontier.Acknowledgment{{Replica: "first", RequestDigest: sha256.Sum256(request), ManifestDigest: digest}, {Replica: "second", RequestDigest: sha256.Sum256(request), ManifestDigest: digest}}}
	v := CertifiedBinding{Context: f.context, Subject: f.subject}
	require.NoError(t, v.VerifyCertified(r, record))
	// An independently valid resulting UC for the same round and state still
	// must name the exact archived block.
	wrongIR := *f.entries[0].ResultingUC.InputRecord
	wrongIR.BlockHash = bytes.Repeat([]byte{0xa5}, 32)
	wrongUC, wrongTR := signWiring(t, f.chain, &wrongIR, 2, r.Round)
	badResult := *record
	badResult.ResultingUC, err = types.Cbor.Marshal(wrongUC)
	require.NoError(t, err)
	badResult.ResultingTR, err = types.Cbor.Marshal(wrongTR)
	require.NoError(t, err)
	require.ErrorIs(t, v.VerifyCertified(r, &badResult), frontier.ErrInvalid)
	// Both certificates authenticate individually, but two different input
	// records at the same partition round are equivocation and cannot bind an
	// archive record.
	wrongOriginalIR := *f.entries[0].ResultingUC.InputRecord
	wrongOriginalIR.Hash = bytes.Repeat([]byte{0x9a}, 32)
	wrongOriginalIR.BlockHash = bytes.Repeat([]byte{0x9b}, 32)
	wrongOriginal, wrongOriginalTR := signWiring(t, f.chain, &wrongOriginalIR, 1, r.Round-1)
	bad := *record
	bad.OriginalUC, err = types.Cbor.Marshal(wrongOriginal)
	require.NoError(t, err)
	bad.OriginalTR, err = types.Cbor.Marshal(wrongOriginalTR)
	require.NoError(t, err)
	var companion engineapi.SealCompanion
	require.NoError(t, json.Unmarshal(bad.Companion, &companion))
	companion.Witnesses[0], err = types.Cbor.Marshal(wrongOriginal)
	require.NoError(t, err)
	companion.Witnesses[1], err = types.Cbor.Marshal(wrongOriginalTR)
	require.NoError(t, err)
	bad.Companion, err = json.Marshal(companion)
	require.NoError(t, err)
	require.ErrorIs(t, v.VerifyCertified(r, &bad), frontier.ErrInvalid)
	bad = *record
	bad.OriginalUC = append([]byte(nil), record.ResultingUC...)
	require.ErrorIs(t, v.VerifyCertified(r, &bad), frontier.ErrInvalid)
	bad = *record
	bad.Companion = append([]byte(nil), record.Companion...)
	marker := []byte(`"witnesses":["0x`)
	position := bytes.Index(bad.Companion, marker)
	require.GreaterOrEqual(t, position, 0)
	position += len(marker)
	if bad.Companion[position] == '0' {
		bad.Companion[position] = '1'
	} else {
		bad.Companion[position] = '0'
	}
	require.ErrorIs(t, v.VerifyCertified(r, &bad), frontier.ErrInvalid)
	r.Round++
	require.ErrorIs(t, v.VerifyCertified(r, record), frontier.ErrInvalid)
	r.Round--
	r.StateRoot[0] ^= 1
	require.ErrorIs(t, v.VerifyCertified(r, record), frontier.ErrInvalid)
}

func TestFrontierJournalAdvancePruneAndRestart(t *testing.T) {
	f := newWiringFixture(t, 6)
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	first, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	second, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	for i := range f.entries {
		q, rec := f.record(t, i)
		for _, s := range []*archive.Store{local, first, second} {
			require.NoError(t, s.Put(q, rec))
		}
	}
	peers := [2]peer.ID{"first", "second"}
	policy := frontier.Policy{Context: f.subject, Replicas: [2]string{peers[0].String(), peers[1].String()}, Binding: CertifiedBinding{Context: f.context, Subject: f.subject}, Availability: fixtureAvailability{stores: map[string]*archive.Store{peers[0].String(): first, peers[1].String(): second}}}
	require.NoError(t, f.store.EnableFrontier(context.Background(), f.context, f.limits, policy))
	finalizedAt := func(height uint64) shardnode.BlockRef {
		for _, entry := range f.entries {
			if entry.Candidate.Number == height {
				return shardnode.BlockRef{Number: height, Hash: entry.Candidate.Hash}
			}
		}
		t.Fatalf("missing certified fixture height %d", height)
		return shardnode.BlockRef{}
	}
	finalized := finalizedAt(3)
	worker := &FrontierWorker{Journal: f.store, Context: f.context, Limits: f.limits, Archive: local, Subject: f.subject, Replicas: peers,
		Finalized: func(context.Context) (shardnode.BlockRef, error) { return finalized, nil }}
	require.NoError(t, worker.Pass(context.Background()))
	partial, err := f.store.LoadJournal(context.Background(), f.context, f.limits)
	require.NoError(t, err)
	require.EqualValues(t, 3, partial.Frontier.Anchor.Height, "archive acknowledgments cannot prune beyond local EL finality")
	finalized = finalizedAt(6)
	require.NoError(t, worker.Pass(context.Background()))
	image, err := f.store.LoadJournal(context.Background(), f.context, f.limits)
	require.NoError(t, err)
	require.NotNil(t, image.Frontier)
	require.EqualValues(t, 6, image.Frontier.Anchor.Height)
	require.EqualValues(t, 6, image.Frontier.Floor)
	require.Len(t, image.Candidates, 1)
	require.Equal(t, image.Frontier.Anchor.Subject.BlockHash[:], image.Candidates[0].Candidate.Hash)
	require.NotEmpty(t, image.Candidates[0].Candidate.Raw)
	require.Empty(t, image.Observations)
	var oldQ archive.Request
	var oldRec *archive.Record
	for i, entry := range f.entries {
		if entry.Candidate.Number == 1 {
			oldQ, oldRec = f.record(t, i)
			break
		}
	}
	require.NotNil(t, oldRec)
	verify := JournalVerifier(f.store, f.context, f.limits, f.subject)
	require.NoError(t, verify(context.Background(), oldQ, oldRec))
	changed := *oldRec
	changed.Body = append([]byte(nil), oldRec.Header...)
	require.ErrorIs(t, verify(context.Background(), oldQ, &changed), ErrUncertified)
}

func TestFrontierPruneSweepKeepsTimeoutRepeatBodies(t *testing.T) {
	f := newWiringFixtureWithTimeouts(t, 8)
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	first, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	second, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	for i := range f.entries {
		q, rec := f.record(t, i)
		for _, s := range []*archive.Store{local, first, second} {
			require.NoError(t, s.Put(q, rec))
		}
	}
	peers := [2]peer.ID{"first", "second"}
	policy := frontier.Policy{Context: f.subject, Replicas: [2]string{peers[0].String(), peers[1].String()}, Binding: CertifiedBinding{Context: f.context, Subject: f.subject}, Availability: fixtureAvailability{stores: map[string]*archive.Store{peers[0].String(): first, peers[1].String(): second}}}
	require.NoError(t, f.store.EnableFrontier(context.Background(), f.context, f.limits, policy))
	worker := &FrontierWorker{Journal: f.store, Context: f.context, Limits: f.limits, Archive: local, Subject: f.subject, Replicas: peers}

	for _, height := range []uint64{4, 8} {
		require.NoError(t, worker.Pass(context.Background()))
		image, err := f.store.LoadJournal(context.Background(), f.context, f.limits)
		require.NoError(t, err)
		require.Equal(t, height, image.Frontier.Anchor.Height)
		require.NotEmpty(t, image.Candidates)
		anchorFound := false
		for _, candidate := range image.Candidates {
			if bytes.Equal(candidate.Candidate.Hash, image.Frontier.Anchor.Subject.BlockHash[:]) {
				anchorFound = true
				require.NotEmpty(t, candidate.Candidate.Raw)
			}
		}
		require.True(t, anchorFound, "frontier anchor body remains materialized")
	}

	var latest configuredprogress.JournalEntry
	for _, entry := range f.entries {
		if entry.Candidate.Number > latest.Candidate.Number {
			latest = entry
		}
	}
	last := latest.ResultingUC.InputRecord
	continuedUC, continuedTR := signWiring(t, f.chain, last, latest.Candidate.Round+1, latest.ResultingUC.GetRootRoundNumber()+2)
	continued, err := rootinput.AuthenticateObservationV2(context.Background(), f.context.Observation, continuedUC, continuedTR)
	require.NoError(t, err)
	p, outcome, err := f.store.PrepareObservation(context.Background(), f.context, continued)
	require.NoError(t, err)
	require.Equal(t, configuredprogress.ObservationRepeated, outcome)
	_, _, err = f.store.CommitObservation(p)
	require.NoError(t, err)
	_, err = f.store.LoadJournal(context.Background(), f.context, f.limits)
	require.NoError(t, err)
}

func TestFrontierPacedAuditRepairsPrunedReplica(t *testing.T) {
	f := newWiringFixture(t, 6)
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	firstPeer := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	secondPeer := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	for _, remote := range []*network.Peer{firstPeer, secondPeer} {
		sender.Network().Peerstore().AddAddrs(remote.ID(), remote.MultiAddresses(), peerstore.PermanentAddrTTL)
	}
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	first, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	secondDir := t.TempDir()
	second, err := archive.Open(secondDir)
	require.NoError(t, err)
	for _, item := range []struct {
		peer  *network.Peer
		store *archive.Store
	}{{firstPeer, first}, {secondPeer, second}} {
		server, err := NewServer(item.store, f.subject, JournalVerifier(f.store, f.context, f.limits, f.subject), []peer.ID{sender.ID()}, DefaultLimits())
		require.NoError(t, err)
		server.Register(context.Background(), item.peer)
	}
	for i := range f.entries {
		q, rec := f.record(t, i)
		for _, s := range []*archive.Store{local, first, second} {
			require.NoError(t, s.Put(q, rec))
		}
	}
	peers := [2]peer.ID{firstPeer.ID(), secondPeer.ID()}
	policy := frontier.Policy{Context: f.subject, Replicas: [2]string{peers[0].String(), peers[1].String()}, Binding: CertifiedBinding{Context: f.context, Subject: f.subject}, Availability: ReplicaAvailability{Context: context.Background(), Host: sender, Replicas: peers, Limits: DefaultLimits()}}
	require.NoError(t, f.store.EnableFrontier(context.Background(), f.context, f.limits, policy))
	worker := &FrontierWorker{Journal: f.store, Context: f.context, Limits: f.limits, Archive: local, Subject: f.subject, Replicas: peers, Host: sender, TransportLimits: DefaultLimits()}
	require.NoError(t, worker.Pass(context.Background()))
	require.NoError(t, worker.Pass(context.Background()))
	q, _ := f.record(t, 0)
	request, err := archive.EncodeRequest(q)
	require.NoError(t, err)
	key := sha256.Sum256(request)
	require.NoError(t, os.RemoveAll(filepath.Join(secondDir, hex.EncodeToString(key[:]))))
	_, err = second.Get(q)
	require.ErrorIs(t, err, archive.ErrUnavailable)
	require.NoError(t, worker.Pass(context.Background()))
	_, err = second.Get(q)
	require.NoError(t, err)
}

func TestFrontierWorkerWaitsToPruneAfterOfflineRestart(t *testing.T) {
	f := newWiringFixture(t, 1)
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	q, rec := f.record(t, 0)
	require.NoError(t, local.Put(q, rec))
	peers := [2]peer.ID{"first", "second"}
	available := digestAvailability{copies: map[string]map[[32]byte][32]byte{"first": {}, "second": {}}}
	policy := frontier.Policy{Context: f.subject, Replicas: [2]string{"first", "second"}, Binding: CertifiedBinding{Context: f.context, Subject: f.subject}, Availability: available}
	request, err := archive.EncodeRequest(q)
	require.NoError(t, err)
	digest, err := archive.ManifestDigest(q, rec)
	require.NoError(t, err)
	available.copies["first"][q.BlockHash] = digest
	available.copies["second"][q.BlockHash] = digest
	require.NoError(t, f.store.EnableFrontier(context.Background(), f.context, f.limits, policy))
	var state [32]byte
	copy(state[:], f.entries[0].Candidate.StateRoot)
	item := frontier.Coverage{Anchor: frontier.Record{Sequence: 1, Height: 1, Round: f.entries[0].ResultingUC.GetRootRoundNumber(), StateRoot: state, Subject: q,
		Acks: [2]frontier.Acknowledgment{{Replica: "first", RequestDigest: sha256.Sum256(request), ManifestDigest: digest}, {Replica: "second", RequestDigest: sha256.Sum256(request), ManifestDigest: digest}}}, Material: rec}
	require.NoError(t, f.store.AdvanceFrontier(context.Background(), f.context, f.limits, []frontier.Coverage{item}))
	require.NoError(t, f.store.Close())
	delete(available.copies["first"], q.BlockHash)
	delete(available.copies["second"], q.BlockHash)
	reopened, err := configuredprogress.OpenConfiguredV2(f.path, configuredprogress.Settings{Retain: 16})
	require.NoError(t, err)
	defer reopened.Close()
	require.NoError(t, reopened.EnableJournal(context.Background(), f.context, f.limits))
	require.NoError(t, reopened.EnableFrontier(context.Background(), f.context, f.limits, policy))
	worker := &FrontierWorker{Journal: reopened, Context: f.context, Limits: f.limits, Archive: local, Subject: f.subject, Replicas: peers}
	require.ErrorIs(t, worker.Pass(context.Background()), frontier.ErrUnavailable)
	snap, err := reopened.LoadFrontier(context.Background(), f.context, f.limits)
	require.NoError(t, err)
	require.Zero(t, snap.Floor)
}

func TestFrontierPruneKeepsIndependentSigningRecord(t *testing.T) {
	f := newWiringFixture(t, 1)
	certified := f.entries[0]
	loser := certified.Candidate
	loserHash := sha256.Sum256([]byte("timed out local proposal"))
	loser.Hash, loser.Raw, loser.LocallyBuilt = loserHash[:], []byte("timed out local proposal"), true
	require.NoError(t, f.store.PutJournalCandidate(context.Background(), f.context, f.limits, loser))

	enrollment := signingauthority.Enrollment{AuthorityID: "frontier-test", NodeID: loser.AuthorizingTR.Leader,
		NetworkID: f.subject.NetworkID, PartitionID: f.subject.PartitionID, ShardID: f.subject.ShardID,
		ShardEpoch: f.subject.ShardEpoch, ShardConfHash: f.context.Origin.FullShardConfHash().Bytes(),
		RootEpoch: signingauthority.PinRootEpoch(f.subject.RootEpoch), Profile: signingauthority.ProfileLegacyBCRv1}
	rootTrust := *f.chain.TrustBase
	rootTrust.NetworkID = f.subject.NetworkID
	authority, err := signingauthority.New(enrollment, fixtureTrust{&rootTrust})
	require.NoError(t, err)
	defer authority.Close()
	session, err := authority.ReplaceSession()
	require.NoError(t, err)
	proposed := &certification.BlockCertificationRequest{PartitionID: f.subject.PartitionID, ShardID: f.subject.ShardID,
		NodeID: enrollment.NodeID, BlockSize: loser.BlockSize, StateSize: loser.StateSize,
		InputRecord: &types.InputRecord{Version: 1, RoundNumber: loser.Round, Epoch: loser.AuthorizingTR.Epoch,
			PreviousHash: loser.AuthorizingUC.InputRecord.Hash, Hash: loser.StateRoot, BlockHash: loser.Hash,
			SummaryValue: []byte{}, Timestamp: loser.AuthorizingUC.UnicitySeal.Timestamp}}
	request := signingauthority.Request{UC: loser.AuthorizingUC, Technical: loser.AuthorizingTR, Proposed: proposed}
	_, err = authority.Reserve(context.Background(), session, request)
	require.NoError(t, err)
	require.NoError(t, authority.Sign(session))
	require.NoError(t, authority.RetainResponse(session))
	require.True(t, authority.Status().ResponseRetained)

	q, rec := f.record(t, 0)
	requestWire, err := archive.EncodeRequest(q)
	require.NoError(t, err)
	digest, err := archive.ManifestDigest(q, rec)
	require.NoError(t, err)
	availability := digestAvailability{copies: map[string]map[[32]byte][32]byte{"first": {q.BlockHash: digest}, "second": {q.BlockHash: digest}}}
	policy := frontier.Policy{Context: f.subject, Replicas: [2]string{"first", "second"}, Binding: CertifiedBinding{Context: f.context, Subject: f.subject}, Availability: availability}
	require.NoError(t, f.store.EnableFrontier(context.Background(), f.context, f.limits, policy))
	var state [32]byte
	copy(state[:], certified.Candidate.StateRoot)
	item := frontier.Coverage{Anchor: frontier.Record{Sequence: 1, Height: 1, Round: certified.ResultingUC.GetRootRoundNumber(), StateRoot: state, Subject: q,
		Acks: [2]frontier.Acknowledgment{{Replica: "first", RequestDigest: sha256.Sum256(requestWire), ManifestDigest: digest}, {Replica: "second", RequestDigest: sha256.Sum256(requestWire), ManifestDigest: digest}}}, Material: rec}
	require.NoError(t, f.store.AdvanceFrontier(context.Background(), f.context, f.limits, []frontier.Coverage{item}))
	require.NoError(t, f.store.PruneFrontier(context.Background(), f.context, f.limits))
	image, err := f.store.LoadJournal(context.Background(), f.context, f.limits)
	require.NoError(t, err)
	require.Len(t, image.Candidates, 1)
	require.Equal(t, image.Frontier.Anchor.Subject.BlockHash[:], image.Candidates[0].Candidate.Hash)
	require.NotEmpty(t, image.Candidates[0].Candidate.Raw)
	require.True(t, authority.Status().ResponseRetained)
	require.Equal(t, loser.Round, authority.Status().ReservedRound)
	changed := *proposed
	changed.BlockSize++
	_, err = authority.Reserve(context.Background(), session, signingauthority.Request{UC: loser.AuthorizingUC, Technical: loser.AuthorizingTR, Proposed: &changed})
	require.ErrorIs(t, err, signingauthority.ErrConflict)
}

func TestFrontierLongRunPastJournalCapsAndReplicaLoss(t *testing.T) {
	const blocks = 518
	limits := configuredprogress.JournalLimits{Candidates: 256, Observations: 512, Bytes: 64 << 20}
	f := newWiringFixtureWithLimits(t, 0, limits)
	peers := [2]peer.ID{"first", "second"}
	availability := digestAvailability{copies: map[string]map[[32]byte][32]byte{peers[0].String(): {}, peers[1].String(): {}}}
	policy := frontier.Policy{Context: f.subject, Replicas: [2]string{peers[0].String(), peers[1].String()}, Binding: CertifiedBinding{Context: f.context, Subject: f.subject}, Availability: availability}
	require.NoError(t, f.store.EnableFrontier(context.Background(), f.context, limits, policy))
	image, err := f.store.LoadJournal(context.Background(), f.context, limits)
	require.NoError(t, err)
	parentUC, parentTR := image.Observations[0].UC, image.Observations[0].TR
	parentHash := [32]byte(f.chain.Blocks[0].Hash)
	parentState := [32]byte(f.chain.Blocks[0].StateRoot)
	var peakBytes int64
	var pending []frontier.Coverage
	for number := 1; number <= blocks; number++ {
		var state [32]byte
		state[0], state[1], state[31] = byte(number), byte(number>>8), byte(number+17)
		hash, raw, size := wiringBlock(t, parentHash, state, uint64(number), parentUC.GetRootRoundNumber(), parentUC, parentTR)
		candidate := configuredprogress.JournalCandidate{Round: uint64(number), Number: uint64(number), ParentNumber: uint64(number - 1), Hash: hash[:], StateRoot: state[:], ParentHash: parentHash[:], ParentState: parentState[:], Raw: raw, BlockSize: size, AuthorizingUC: parentUC, AuthorizingTR: parentTR}
		require.NoError(t, f.store.PutJournalCandidate(context.Background(), f.context, limits, candidate), "candidate %d", number)
		ir := &types.InputRecord{Version: 1, RoundNumber: uint64(number), Hash: state[:], BlockHash: hash[:], SummaryValue: []byte{}, Timestamp: 1_700_000_000 + uint64(number)}
		if number > 1 {
			ir.PreviousHash = append([]byte(nil), parentState[:]...)
		}
		resultUC, resultTR := signWiring(t, f.chain, ir, uint64(number+1), uint64(4+number))
		o, err := rootinput.AuthenticateObservationV2(context.Background(), f.context.Observation, resultUC, resultTR)
		require.NoError(t, err)
		prepared, _, err := f.store.PrepareObservation(context.Background(), f.context, o)
		require.NoError(t, err)
		_, _, err = f.store.CommitObservation(prepared)
		require.NoError(t, err)
		image, err = f.store.LoadJournal(context.Background(), f.context, limits)
		require.NoError(t, err)
		var entry configuredprogress.JournalEntry
		for _, candidate := range image.Candidates {
			if bytes.Equal(candidate.Candidate.Hash, hash[:]) {
				entry = candidate
				break
			}
		}
		require.True(t, entry.Certified)
		q, rec, err := FromJournal(context.Background(), f.context, f.subject, nil, entry)
		require.NoError(t, err)
		digest, err := archive.ManifestDigest(q, rec)
		require.NoError(t, err)
		request, err := archive.EncodeRequest(q)
		require.NoError(t, err)
		ack := sha256.Sum256(request)
		availability.copies[peers[0].String()][q.BlockHash] = digest
		if number <= 516 {
			availability.copies[peers[1].String()][q.BlockHash] = digest
		}
		pending = append(pending, frontier.Coverage{Anchor: frontier.Record{Sequence: uint64(number), Round: resultUC.GetRootRoundNumber(), Height: uint64(number), StateRoot: state, Subject: q, Acks: [2]frontier.Acknowledgment{{Replica: peers[0].String(), RequestDigest: ack, ManifestDigest: digest}, {Replica: peers[1].String(), RequestDigest: ack, ManifestDigest: digest}}}, Material: rec})
		if number%4 == 0 {
			require.NoError(t, f.store.AdvanceFrontier(context.Background(), f.context, limits, pending), "frontier pass at %d", number)
			require.NoError(t, f.store.PruneFrontier(context.Background(), f.context, limits))
			pending = nil
		}
		if image.Bytes > peakBytes {
			peakBytes = image.Bytes
		}
		parentUC, parentTR, parentHash, parentState = resultUC, resultTR, hash, state
	}
	// Loss of one configured copy prevents the next advance. The journal
	// still admits the already certified block independently of archive work.
	_, err = f.store.LoadJournal(context.Background(), f.context, limits)
	require.NoError(t, err)
	// The first 516 are pruned; two remaining certified records are pending.
	require.ErrorIs(t, f.store.AdvanceFrontier(context.Background(), f.context, limits, pending), frontier.ErrAcknowledgment)
	image, err = f.store.LoadJournal(context.Background(), f.context, limits)
	require.NoError(t, err)
	require.EqualValues(t, 516, image.Frontier.Anchor.Height)
	require.Len(t, image.Candidates, 3)
	for _, item := range pending {
		availability.copies[peers[1].String()][item.Anchor.Subject.BlockHash] = item.Anchor.Acks[1].ManifestDigest
	}
	require.NoError(t, f.store.AdvanceFrontier(context.Background(), f.context, limits, pending))
	require.NoError(t, f.store.PruneFrontier(context.Background(), f.context, limits))
	require.NoError(t, f.store.Close())
	start := time.Now()
	reopened, err := configuredprogress.OpenConfiguredV2(f.path, configuredprogress.Settings{Retain: 16})
	require.NoError(t, err)
	defer reopened.Close()
	require.NoError(t, reopened.EnableJournal(context.Background(), f.context, limits))
	require.NoError(t, reopened.EnableFrontier(context.Background(), f.context, limits, policy))
	image, err = reopened.LoadJournal(context.Background(), f.context, limits)
	require.NoError(t, err)
	restartTime := time.Since(start)
	require.EqualValues(t, blocks, image.Frontier.Anchor.Height)
	require.Len(t, image.Candidates, 1)
	require.Equal(t, image.Frontier.Anchor.Subject.BlockHash[:], image.Candidates[0].Candidate.Hash)
	require.NotEmpty(t, image.Candidates[0].Candidate.Raw)
	require.Empty(t, image.Observations)
	stat, err := os.Stat(f.path)
	require.NoError(t, err)
	t.Logf("blocks=%d hot-journal-peak=%dB hot-journal-final=%dB bolt-file=%dB restart-load=%s", blocks, peakBytes, image.Bytes, stat.Size(), restartTime)
}
