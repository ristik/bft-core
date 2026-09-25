package archivewiring

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/frontier"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/rootinput"
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
	bad := *record
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
	worker := &FrontierWorker{Journal: f.store, Context: f.context, Limits: f.limits, Archive: local, Subject: f.subject, Replicas: peers}
	require.NoError(t, worker.Pass(context.Background()))
	require.NoError(t, worker.Pass(context.Background()))
	image, err := f.store.LoadJournal(context.Background(), f.context, f.limits)
	require.NoError(t, err)
	require.NotNil(t, image.Frontier)
	require.EqualValues(t, 6, image.Frontier.Anchor.Height)
	require.EqualValues(t, 6, image.Frontier.Floor)
	require.Empty(t, image.Candidates)
	require.Empty(t, image.Observations)
	oldQ, oldRec := f.record(t, 0)
	verify := JournalVerifier(f.store, f.context, f.limits, f.subject)
	require.NoError(t, verify(context.Background(), oldQ, oldRec))
	changed := *oldRec
	changed.Body = append([]byte(nil), oldRec.Header...)
	require.ErrorIs(t, verify(context.Background(), oldQ, &changed), ErrUncertified)
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
	require.Len(t, image.Candidates, 2)
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
	require.Empty(t, image.Candidates)
	require.Empty(t, image.Observations)
	stat, err := os.Stat(f.path)
	require.NoError(t, err)
	t.Logf("blocks=%d hot-journal-peak=%dB hot-journal-final=%dB bolt-file=%dB restart-load=%s", blocks, peakBytes, image.Bytes, stat.Size(), restartTime)
}
