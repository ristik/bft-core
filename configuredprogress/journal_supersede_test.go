package configuredprogress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
	bolt "go.etcd.io/bbolt"
)

// bft-core#1019: many more consecutive failed rounds at one height than the journal's candidate and observation bounds. Every failed round
// journals one more uncertified proposal for h = frontier+1 and one more repeat certificate of block h-1. The journal must keep admitting
// proposals and certificates, a certifiable proposal must then be admitted and certified, and the frontier must advance over it, across a restart.
func TestJournalSurvivesFailedRoundsBeyondBoundsAtOneHeight(t *testing.T) {
	path := t.TempDir() + "/journal.db"
	limits := JournalLimits{Candidates: 3, Observations: 5, Bytes: 16 << 20}
	s, f, c, policy, item, _ := frontierTestSetupWithLimits(t, path, limits)
	ctx := context.Background()
	admit := func(o rootinput.VerifiedObservationV2) {
		t.Helper()
		p, _, err := s.PrepareObservation(ctx, c, o)
		require.NoError(t, err)
		_, _, err = s.CommitObservation(p)
		require.NoError(t, err)
	}
	// The frontier covers height 1; the shard is stuck at height 2.
	require.NoError(t, s.AdvanceFrontier(ctx, c, limits, []frontier.Coverage{item}))
	require.NoError(t, s.PruneFrontier(ctx, c, limits))
	var anchorUC types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(item.Material.ResultingUC, &anchorUC))
	anchorTR := new(certification.TechnicalRecord)
	require.NoError(t, types.Cbor.Unmarshal(item.Material.ResultingTR, anchorTR))
	auth, err := rootinput.AuthenticateObservationV2(ctx, c.Observation, &anchorUC, anchorTR)
	require.NoError(t, err)
	parentHash, parentState := item.Anchor.Subject.BlockHash, item.Anchor.StateRoot

	const failed = 3 * 5 // well beyond both bounds
	round, rootRound := uint64(2), anchorUC.GetRootRoundNumber()+1
	var firstFailed JournalCandidate
	for i := 0; i < failed; i++ {
		// The round's proposal is journaled (alternately by the leader and by a follower) and never certified.
		dead := JournalCandidate{Round: round, Number: 2, ParentNumber: 1, Hash: bytes.Repeat([]byte{byte(0x40 + i)}, 32), StateRoot: bytes.Repeat([]byte{byte(0x80 + i)}, 32),
			ParentHash: parentHash[:], ParentState: parentState[:], Raw: []byte{byte(i), 1, 2}, BlockSize: 3, LocallyBuilt: i%2 == 0,
			AuthorizingUC: auth.Certificate(), AuthorizingTR: auth.TechnicalRecord()}
		require.NoError(t, s.PutJournalCandidate(ctx, c, limits, dead), "failed round %d: the proposal must be admitted", i)
		if i == 0 {
			firstFailed = dead
		}
		// The root times out: a repeat certificate of block 1 that moves the shard to the next round.
		auth = f.observation(anchorUC.InputRecord, round+1, rootRound)
		p, outcome, err := s.PrepareObservation(ctx, c, auth)
		require.NoError(t, err)
		require.Equal(t, ObservationRepeated, outcome)
		_, _, err = s.CommitObservation(p)
		require.NoError(t, err, "failed round %d: the repeat certificate must be admitted", i)
		image, err := s.LoadJournal(ctx, c, limits)
		require.NoError(t, err)
		require.LessOrEqual(t, len(image.Candidates), limits.Candidates)
		require.LessOrEqual(t, len(image.Observations), limits.Observations)
		round++
		rootRound++
	}

	// A different local proposal for an evicted proposal's authorization is still refused (equivocation avoidance survives the eviction).
	again := firstFailed
	again.Hash, again.Raw, again.LocallyBuilt = bytes.Repeat([]byte{0xee}, 32), []byte{0xee}, true
	err = s.PutJournalCandidate(ctx, c, limits, again)
	require.ErrorIs(t, err, ErrLocalProposalConflict)
	require.ErrorIs(t, err, ErrConflict)

	// Restart in the stall: the journal reopens and verifies.
	require.NoError(t, s.Close())
	s, err = OpenConfiguredV2(path, Settings{Retain: 3})
	require.NoError(t, err)
	defer func() { require.NoError(t, s.Close()) }()
	require.NoError(t, s.EnableJournal(ctx, c, limits))
	require.NoError(t, s.EnableFrontier(ctx, c, limits, policy))
	_, err = s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)

	// The certifiable proposal of this round is admitted, certified and covered by the frontier.
	state := common.Hash{31: 0x42}
	header := &gethtypes.Header{ParentHash: common.Hash(parentHash), Root: state, Number: big.NewInt(2), Difficulty: new(big.Int), BaseFee: big.NewInt(1)}
	headerRaw, err := rlp.EncodeToBytes(header)
	require.NoError(t, err)
	hash := header.Hash()
	good := JournalCandidate{Round: round, Number: 2, ParentNumber: 1, Hash: hash.Bytes(), StateRoot: state.Bytes(), ParentHash: parentHash[:], ParentState: parentState[:],
		Raw: []byte{7, 7, 7}, BlockSize: 3, LocallyBuilt: true, AuthorizingUC: auth.Certificate(), AuthorizingTR: auth.TechnicalRecord()}
	require.NoError(t, s.PutJournalCandidate(ctx, c, limits, good))
	result := f.observation(&types.InputRecord{Version: 1, RoundNumber: round, PreviousHash: parentState[:], Hash: state.Bytes(), BlockHash: hash.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_000 + round}, round+1, rootRound)
	admit(result)
	image, err := s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	certified := false
	for _, e := range image.Candidates {
		if bytes.Equal(e.Candidate.Hash, hash.Bytes()) {
			certified = e.Certified
		}
	}
	require.True(t, certified, "the certifiable proposal is certified")

	uc0, _ := types.Cbor.Marshal(auth.Certificate())
	tr0, _ := types.Cbor.Marshal(auth.TechnicalRecord())
	uc1, _ := types.Cbor.Marshal(result.Certificate())
	tr1, _ := types.Cbor.Marshal(result.TechnicalRecord())
	bodyRaw, _ := rlp.EncodeToBytes(&gethtypes.Body{})
	rec := &archive.Record{Header: headerRaw, Body: bodyRaw, CanonicalRootInput: []byte{1}, OriginalUC: uc0, OriginalTR: tr0, ResultingUC: uc1, ResultingTR: tr1, Companion: []byte{1}}
	q := archive.Request{Context: item.Anchor.Subject.Context, BlockHash: [32]byte(hash)}
	req, err := archive.EncodeRequest(q)
	require.NoError(t, err)
	digest, err := archive.ManifestDigest(q, rec)
	require.NoError(t, err)
	ack := sha256.Sum256(req)
	next := frontier.Record{Sequence: 2, Round: result.Certificate().GetRootRoundNumber(), Height: 2, StateRoot: [32]byte(state), Subject: q,
		Acks: [2]frontier.Acknowledgment{{Replica: "first", RequestDigest: ack, ManifestDigest: digest}, {Replica: "second", RequestDigest: ack, ManifestDigest: digest}}}
	require.NoError(t, s.AdvanceFrontier(ctx, c, limits, []frontier.Coverage{{Anchor: next, Material: rec}}))
	require.NoError(t, s.PruneFrontier(ctx, c, limits))
	image, err = s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	require.EqualValues(t, 2, image.Frontier.Anchor.Height, "the frontier advanced past the stuck height")
}

// stallJournal holds block 1, certified (association at root round 5, next round 2), after the bootstrap certificate.
func stallJournal(t *testing.T, limits JournalLimits) (*Store, *fixture, rootinput.VerifiedObservationV2) {
	t.Helper()
	f := newFixture(t, 1)
	s, _ := openJournal(t, f, limits)
	t.Cleanup(func() { _ = s.Close() })
	bootstrap := f.bootstrap(1, 4)
	admitJournal(t, s, f, bootstrap)
	require.NoError(t, s.PutJournalCandidate(context.Background(), f.ctx, limits, candidateB1(f, bootstrap)))
	b1 := f.first(1, 2, 5)
	admitJournal(t, s, f, b1)
	return s, f, b1
}

func height2(f *fixture, round uint64, tag byte, auth rootinput.VerifiedObservationV2) JournalCandidate {
	b1 := f.c.Blocks[1]
	return JournalCandidate{Round: round, Number: 2, ParentNumber: 1, Hash: bytes.Repeat([]byte{tag}, 32), StateRoot: bytes.Repeat([]byte{tag ^ 0xff}, 32),
		ParentHash: b1.Hash.Bytes(), ParentState: b1.StateRoot.Bytes(), Raw: []byte{tag}, BlockSize: 1, AuthorizingUC: auth.Certificate(), AuthorizingTR: auth.TechnicalRecord()}
}

func candidateHashes(t *testing.T, s *Store, f *fixture, limits JournalLimits) map[byte]bool {
	t.Helper()
	image, err := s.LoadJournal(context.Background(), f.ctx, limits)
	require.NoError(t, err, "the journal stays consistent after eviction")
	out := map[byte]bool{}
	for _, e := range image.Candidates {
		out[e.Candidate.Hash[0]] = e.Certified
	}
	return out
}

// Rule 1 evicts only what the evidence proves dead: E.IR.RoundNumber < r < E.TR.Round, and only uncertified bodies.
func TestEvictDeadCandidatesKeepsCertifiedAncestorsAndLiveProposal(t *testing.T) {
	limits := JournalLimits{Candidates: 16, Observations: 16, Bytes: 16 << 20}
	s, f, _ := stallJournal(t, limits)
	ctx := context.Background()
	for _, r := range []uint64{2, 3, 5, 6, 7} {
		require.NoError(t, s.PutJournalCandidate(ctx, f.ctx, limits, height2(f, r, byte(0x10+r), f.first(1, r, 5+r))))
	}
	b1 := f.c.Blocks[1].Hash.Bytes()[0]
	evict := func(irRound, next uint64) int {
		var n int
		require.NoError(t, s.db.Update(func(tx *bolt.Tx) error {
			var err error
			n, err = evictDeadCandidates(tx.Bucket(bucketName), &types.UnicityCertificate{InputRecord: &types.InputRecord{RoundNumber: irRound}}, &certification.TechnicalRecord{Round: next})
			return err
		}))
		return n
	}
	// E: certified round 5, next round 7. Round 6 was skipped. Rounds 3 and 5 may belong to certified blocks whose certificates this node
	// missed (an ancestor, or the block certified at round 5); round 7 is the live round. Block 1 is certified.
	require.Equal(t, 1, evict(5, 7))
	got := candidateHashes(t, s, f, limits)
	require.Equal(t, map[byte]bool{b1: true, 0x12: false, 0x13: false, 0x15: false, 0x17: false}, got)
	// E: certified round 0, next round 10 (evidence no real root issues after block 1, here only to show that a certified body is never
	// evicted whatever the evidence says). Every uncertified round 1..9 is dead; block 1 stays.
	require.Equal(t, 4, evict(0, 10))
	require.Equal(t, map[byte]bool{b1: true}, candidateHashes(t, s, f, limits))
}

// Rule 2 at the observation bound, with two certified blocks: the association and the newest observation of each block, and every retained
// candidate's authorization, survive; only an older repeat that is none of those is evicted.
func TestEvictSupersededObservationsKeepsAssociationNewestAndAuthorizations(t *testing.T) {
	limits := JournalLimits{Candidates: 16, Observations: 16, Bytes: 16 << 20}
	s, f, b1Cert := stallJournal(t, limits) // bootstrap @4, block 1 association @5 (next 2)
	ctx := context.Background()
	r1 := f.first(1, 3, 6) // repeat of block 1
	admitJournal(t, s, f, r1)
	r2 := f.first(1, 4, 7) // newer repeat of block 1; authorizes block 2
	admitJournal(t, s, f, r2)
	b2 := height2(f, 4, 0x24, r2)
	b2.LocallyBuilt = true
	require.NoError(t, s.PutJournalCandidate(ctx, f.ctx, limits, b2))
	ir2 := &types.InputRecord{Version: 1, RoundNumber: 4, PreviousHash: f.c.Blocks[1].StateRoot.Bytes(), Hash: b2.StateRoot, BlockHash: b2.Hash, SummaryValue: []byte{}, Timestamp: 1_700_000_004}
	x := f.observation(ir2, 5, 8) // block 2 association
	admitJournal(t, s, f, x)
	y1 := f.observation(ir2, 6, 9) // repeat of block 2
	admitJournal(t, s, f, y1)
	y2 := f.observation(ir2, 7, 10) // newest repeat of block 2
	admitJournal(t, s, f, y2)
	// A late copy of a round-3 proposal, authorized by r1, is retained (follower copies of a closed round are not refused).
	require.NoError(t, s.PutJournalCandidate(ctx, f.ctx, limits, height2(f, 3, 0x33, r1)))

	var n int
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error {
		var err error
		n, err = evictSupersededObservations(tx.Bucket(bucketName), nil, 0, 0, false, nil, nil)
		return err
	}))
	require.Equal(t, 1, n)
	image, err := s.LoadJournal(ctx, f.ctx, limits)
	require.NoError(t, err)
	var roots []uint64
	for _, o := range image.Observations {
		roots = append(roots, o.UC.GetRootRoundNumber())
	}
	// 4 bootstrap, 5 block 1's association, 6 the round-3 copy's authorization, 7 block 1's newest (block 2's authorization),
	// 8 block 2's association, 10 block 2's newest. Only 9 is gone.
	require.Equal(t, []uint64{4, b1Cert.Certificate().GetRootRoundNumber(), 6, 7, 8, 10}, roots)
}

// Rule 1 runs on every committed certificate, not only at the bound: once the certificate of the stuck height is admitted, no single
// certificate can prove the stall's proposals dead any more, so they must already be gone by then (review of #1021).
func TestDeadCandidatesAreFreedBeforeTheStuckHeightIsCertified(t *testing.T) {
	limits := JournalLimits{Candidates: 64, Observations: 64, Bytes: 16 << 20}
	s, f, auth := stallJournal(t, limits)
	ctx := context.Background()
	round, root := auth.TechnicalRecord().Round, auth.Certificate().GetRootRoundNumber()+1
	for i := 0; i < 5; i++ {
		require.NoError(t, s.PutJournalCandidate(ctx, f.ctx, limits, height2(f, round, byte(0x40+i), auth)))
		auth = f.first(1, round+1, root)
		admitJournal(t, s, f, auth)
		round++
		root++
	}
	live := height2(f, round, 0x77, auth)
	require.NoError(t, s.PutJournalCandidate(ctx, f.ctx, limits, live))
	ir := &types.InputRecord{Version: 1, RoundNumber: round, PreviousHash: f.c.Blocks[1].StateRoot.Bytes(), Hash: live.StateRoot, BlockHash: live.Hash, SummaryValue: []byte{}, Timestamp: 1_700_000_000 + round}
	admitJournal(t, s, f, f.observation(ir, round+1, root))
	require.Equal(t, map[byte]bool{f.c.Blocks[1].Hash.Bytes()[0]: true, 0x77: true}, candidateHashes(t, s, f, limits), "only the two certified blocks remain")
}
