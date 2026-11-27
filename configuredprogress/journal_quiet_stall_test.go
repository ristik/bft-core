package configuredprogress

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
	bolt "go.etcd.io/bbolt"
)

// failRounds runs n failed leader rounds at height `number` on top of (parentHash, parentState): each round journals one more uncertified
// proposal, and the root's timeout journals one more repeat certificate of `ir`. Every proposal and every certificate must be admitted, and the
// journal must stay inside its bounds and reload. It returns the authorization of the next round.
func failRounds(t *testing.T, s *Store, f *fixture, limits JournalLimits, n int, number uint64, parentHash, parentState []byte, ir *types.InputRecord,
	auth rootinput.VerifiedObservationV2) rootinput.VerifiedObservationV2 {
	t.Helper()
	ctx := context.Background()
	round, root := auth.TechnicalRecord().Round, auth.Certificate().GetRootRoundNumber()+1
	for i := 0; i < n; i++ {
		tag := byte(0x40 + i)
		proposal := JournalCandidate{Round: round, Number: number, ParentNumber: number - 1, Hash: bytes.Repeat([]byte{tag}, 32), StateRoot: bytes.Repeat([]byte{tag ^ 0xff}, 32),
			ParentHash: parentHash, ParentState: parentState, Raw: []byte{tag}, BlockSize: 1, LocallyBuilt: i%2 == 0,
			AuthorizingUC: auth.Certificate(), AuthorizingTR: auth.TechnicalRecord()}
		require.NoError(t, s.PutJournalCandidate(ctx, f.ctx, limits, proposal), "failed round %d: the proposal must be admitted", i)
		auth = f.observation(ir, round+1, root)
		p, outcome, err := s.PrepareObservation(ctx, f.ctx, auth)
		require.NoError(t, err)
		require.Equal(t, ObservationRepeated, outcome)
		_, _, err = s.CommitObservation(p)
		require.NoError(t, err, "failed round %d: the repeat certificate must be admitted", i)
		image, err := s.LoadJournal(ctx, f.ctx, limits)
		require.NoError(t, err)
		require.LessOrEqual(t, len(image.Candidates), limits.Candidates)
		require.LessOrEqual(t, len(image.Observations), limits.Observations)
		round++
		root++
	}
	return auth
}

// bft-core#1019, the quiet variant: a shard stuck at its first block, right after the bootstrap certificate. Every repeat certificate repeats
// the bootstrap input record, whose block hash is nil, so the superseded-repeat rule must not depend on a target block.
func TestJournalSurvivesFailedRoundsAfterBootstrap(t *testing.T) {
	limits := JournalLimits{Candidates: 3, Observations: 5, Bytes: 16 << 20}
	f := newFixture(t, 1)
	s, _ := openJournal(t, f, limits)
	t.Cleanup(func() { _ = s.Close() })
	bootstrap := f.bootstrap(1, 4)
	admitJournal(t, s, f, bootstrap)
	genesis := f.c.Blocks[0]
	auth := failRounds(t, s, f, limits, 3*5, 1, genesis.Hash.Bytes(), genesis.StateRoot.Bytes(), bootstrap.Certificate().InputRecord, bootstrap)

	// Block 1 is then proposed and certified.
	b1 := candidateB1(f, auth)
	b1.Round = auth.TechnicalRecord().Round
	require.NoError(t, s.PutJournalCandidate(context.Background(), f.ctx, limits, b1))
	b := f.c.Blocks[1]
	admitJournal(t, s, f, f.observation(&types.InputRecord{Version: 1, RoundNumber: b1.Round, Hash: b.StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_000 + b1.Round, BlockHash: b.Hash.Bytes()},
		b1.Round+1, auth.Certificate().GetRootRoundNumber()+1))
	require.Equal(t, map[byte]bool{b.Hash.Bytes()[0]: true}, candidateHashes(t, s, f, limits), "block 1 is certified and the stall's proposals are gone")
}

// bft-core#1019, the quiet-tail variant: block 1 is certified, then a quiet round certifies its state again without a block, and the shard is
// stuck at height 2. Every repeat certificate repeats the quiet input record.
func TestJournalSurvivesFailedRoundsAfterQuietRound(t *testing.T) {
	limits := JournalLimits{Candidates: 3, Observations: 5, Bytes: 16 << 20}
	s, f, b1Cert := stallJournal(t, limits) // bootstrap @4, block 1 @5 (next round 2)
	b1 := f.c.Blocks[1]
	quiet := &types.InputRecord{Version: 1, RoundNumber: 2, PreviousHash: b1.StateRoot.Bytes(), Hash: b1.StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_002}
	q := f.observation(quiet, 3, b1Cert.Certificate().GetRootRoundNumber()+1)
	admitJournal(t, s, f, q)
	failRounds(t, s, f, limits, 3*5, 2, b1.Hash.Bytes(), b1.StateRoot.Bytes(), quiet, q)
}

// Rule 2 on quiet observations: grouped by their complete input record, an older copy is evicted only when a later copy of the same input
// record is retained and no retained candidate was authorized by it. Two different quiet input records at the same state are not one group.
func TestEvictSupersededQuietObservationsKeepsNewestPerRecordAndAuthorizations(t *testing.T) {
	limits := JournalLimits{Candidates: 16, Observations: 16, Bytes: 16 << 20}
	s, f, b1Cert := stallJournal(t, limits) // bootstrap @4, block 1 association @5 (next 2)
	b1 := f.c.Blocks[1]
	quiet := func(round uint64) *types.InputRecord {
		return &types.InputRecord{Version: 1, RoundNumber: round, PreviousHash: b1.StateRoot.Bytes(), Hash: b1.StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_000 + round}
	}
	admitJournal(t, s, f, f.observation(quiet(2), 3, 6)) // quiet round 2
	q2auth := f.observation(quiet(2), 4, 7)              // repeat; authorizes a late round-4 copy below
	admitJournal(t, s, f, q2auth)
	admitJournal(t, s, f, f.observation(quiet(2), 5, 8)) // newest repeat of quiet round 2
	admitJournal(t, s, f, f.observation(quiet(5), 6, 9)) // a different quiet input record at the same state
	admitJournal(t, s, f, f.observation(quiet(5), 7, 10))
	// A follower's late copy of the round-4 proposal, authorized by the root-round-7 repeat.
	require.NoError(t, s.PutJournalCandidate(context.Background(), f.ctx, limits, height2(f, 4, 0x44, q2auth)))

	var n int
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error {
		var err error
		n, err = evictSupersededObservations(tx.Bucket(bucketName), nil, 0, 0, false, nil, nil)
		return err
	}))
	require.Equal(t, 2, n)
	image, err := s.LoadJournal(context.Background(), f.ctx, limits)
	require.NoError(t, err)
	var roots []uint64
	for _, o := range image.Observations {
		roots = append(roots, o.UC.GetRootRoundNumber())
	}
	// 4 bootstrap (the only copy of its record), 5 block 1's association, 7 the late copy's authorization, 8 quiet round 2's newest,
	// 10 quiet round 5's newest. 6 and 9 are gone.
	require.Equal(t, []uint64{4, b1Cert.Certificate().GetRootRoundNumber(), 7, 8, 10}, roots)
}
