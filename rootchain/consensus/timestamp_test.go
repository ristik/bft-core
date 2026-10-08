package consensus

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	testnetwork "github.com/unicitynetwork/bft-core/internal/testutils/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	basetypes "github.com/unicitynetwork/bft-go-base/types"
)

func TestProposalTimestamp(t *testing.T) {
	for _, tc := range []struct {
		name              string
		now, parent, want uint64
	}{
		{"wall clock", 100, 80, 100}, {"same second repeats the parent", 100, 100, 100},
		{"clock rollback keeps the parent", 90, 100, 100}, {"the largest parent", 0, math.MaxUint64, math.MaxUint64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, proposalTimestamp(tc.now, tc.parent))
		})
	}
}

// The #447 stall: with a strict whole-second increase and rounds shorter than a second, the seal time ran ahead of the wall clock by one
// second per round it was ahead, until the 30 s voter skew bound refused every proposal. Under the non-decreasing rule 250 consecutive rounds
// at 800 ms (over three minutes of rounds, twice the 30 s bound's worth of drift) are all proposed and voted without a skew refusal, and the
// seal time never leads the wall clock.
func TestSubSecondRoundsNeverDriftPastTheVoterSkew(t *testing.T) {
	r := newDecisionRig(t)
	m, _ := r.open(r.signer, r.scheme2())
	const period = 800 * time.Millisecond
	start := time.Unix(1_700_000_000, 0)
	var clock time.Time
	m.now = func() uint64 { return uint64(clock.Unix()) }
	times := map[uint64]uint64{0: uint64(start.Unix())}
	WithParentTimestamp(func(round uint64) (uint64, error) { return times[round], nil })(m)
	shared := 0
	for round := uint64(1); round <= 250; round++ {
		clock = start.Add(time.Duration(round) * period)
		ts := proposalTimestamp(m.now(), times[round-1])
		require.LessOrEqual(t, ts, m.now(), "round %d: the seal time never leads the wall clock", round)
		block := &drctypes.BlockData{Round: round, Timestamp: ts, Qc: &drctypes.QuorumCert{VoteInfo: &drctypes.RoundInfo{RoundNumber: round - 1}}}
		require.NoError(t, m.validateVoteTimestamp(block), "round %d", round)
		if ts == times[round-1] {
			shared++
		}
		times[round] = ts
	}
	require.Greater(t, shared, 40, "premise: many rounds share a second")
}

func TestVoteTimestampGuards(t *testing.T) {
	for _, scheme2 := range []bool{false, true} {
		name := "legacy"
		if scheme2 {
			name = "scheme2"
		}
		for _, timeout := range []bool{false, true} {
			path := "QC"
			if timeout {
				path = "TC"
			}
			for _, tc := range []struct {
				name      string
				timestamp uint64
				want      error
			}{
				{"equal parent", 100, nil},
				{"before parent", 99, ErrTimestampNotIncreasing},
				{"one ahead", 101, nil}, {"skew boundary", 130, nil},
				{"too far ahead", 131, ErrTimestampTooFarAhead},
				{"overflow attack", math.MaxUint64, ErrTimestampTooFarAhead},
			} {
				t.Run(name+"/"+path+"/"+tc.name, func(t *testing.T) {
					r := newDecisionRig(t)
					resolver := SigningResolver(fixedSigning{cfg: votesig.Config{Scheme: votesig.SchemeLegacy}})
					if scheme2 {
						resolver = r.scheme2()
					}
					m, db := r.open(r.signer, resolver)
					m.now = func() uint64 { return 100 }
					var parentRound uint64
					WithParentTimestamp(func(round uint64) (uint64, error) { parentRound = round; return 100, nil })(m)
					block := r.committingBlock(8)
					var cert *drctypes.TimeoutCert
					if timeout {
						block, cert = r.nonCommittingBlock(8)
					}
					block.Timestamp = tc.timestamp
					// The QC's timestamp must not override the locally executed parent.
					block.Qc.VoteInfo.Timestamp = 1
					if scheme2 {
						block.Qc.Scheme = votesig.SchemeDomainBound
						block.Qc.VoteInfo.Timestamp = 0
					}
					before := db.GetHighestVotedRound()
					v, err := m.MakeVote(block, hash32(2), nil, cert)
					require.Equal(t, block.GetParentRound(), parentRound)
					if tc.want == nil {
						require.NoError(t, err)
						require.NotNil(t, v)
					} else {
						require.ErrorIs(t, err, tc.want)
						require.ErrorIs(t, err, ErrNotSafeToVote)
						require.Nil(t, v)
						require.Equal(t, before, db.GetHighestVotedRound(), "refusal must not persist a vote lock")
					}
				})
			}
		}
	}
}

func TestVoteTimestampMissingParentAndOldLiveProposal(t *testing.T) {
	r := newDecisionRig(t)
	m, _ := r.open(r.signer, r.scheme2())
	block := r.committingBlock(8)
	missing := errors.New("missing executed block")
	WithParentTimestamp(func(uint64) (uint64, error) { return 0, missing })(m)
	_, err := m.MakeVote(block, hash32(2), nil, nil)
	require.ErrorIs(t, err, ErrTimestampParentUnavailable)
	require.ErrorIs(t, err, missing)
	WithParentTimestamp(func(uint64) (uint64, error) { return 100, nil })(m)
	m.now = func() uint64 { return 1000000 }
	block.Timestamp = 101
	// Delayed proposals can still advance recovery: there is no past-time cutoff.
	_, err = m.MakeVote(block, hash32(2), nil, nil)
	require.NoError(t, err)
}

func TestVoteTimestampRestartRechecksClockBeforeRecordedDecision(t *testing.T) {
	r := newDecisionRig(t)
	m, _ := r.open(r.signer, r.scheme2())
	WithParentTimestamp(func(uint64) (uint64, error) { return 100, nil })(m)
	m.now = func() uint64 { return 100 }
	block := r.committingBlock(8)
	block.Timestamp = 130
	vote, err := m.MakeVote(block, hash32(2), nil, nil)
	require.NoError(t, err)
	restarted, _ := r.open(r.signer, r.scheme2())
	WithParentTimestamp(func(uint64) (uint64, error) { return 100, nil })(restarted)
	restarted.now = func() uint64 { return 99 }
	_, err = restarted.MakeVote(block, hash32(2), nil, nil)
	require.ErrorIs(t, err, ErrTimestampTooFarAhead)
	restarted.now = func() uint64 { return 100 }
	replay, err := restarted.MakeVote(block, hash32(2), nil, nil)
	require.NoError(t, err)
	require.Equal(t, vote, replay)
	// A changed proposal must satisfy live admission before the recorded-decision retry.
	block.Timestamp = 99
	_, err = restarted.MakeVote(block, hash32(2), nil, nil)
	require.ErrorIs(t, err, ErrTimestampNotIncreasing)
}

// Keep the live-voting tests distinct from history verification: an old certified
// block can be structurally verified without consulting any local clock.
func TestCertifiedHistoryHasNoClockCheck(t *testing.T) {
	r := newDecisionRig(t)
	block := r.committingBlock(8)
	block.Payload = &drctypes.Payload{}
	block.Timestamp = 101
	require.NoError(t, block.IsValid())
	// Even an ahead-of-clock certificate is checked by its proof, not wall time.
	block.Timestamp = math.MaxUint64
	require.NoError(t, block.IsValid())
}

func TestManagerTimestampBuilderAndEarlyRefusal(t *testing.T) {
	net := testnetwork.NewRootMockNetwork()
	cm, node, _ := initConsensusManager(t, net)
	// This test drives proposals without Run, so allow its certificate batches
	// to queue even when a mutation lets invalid proposals reach processQC.
	cm.ucSink = make(chan []*certification.CertificationResponse, 4)
	ctx := context.Background()
	qc := cm.blockStore.GetHighQc()
	parent, err := cm.blockStore.Block(qc.GetRound())
	require.NoError(t, err)
	before := basetypes.NewTimestamp()
	cm.pacemaker.Reset(ctx, qc.GetRound(), nil, nil)
	cm.processNewRoundEvent(ctx)
	proposal := net.WaitRootProposal(t)
	require.GreaterOrEqual(t, proposal.Block.Timestamp, before)
	require.GreaterOrEqual(t, proposal.Block.Timestamp, parent.BlockData.Timestamp)
	original := proposal.Block.Timestamp
	for _, tc := range []struct {
		name      string
		timestamp uint64
		want      error
	}{
		{"before parent", parent.BlockData.Timestamp - 1, ErrTimestampNotIncreasing},
		{"future", basetypes.NewTimestamp() + 60, ErrTimestampTooFarAhead},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proposal.Block.Timestamp = tc.timestamp
			require.NoError(t, proposal.Sign(node.Signer))
			err := cm.onProposalMsg(ctx, proposal)
			require.ErrorIs(t, err, tc.want)
			_, err = cm.blockStore.Block(proposal.Block.Round)
			require.Error(t, err, "invalid proposal must not enter executed storage")
		})
	}
	// a proposal at exactly the parent's time is valid: several rounds may share a second
	proposal.Block.Timestamp = parent.BlockData.Timestamp
	require.NoError(t, proposal.Sign(node.Signer))
	require.NoError(t, cm.onProposalMsg(ctx, proposal))
	_ = original
}

func TestManagerTimestampRecoveryUsesReplacementStore(t *testing.T) {
	for _, tc := range []struct {
		name    string
		invalid bool
	}{{"old certified history", false}, {"future live trigger", true}} {
		t.Run(tc.name, func(t *testing.T) {
			net := testnetwork.NewRootMockNetwork()
			cm, node, _ := initConsensusManager(t, net)
			ctx := context.Background()
			state, err := cm.blockStore.GetState()
			require.NoError(t, err)
			cm.pacemaker.Reset(ctx, cm.blockStore.GetHighQc().GetRound(), nil, nil)
			cm.processNewRoundEvent(ctx)
			proposal := net.WaitRootProposal(t)
			if tc.invalid {
				proposal.Block.Timestamp = basetypes.NewTimestamp() + 60
			} else {
				// A local clock far ahead must not reject old certified state or a delayed vote.
				cm.safety.now = func() uint64 { return basetypes.NewTimestamp() + 86400 }
			}
			require.NoError(t, proposal.Sign(node.Signer))
			_, err = cm.recovery.Set(proposal)
			require.NoError(t, err)
			previous := cm.blockStore
			err = cm.onStateResponse(ctx, state)
			if tc.invalid {
				require.ErrorIs(t, err, ErrTimestampTooFarAhead)
				_, missing := cm.blockStore.Block(proposal.Block.Round)
				require.Error(t, missing, "future recovery trigger must not enter executed storage")
			} else {
				require.NoError(t, err)
			}
			require.NotSame(t, previous, cm.blockStore)
			// Change only the retired store's parent; live validation must read the replacement.
			oldParent, e := previous.Block(proposal.Block.GetParentRound())
			require.NoError(t, e)
			oldData := *oldParent.BlockData
			oldParent.BlockData = &oldData
			oldParent.BlockData.Timestamp = math.MaxUint64
			proposal.Block.Timestamp = basetypes.NewTimestamp()
			require.NoError(t, cm.safety.validateVoteTimestamp(proposal.Block))
		})
	}
}
