package rootchain

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/internal/testutils/requestvectors"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

func weightedTB(v requestvectors.Vector) *partitions.TrustBase {
	return partitions.NewWeightedPartitionTrustBase("w", v.Weights)
}

func voteReq(v requestvectors.Vote) *certification.BlockCertificationRequest {
	return &certification.BlockCertificationRequest{PartitionID: sysID1, NodeID: v.Signer,
		InputRecord: &types.InputRecord{Version: 1, PreviousHash: []byte{9}, Hash: []byte(v.Group), RoundNumber: 2, Timestamp: 1}}
}

func permute(votes []requestvectors.Vote, visit func([]requestvectors.Vote)) {
	cur := slices.Clone(votes)
	var rec func(k int)
	rec = func(k int) {
		if k == len(cur) {
			visit(slices.Clone(cur))
			return
		}
		for i := k; i < len(cur); i++ {
			cur[k], cur[i] = cur[i], cur[k]
			rec(k + 1)
			cur[k], cur[i] = cur[i], cur[k]
		}
	}
	rec(0)
}

// trustProof adapts the trust base to proof verification: the requests are not signed in the vectors, ValidRequest is the
// signature/continuity check the production ShardInfo does.
type trustProof struct{ *partitions.TrustBase }

func (trustProof) ValidRequest(*certification.BlockCertificationRequest) error { return nil }

func luc() *types.UnicityCertificate {
	return &types.UnicityCertificate{Version: 1, InputRecord: &types.InputRecord{Version: 1, Hash: []byte{9}, RoundNumber: 1}, UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 1}}
}

// The shared vectors through buffer formation, in every arrival order: after each request the status is the oracle's, the
// proof is the winning group (quorum) or every request (no quorum), and independent proof verification accepts exactly
// that proof.
func TestRequestBufferAgreesWithOracleForEveryOrder(t *testing.T) {
	for _, vec := range requestvectors.Vectors() {
		t.Run(vec.Name, func(t *testing.T) {
			tb := weightedTB(vec)
			permute(vec.Votes, func(order []requestvectors.Vote) {
				rs := newRequestStore()
				for n, v := range order {
					qs, proof, err := rs.add(voteReq(v), tb)
					require.NoError(t, err)
					switch want := vec.Oracle(order[:n+1]); want {
					case requestvectors.Achieved:
						require.Equal(t, QuorumAchieved, qs, "%v", order[:n+1])
						win := vec.Winner(order[:n+1])
						var got uint64
						for _, r := range proof {
							require.Equal(t, win, string(r.InputRecord.Hash), "a quorum proof carries only the matching group")
							w, _ := tb.SignerWeight(r.NodeID)
							got += w
						}
						require.GreaterOrEqual(t, got, tb.Threshold())
						x := &rctypes.IRChangeReq{Partition: sysID1, CertReason: rctypes.Quorum, Requests: proof}
						_, err := x.Verify(trustProof{tb}, luc(), 5, 1)
						require.NoError(t, err, "independent verification accepts the buffer's quorum proof")
					case requestvectors.Impossible:
						require.Equal(t, QuorumNotPossible, qs, "%v", order[:n+1])
						require.Len(t, proof, n+1)
						x := &rctypes.IRChangeReq{Partition: sysID1, CertReason: rctypes.QuorumNotPossible, Requests: proof}
						_, err := x.Verify(trustProof{tb}, luc(), 5, 1)
						require.NoError(t, err, "independent verification accepts the buffer's no-quorum proof")
					default:
						require.Equal(t, QuorumInProgress, qs, "%v", order[:n+1])
						require.Nil(t, proof)
					}
				}
			})
		})
	}
}

// Fixture 2 by name: the strict boundary, then the equality case in the same buffer type.
func TestRequestBufferExactBoundary(t *testing.T) {
	w := map[string]uint64{"a": 3, "b": 2, "c": 1, "d": 2, "e": 2}
	tb := partitions.NewWeightedPartitionTrustBase("w", w)
	add := func(rs *requestBuffer, id, g string) QuorumStatus {
		qs, _, err := rs.add(voteReq(requestvectors.Vote{Signer: id, Group: g}), tb)
		require.NoError(t, err)
		return qs
	}
	strict := newRequestStore()
	require.Equal(t, QuorumInProgress, add(strict, "a", "X"))
	require.Equal(t, QuorumInProgress, add(strict, "b", "Y"))
	require.Equal(t, QuorumInProgress, add(strict, "c", "Y"), "R=6 M=3 U=4")
	require.Equal(t, QuorumNotPossible, add(strict, "d", "Z"), "R=8 M=3 U=2: 5<6")

	equal := newRequestStore()
	require.Equal(t, QuorumInProgress, add(equal, "a", "X"))
	require.Equal(t, QuorumInProgress, add(equal, "b", "Y"))
	require.Equal(t, QuorumInProgress, add(equal, "d", "Y"), "R=7 M=4 U=3")
	require.Equal(t, QuorumInProgress, add(equal, "c", "Z"), "R=8 M=4 U=2: 6==Q is still possible")
	require.Equal(t, QuorumAchieved, add(equal, "e", "Y"), "the missing weight-2 signer completes Y")
}

type bufferSnapshot struct {
	nodes, groups, signers int
	received               uint64
	status                 QuorumStatus
	identity               string
}

func snapshot(rs *requestBuffer) bufferSnapshot {
	s := bufferSnapshot{nodes: len(rs.nodeRequest), groups: len(rs.requests), status: rs.qState, identity: rs.identity}
	if rs.tally != nil {
		s.signers, s.received = rs.tally.Signers(), rs.tally.Received()
	}
	return s
}

// Forged-by-membership, unknown, duplicate and nil requests are refused with errors.Is sentinels and leave the requests,
// tally and status unchanged.
func TestRequestBufferErrorsLeaveStateUnchanged(t *testing.T) {
	tb := partitions.NewWeightedPartitionTrustBase("w", map[string]uint64{"a": 3, "b": 2, "c": 1})
	rs := newRequestStore()
	_, _, err := rs.add(voteReq(requestvectors.Vote{Signer: "a", Group: "X"}), tb)
	require.NoError(t, err)
	before := snapshot(rs)
	ir := voteReq(requestvectors.Vote{Signer: "b", Group: "X"})

	for _, tc := range []struct {
		name string
		req  *certification.BlockCertificationRequest
		tb   QuorumInfo
		is   error
	}{
		{"unknown signer", voteReq(requestvectors.Vote{Signer: "zz", Group: "X"}), tb, quorumweight.ErrUnknownSigner},
		{"duplicate signer", voteReq(requestvectors.Vote{Signer: "a", Group: "Y"}), tb, quorumweight.ErrDuplicateSigner},
		{"nil request", nil, tb, rctypes.ErrInvalidRequest},
		{"nil input record", &certification.BlockCertificationRequest{PartitionID: sysID1, NodeID: "b"}, tb, rctypes.ErrInvalidRequest},
		{"other assignment", ir, partitions.NewWeightedPartitionTrustBase("other", map[string]uint64{"a": 3, "b": 2, "c": 1}), quorumweight.ErrRequestContext},
		{"no quorum information", ir, nil, quorumweight.ErrRequestContext},
		{"inconsistent context", ir, inconsistentTB{tb}, quorumweight.ErrInconsistentTally},
	} {
		t.Run(tc.name, func(t *testing.T) {
			qs, proof, err := rs.add(tc.req, tc.tb)
			require.ErrorIs(t, err, tc.is)
			require.Equal(t, QuorumUnknown, qs)
			require.Nil(t, proof)
			require.Equal(t, before, snapshot(rs))
		})
	}
	// the refused request did not use up its signer: "b" is still accepted afterwards
	qs, _, err := rs.add(ir, tb)
	require.NoError(t, err)
	require.Equal(t, QuorumAchieved, qs)
}

// inconsistentTB reports a threshold that is not the majority of its total.
type inconsistentTB struct{ *partitions.TrustBase }

func (inconsistentTB) Threshold() uint64 { return 1 }

// The same through CertRequestBuffer, whose nil guard comes before any shard state is created.
func TestCertRequestBufferRefusesNil(t *testing.T) {
	cs, err := NewCertificationRequestBuffer(observability.Default(t).Meter("test"))
	require.NoError(t, err)
	tb := partitions.NewPartitionTrustBase(nil)
	for _, req := range []*certification.BlockCertificationRequest{nil, {PartitionID: sysID1, NodeID: "1"}} {
		_, _, err = cs.Add(context.Background(), req, tb)
		require.ErrorIs(t, err, rctypes.ErrInvalidRequest)
	}
	require.Empty(t, cs.store)
}

// Requests counted under one assignment are never retallied with another's weights: the other assignment is refused, its
// status query says nothing, and only after Clear is it accepted.
func TestRequestBufferTagsTheAssignment(t *testing.T) {
	cs, err := NewCertificationRequestBuffer(observability.Default(t).Meter("test"))
	require.NoError(t, err)
	old := partitions.NewWeightedPartitionTrustBase("old", map[string]uint64{"a": 6, "b": 1, "c": 1, "d": 1})
	fresh := partitions.NewWeightedPartitionTrustBase("new", map[string]uint64{"a": 1, "b": 6, "c": 1, "d": 1})
	shard := types.ShardID{}
	_, _, err = cs.Add(context.Background(), voteReq(requestvectors.Vote{Signer: "b", Group: "X"}), old)
	require.NoError(t, err)
	require.Equal(t, QuorumInProgress, cs.IsConsensusReceived(sysID1, shard, old))
	require.Equal(t, QuorumUnknown, cs.IsConsensusReceived(sysID1, shard, fresh), "a status counted under the old weights is not the new one's")

	// b has weight 6 under the new assignment and would certify; the old tally must not be reweighted
	qs, _, err := cs.Add(context.Background(), voteReq(requestvectors.Vote{Signer: "c", Group: "X"}), fresh)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext)
	require.Equal(t, QuorumUnknown, qs)
	require.Equal(t, QuorumInProgress, cs.IsConsensusReceived(sysID1, shard, old))

	cs.Clear(context.Background(), sysID1, shard)
	qs, _, err = cs.Add(context.Background(), voteReq(requestvectors.Vote{Signer: "b", Group: "X"}), fresh)
	require.NoError(t, err)
	require.Equal(t, QuorumAchieved, qs, "fresh assignment: b has weight 6")
}

// The buffer owns what it stores and returns: mutating the request after Add or the proof after it was returned changes
// nothing that is counted.
func TestRequestBufferOwnsItsRequests(t *testing.T) {
	tb := partitions.NewPartitionTrustBase(map[string]crypto.Verifier{"a": nil, "b": nil, "c": nil})
	rs := newRequestStore()
	req := voteReq(requestvectors.Vote{Signer: "a", Group: "X"})
	_, _, err := rs.add(req, tb)
	require.NoError(t, err)
	req.InputRecord.Hash[0] ^= 0xff
	req.Signature = []byte{1}
	_, proof, err := rs.add(voteReq(requestvectors.Vote{Signer: "b", Group: "X"}), tb)
	require.NoError(t, err)
	require.Len(t, proof, 2, "a's mutated request still counted in group X")
	for _, r := range proof {
		require.Equal(t, []byte("X"), []byte(r.InputRecord.Hash))
		r.InputRecord.Hash[0] = 0
	}
	_, proof, err = rs.add(voteReq(requestvectors.Vote{Signer: "c", Group: "X"}), tb)
	require.NoError(t, err)
	for _, r := range proof {
		require.Equal(t, []byte("X"), []byte(r.InputRecord.Hash), "mutating an earlier proof did not reach the buffer")
	}
}

// The no-quorum proof is a copy too.
func TestRequestBufferNoQuorumProofIsACopy(t *testing.T) {
	tb := partitions.NewPartitionTrustBase(map[string]crypto.Verifier{"a": nil, "b": nil})
	rs := newRequestStore()
	_, _, err := rs.add(voteReq(requestvectors.Vote{Signer: "a", Group: "X"}), tb)
	require.NoError(t, err)
	qs, proof, err := rs.add(voteReq(requestvectors.Vote{Signer: "b", Group: "Y"}), tb)
	require.NoError(t, err)
	require.Equal(t, QuorumNotPossible, qs)
	for _, r := range proof {
		r.InputRecord.Hash[0] = 0
	}
	for _, reqs := range rs.requests {
		for _, r := range reqs {
			require.NotEqual(t, byte(0), r.InputRecord.Hash[0])
		}
	}
}

// The first public Add of a shard is atomic: a refusal publishes no shard state, and the shard is still empty afterwards.
func TestCertRequestBufferFirstRefusedAddPublishesNothing(t *testing.T) {
	tb := partitions.NewWeightedPartitionTrustBase("w", map[string]uint64{"a": 3, "b": 2, "c": 1})
	for _, tc := range []struct {
		name string
		req  *certification.BlockCertificationRequest
		tb   QuorumInfo
		is   error
	}{
		{"unknown signer", voteReq(requestvectors.Vote{Signer: "zz", Group: "X"}), tb, quorumweight.ErrUnknownSigner},
		{"no quorum information", voteReq(requestvectors.Vote{Signer: "a", Group: "X"}), nil, quorumweight.ErrRequestContext},
		{"inconsistent threshold", voteReq(requestvectors.Vote{Signer: "a", Group: "X"}), inconsistentTB{tb}, quorumweight.ErrInconsistentTally},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs, err := NewCertificationRequestBuffer(observability.Default(t).Meter("test"))
			require.NoError(t, err)
			qs, proof, err := cs.Add(context.Background(), tc.req, tc.tb)
			require.ErrorIs(t, err, tc.is)
			require.Equal(t, QuorumUnknown, qs)
			require.Nil(t, proof)
			require.Empty(t, cs.store, "a refused first Add must not register the shard")
			// and the same request is accepted afterwards under a good context
			qs, _, err = cs.Add(context.Background(), voteReq(requestvectors.Vote{Signer: "a", Group: "X"}), tb)
			require.NoError(t, err)
			require.Equal(t, QuorumInProgress, qs)
			require.Len(t, cs.store, 1)
		})
	}
}

// taggedTB is a QuorumInfo that also names the shard round and anchor its requests build on.
type taggedTB struct {
	QuorumInfo
	tag string
}

func (t taggedTB) RoundTag() string { return t.tag }

// Stale buffer status: a quorum counted for one shard round/anchor says nothing about the next, new requests are refused
// against it with the request-context sentinel and never retallied, and only retiring it (the round advanced) or Clear starts
// the next tally. A buffer counted under the same tag, an empty one and an unknown shard are not retired.
func TestRequestBufferTagsTheShardRoundAndAnchor(t *testing.T) {
	cs, err := NewCertificationRequestBuffer(observability.Default(t).Meter("test"))
	require.NoError(t, err)
	base := partitions.NewWeightedPartitionTrustBase("same", map[string]uint64{"a": 6, "b": 1, "c": 1, "d": 1})
	r1, r2 := taggedTB{base, "round-1"}, taggedTB{base, "round-2"}
	shard := types.ShardID{}
	ctx := context.Background()

	qs, _, err := cs.Add(ctx, voteReq(requestvectors.Vote{Signer: "a", Group: "X"}), r1)
	require.NoError(t, err)
	require.Equal(t, QuorumAchieved, qs)
	require.Equal(t, QuorumAchieved, cs.IsConsensusReceived(sysID1, shard, r1))
	require.Equal(t, QuorumUnknown, cs.IsConsensusReceived(sysID1, shard, r2), "the stale status is not the next round's")
	require.Equal(t, QuorumUnknown, cs.IsConsensusReceived(sysID1, shard, base), "an untagged context never reads a tagged tally")

	before := snapshot(cs.store[partitionShard{partition: sysID1, shard: shard.Key()}])
	qs, proof, err := cs.Add(ctx, voteReq(requestvectors.Vote{Signer: "b", Group: "X"}), r2)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext)
	require.Equal(t, QuorumUnknown, qs)
	require.Nil(t, proof)
	require.Equal(t, before, snapshot(cs.store[partitionShard{partition: sysID1, shard: shard.Key()}]), "a refused request changes nothing")

	require.False(t, cs.Retire(sysID1, shard, r1), "counted under this tag")
	require.False(t, cs.Retire(sysID1, shard, nil))
	require.False(t, cs.Retire(sysID2, shard, r2), "no buffer for the shard")
	require.True(t, cs.Retire(sysID1, shard, r2))
	require.False(t, cs.Retire(sysID1, shard, r2), "already empty")
	require.Equal(t, QuorumInProgress, cs.IsConsensusReceived(sysID1, shard, r2))
	qs, _, err = cs.Add(ctx, voteReq(requestvectors.Vote{Signer: "b", Group: "X"}), r2)
	require.NoError(t, err)
	require.Equal(t, QuorumInProgress, qs, "a's old weight-6 signature is not counted again: only b's 1 of 9")
}
