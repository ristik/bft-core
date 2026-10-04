package types

import (
	"crypto"
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/testutils/requestvectors"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	abhash "github.com/unicitynetwork/bft-go-base/hash"
	"github.com/unicitynetwork/bft-go-base/types"
)

const testPartition types.PartitionID = 8

func groupIR(group string) *types.InputRecord {
	return &types.InputRecord{Version: 1, PreviousHash: []byte{9}, Hash: []byte(group), RoundNumber: 2, Timestamp: 1}
}

func vReq(signer, group string, blockSize uint64) *certification.BlockCertificationRequest {
	return &certification.BlockCertificationRequest{PartitionID: testPartition, NodeID: signer, InputRecord: groupIR(group), BlockSize: blockSize}
}

func groupHash(t *testing.T, r *certification.BlockCertificationRequest) [32]byte {
	h, err := abhash.HashValues(crypto.SHA256, r.InputRecord, r.BlockSize, r.StateSize)
	require.NoError(t, err)
	return sha256Hash(h)
}

func permutations(votes []requestvectors.Vote, visit func([]requestvectors.Vote)) {
	var rec func(k int)
	cur := slices.Clone(votes)
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

func luc() *types.UnicityCertificate {
	return &types.UnicityCertificate{Version: 1, InputRecord: &types.InputRecord{Version: 1, Hash: []byte{9}, RoundNumber: 1}, UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 1}}
}

func proofOf(votes []requestvectors.Vote, reason IRChangeReason) *IRChangeReq {
	x := &IRChangeReq{Partition: testPartition, CertReason: reason}
	for _, v := range votes {
		x.Requests = append(x.Requests, vReq(v.Signer, v.Group, 0))
	}
	return x
}

// The shared vectors through independent proof verification: for every arrival order and every prefix (so every subset in
// every order) a proof is accepted exactly when the brute-force oracle says it proves what it claims.
func TestVerifyProofAgreesWithOracle(t *testing.T) {
	for _, vec := range requestvectors.Vectors() {
		t.Run(vec.Name, func(t *testing.T) {
			tb := mockReqVerifier{weights: vec.Weights, validReq: func(*certification.BlockCertificationRequest) error { return nil }}
			require.Equal(t, vec.Total(), tb.TotalWeight())
			permutations(vec.Votes, func(order []requestvectors.Vote) {
				for n := 1; n <= len(order); n++ {
					prefix := order[:n]
					want := vec.Oracle(prefix)

					// no-quorum proof over every request received so far
					_, err := proofOf(prefix, QuorumNotPossible).Verify(tb, luc(), 5, 1)
					if want == requestvectors.Impossible {
						require.NoError(t, err, "%v", prefix)
					} else {
						require.ErrorIs(t, err, ErrInvalidRequest, "%v is %s", prefix, want)
					}

					// quorum proof over the winning group only
					if want == requestvectors.Achieved {
						win := vec.Winner(prefix)
						var group []requestvectors.Vote
						for _, v := range prefix {
							if v.Group == win {
								group = append(group, v)
							}
						}
						ir, err := proofOf(group, Quorum).Verify(tb, luc(), 5, 1)
						require.NoError(t, err, "%v", prefix)
						require.Equal(t, win, string(ir.Hash))
						// a proof carrying a losing group as well is redundant info and refused
						if len(group) < len(prefix) {
							_, err = proofOf(prefix, Quorum).Verify(tb, luc(), 5, 1)
							require.ErrorIs(t, err, ErrInvalidRequest)
						}
					} else {
						// no group has a quorum: the heaviest single group cannot be proven as one
						for g := range groupsOf(prefix) {
							var group []requestvectors.Vote
							for _, v := range prefix {
								if v.Group == g {
									group = append(group, v)
								}
							}
							_, err := proofOf(group, Quorum).Verify(tb, luc(), 5, 1)
							require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached, "%v", group)
							require.ErrorIs(t, err, ErrInvalidRequest)
						}
					}
				}
			})
		})
	}
}

func groupsOf(votes []requestvectors.Vote) map[string]bool {
	m := map[string]bool{}
	for _, v := range votes {
		m[v.Group] = true
	}
	return m
}

// Fixture 1: the heavy signer certifies alone; the three light ones cannot, and their omission of the heavy signer is not
// impossibility (M=3, U=6); the root threshold 7 would be a different number.
func TestVerifySkewedWeights(t *testing.T) {
	skew := mockReqVerifier{weights: map[string]uint64{"a": 6, "b": 1, "c": 1, "d": 1}, validReq: func(*certification.BlockCertificationRequest) error { return nil }}
	require.EqualValues(t, 9, skew.TotalWeight())
	require.EqualValues(t, 5, skew.Threshold())
	_, err := proofOf([]requestvectors.Vote{{Signer: "a", Group: "X"}}, Quorum).Verify(skew, luc(), 5, 1)
	require.NoError(t, err, "one heavy signer certifies")
	_, err = proofOf([]requestvectors.Vote{{Signer: "b", Group: "X"}, {Signer: "c", Group: "X"}, {Signer: "d", Group: "X"}}, Quorum).Verify(skew, luc(), 5, 1)
	require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached, "three light identities are a count majority, not a weight quorum")
	_, err = proofOf([]requestvectors.Vote{{Signer: "b", Group: "X"}, {Signer: "c", Group: "Y"}, {Signer: "d", Group: "Z"}}, QuorumNotPossible).Verify(skew, luc(), 5, 1)
	require.ErrorIs(t, err, ErrInvalidRequest, "the light identities omit the heavy signer: M=1, U=6")
	// four unit keys: three are needed, one never certifies
	unit := mockReqVerifier{nodeCnt: 4, validReq: func(*certification.BlockCertificationRequest) error { return nil }}
	_, err = proofOf([]requestvectors.Vote{{Signer: "a", Group: "X"}}, Quorum).Verify(unit, luc(), 5, 1)
	require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached)
	_, err = proofOf([]requestvectors.Vote{{Signer: "a", Group: "X"}, {Signer: "b", Group: "X"}, {Signer: "c", Group: "X"}}, Quorum).Verify(unit, luc(), 5, 1)
	require.NoError(t, err)
}

// Fixture 2, spelled out: the strict boundary is impossible (5<6), the equality case is not (6==Q), and the repeat UC
// follows the strict proof.
func TestVerifyExactBoundary(t *testing.T) {
	tb := mockReqVerifier{weights: map[string]uint64{"a": 3, "b": 2, "c": 1, "d": 2, "e": 2}, validReq: func(*certification.BlockCertificationRequest) error { return nil }}
	strict := []requestvectors.Vote{{Signer: "a", Group: "X"}, {Signer: "b", Group: "Y"}, {Signer: "c", Group: "Y"}, {Signer: "d", Group: "Z"}}
	ir, err := proofOf(strict, QuorumNotPossible).Verify(tb, luc(), 5, 1)
	require.NoError(t, err)
	require.Equal(t, luc().InputRecord.NewRepeatIR(), ir, "the strict boundary certifies a repeat UC")
	equal := []requestvectors.Vote{{Signer: "a", Group: "X"}, {Signer: "b", Group: "Y"}, {Signer: "d", Group: "Y"}, {Signer: "c", Group: "Z"}}
	_, err = proofOf(equal, QuorumNotPossible).Verify(tb, luc(), 5, 1)
	require.ErrorIs(t, err, ErrInvalidRequest, "M+U == Q is still possible")
	require.ErrorContains(t, err, "it is possible to get 6 votes, quorum is 6")
}

// Group hashes include the sizes: equal IR with different block sizes are different groups.
func TestVerifyMatchingHashIncludesSizes(t *testing.T) {
	tb := mockReqVerifier{nodeCnt: 3, validReq: func(*certification.BlockCertificationRequest) error { return nil }}
	require.NotEqual(t, groupHash(t, vReq("a", "X", 1)), groupHash(t, vReq("a", "X", 2)))
	x := &IRChangeReq{Partition: testPartition, CertReason: Quorum, Requests: []*certification.BlockCertificationRequest{vReq("a", "X", 1), vReq("b", "X", 2)}}
	_, err := x.Verify(tb, luc(), 5, 1)
	require.ErrorIs(t, err, ErrInvalidRequest, "same IR, different sizes: two groups")
	x.Requests[1].BlockSize = 1
	_, err = x.Verify(tb, luc(), 5, 1)
	require.NoError(t, err)
}

// Proof bounds are member counts, not weights: a heavy committee of two still cannot carry three requests.
func TestVerifyBoundIsMemberCount(t *testing.T) {
	tb := mockReqVerifier{weights: map[string]uint64{"a": 100, "b": 100}, validReq: func(*certification.BlockCertificationRequest) error { return nil }}
	x := proofOf([]requestvectors.Vote{{Signer: "a", Group: "X"}, {Signer: "b", Group: "X"}, {Signer: "c", Group: "X"}}, Quorum)
	_, err := x.Verify(tb, luc(), 5, 1)
	require.ErrorIs(t, err, ErrInvalidRequest)
	require.EqualError(t, err, "IR Change Request contains more requests than registered partition nodes")
}

// Forged, unknown, duplicate and nil requests are refused with their sentinels.
func TestVerifyRejectsBadRequests(t *testing.T) {
	forged := fmt.Errorf("%w: bad signature", quorumweight.ErrInvalidSignature)
	tb := mockReqVerifier{weights: map[string]uint64{"a": 3, "b": 2}, validReq: func(r *certification.BlockCertificationRequest) error {
		if r.NodeID == "b" {
			return forged
		}
		return nil
	}}
	_, err := (&IRChangeReq{Partition: testPartition, CertReason: Quorum, Requests: []*certification.BlockCertificationRequest{vReq("a", "X", 0), vReq("b", "X", 0)}}).Verify(tb, luc(), 5, 1)
	require.ErrorIs(t, err, quorumweight.ErrInvalidSignature)

	tb.validReq = func(*certification.BlockCertificationRequest) error { return nil }
	_, err = (&IRChangeReq{Partition: testPartition, CertReason: Quorum, Requests: []*certification.BlockCertificationRequest{vReq("zz", "X", 0)}}).Verify(tb, luc(), 5, 1)
	require.ErrorIs(t, err, quorumweight.ErrUnknownSigner)
	_, err = (&IRChangeReq{Partition: testPartition, CertReason: Quorum, Requests: []*certification.BlockCertificationRequest{vReq("a", "X", 0), vReq("a", "X", 0)}}).Verify(tb, luc(), 5, 1)
	require.ErrorIs(t, err, quorumweight.ErrDuplicateSigner)
	require.ErrorIs(t, err, ErrInvalidRequest)
	require.EqualError(t, err, "invalid partition 00000008 proof: contains duplicate request from node a")
	_, err = (&IRChangeReq{Partition: testPartition, CertReason: Quorum, Requests: []*certification.BlockCertificationRequest{nil}}).Verify(tb, luc(), 5, 1)
	require.ErrorIs(t, err, ErrInvalidRequest)
	other := vReq("a", "X", 0)
	other.PartitionID = 9
	_, err = (&IRChangeReq{Partition: testPartition, CertReason: Quorum, Requests: []*certification.BlockCertificationRequest{other}}).Verify(tb, luc(), 5, 1)
	require.ErrorIs(t, err, ErrInvalidRequest)
}

// A context whose threshold is not the majority of its total is an inconsistent tally: an error, never impossibility.
func TestTallyRefusesInconsistentContext(t *testing.T) {
	tally := NewRequestTally(brokenWeights{})
	require.NoError(t, tally.Add("a", [32]byte{1}))
	_, err := tally.QuorumImpossible()
	require.ErrorIs(t, err, quorumweight.ErrInconsistentTally)
}

// A zero total, a received weight above the total and a threshold that is not the majority are all refused by Validate.
func TestTallyValidate(t *testing.T) {
	require.ErrorIs(t, NewRequestTally(zeroTotal{}).Validate(), quorumweight.ErrZeroWeight)

	over := NewRequestTally(smallTotal{})
	require.NoError(t, over.Add("a", [32]byte{1}))
	require.ErrorIs(t, over.Validate(), quorumweight.ErrInconsistentTally, "5 received of a total of 4")

	require.ErrorIs(t, NewRequestTally(brokenWeights{}).Validate(), quorumweight.ErrInconsistentTally)
	require.NoError(t, NewRequestTally(mockReqVerifier{nodeCnt: 3}).Validate())
}

type zeroTotal struct{ brokenWeights }

func (zeroTotal) TotalWeight() uint64 { return 0 }
func (zeroTotal) Threshold() uint64   { return 1 }

// smallTotal has a member heavier than its total: threshold 3 is consistent with 4, the received weight 5 is not.
type smallTotal struct{ brokenWeights }

func (smallTotal) TotalWeight() uint64                 { return 4 }
func (smallTotal) Threshold() uint64                   { return 3 }
func (smallTotal) SignerWeight(string) (uint64, error) { return 5, nil }

// An inconsistent context never certifies and never proves impossibility, whatever the proof.
func TestVerifyRefusesInconsistentContext(t *testing.T) {
	tb := inconsistentVerifier{mockReqVerifier{weights: map[string]uint64{"a": 3, "b": 2, "c": 1}, validReq: func(*certification.BlockCertificationRequest) error { return nil }}}
	_, err := proofOf([]requestvectors.Vote{{Signer: "a", Group: "X"}}, Quorum).Verify(tb, luc(), 5, 1)
	require.ErrorIs(t, err, quorumweight.ErrInconsistentTally, "threshold 1 would let one request certify")
	require.ErrorIs(t, err, ErrInvalidRequest)
	_, err = proofOf([]requestvectors.Vote{{Signer: "a", Group: "X"}, {Signer: "b", Group: "Y"}, {Signer: "c", Group: "Z"}}, QuorumNotPossible).Verify(tb, luc(), 5, 1)
	require.ErrorIs(t, err, quorumweight.ErrInconsistentTally)
	// weight never affects time: a timeout proof does not read the weights
	_, err = proofOf(nil, T2Timeout).Verify(tb, luc(), 5, 1)
	require.NoError(t, err)
}

type inconsistentVerifier struct{ mockReqVerifier }

func (inconsistentVerifier) Threshold() uint64 { return 1 }

// A no-quorum proof over a set where a group already has quorum is refused as such.
func TestVerifyNoQuorumProofOfAnAchievedQuorum(t *testing.T) {
	tb := mockReqVerifier{weights: map[string]uint64{"a": 3, "b": 2, "c": 1}, validReq: func(*certification.BlockCertificationRequest) error { return nil }}
	_, err := proofOf([]requestvectors.Vote{{Signer: "a", Group: "X"}, {Signer: "b", Group: "X"}}, QuorumNotPossible).Verify(tb, luc(), 5, 1)
	require.ErrorIs(t, err, ErrInvalidRequest)
	require.ErrorContains(t, err, "one input already does have quorum (5 votes, quorum is 4)")
}

type brokenWeights struct{}

func (brokenWeights) MemberCount() int                    { return 1 }
func (brokenWeights) TotalWeight() uint64                 { return 10 }
func (brokenWeights) Threshold() uint64                   { return 1 }
func (brokenWeights) SignerWeight(string) (uint64, error) { return 1, nil }

// A refused Add leaves the tally unchanged.
func TestTallyAddIsAtomic(t *testing.T) {
	tb := mockReqVerifier{weights: map[string]uint64{"a": 3, "b": 2}}
	tally := NewRequestTally(tb)
	require.NoError(t, tally.Add("a", [32]byte{1}))
	for _, bad := range []string{"a", "zz"} {
		require.Error(t, tally.Add(bad, [32]byte{1}))
		require.EqualValues(t, 3, tally.Received())
		require.EqualValues(t, 3, tally.Matching())
		require.Equal(t, 1, tally.Signers())
	}
	over := NewRequestTally(overflowWeights{})
	require.NoError(t, over.Add("a", [32]byte{1}))
	require.ErrorIs(t, over.Add("b", [32]byte{2}), quorumweight.ErrWeightOverflow)
	require.Equal(t, 1, over.Signers())
	zero := NewRequestTally(zeroWeights{})
	require.ErrorIs(t, zero.Add("a", [32]byte{1}), quorumweight.ErrZeroWeight)
	require.Zero(t, zero.Signers())
}

type overflowWeights struct{ brokenWeights }

func (overflowWeights) SignerWeight(string) (uint64, error) { return ^uint64(0), nil }

type zeroWeights struct{ brokenWeights }

func (zeroWeights) SignerWeight(string) (uint64, error) { return 0, nil }
