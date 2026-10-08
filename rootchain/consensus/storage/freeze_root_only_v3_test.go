package storage

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// rootOnlyRules is a V3FreezeRules that reports a fixed committee for any body.
type rootOnlyRules struct{ members []evmassign.RootMember }

func (r rootOnlyRules) VerifyBody([]byte) (V3Body, error) { return V3Body{Members: r.members}, nil }
func (rootOnlyRules) Prior(uint64, uint64, uint64, []byte) ([]byte, error) {
	return nil, errors.New("not used")
}
func (rootOnlyRules) VerifyReceipts([]byte, []byte, uint64, []byte) error { return nil }

// A root-only handoff through the Q3 flow (no EVM assignment, an empty candidate preimage) carries a VERSION-3 body. On a chain that requires coupling the
// freeze admission must read that body's committee as a V3 body: the same committee passes, a changed committee is an uncoupled change.
func TestARootOnlyV3FreezeIsJudgedOnItsV3BodyOnACouplingChain(t *testing.T) {
	committee := []evmassign.RootMember{{NodeID: "a", Key: []byte{1}, Weight: 1}, {NodeID: "b", Key: []byte{2}, Weight: 1}, {NodeID: "c", Key: []byte{3}, Weight: 1}}
	companion, err := FreezeV3Authorization{Version: freezeV3Version, Body: []byte("v3 body"), Parent: bytes.Repeat([]byte{4}, 32), Candidate: bytes.Repeat([]byte{5}, 32),
		Receipts: []byte("receipts"), Signatures: map[string]hex.Bytes{"a": {1}}}.Bytes()
	require.NoError(t, err)
	installed := &types.PartitionDescriptionRecord{PartitionParams: map[string]string{evmassign.CouplingParam: "true"}}
	steady := &ShardInfo{IR: &types.InputRecord{Epoch: 3}, TR: certification.TechnicalRecord{Epoch: 3}}
	verify := func(si *ShardInfo, rules V3FreezeRules) error {
		return verifyFreezeAssignment(companion, si, installed, nil, committee, nil, nil, rules)
	}

	require.NoError(t, verify(steady, rootOnlyRules{members: committee}), "the same committee in a V3 body is admitted")

	changed := append(append([]evmassign.RootMember(nil), committee[:2]...), evmassign.RootMember{NodeID: "d", Key: []byte{9}, Weight: 1})
	require.ErrorIs(t, verify(steady, rootOnlyRules{members: changed}), evmassign.ErrCoupling, "a changed committee is an uncoupled change")

	reweighted := append([]evmassign.RootMember(nil), committee...)
	reweighted[0].Weight = 5
	require.ErrorIs(t, verify(steady, rootOnlyRules{members: reweighted}), evmassign.ErrCoupling, "new weights without a new EVM assignment are an uncoupled change")

	require.ErrorIs(t, verify(steady, nil), ErrFreezeV3Disabled, "a V3 companion without V3 rules is refused by name")

	pending := &ShardInfo{IR: &types.InputRecord{Epoch: 3}, TR: certification.TechnicalRecord{Epoch: 4}}
	require.ErrorIs(t, verify(pending, rootOnlyRules{members: committee}), ErrAssignmentAckPending, "an unacknowledged assignment still blocks it")
}
