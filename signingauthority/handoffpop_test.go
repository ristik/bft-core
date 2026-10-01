package signingauthority

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-go-base/types"
)

func popFixture(t *testing.T) (*Authority, HandoffPoPRequest, []byte) {
	t.Helper()
	f := newFixture(t, 1)
	a, err := New(f.enroll, trustStub{tb: f.tb})
	require.NoError(t, err)
	pub, err := a.SigningPublicKey()
	require.NoError(t, err)
	succ := &types.PartitionDescriptionRecord{Version: 1, NetworkID: testNetworkID, PartitionID: testPartitionID, PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 2500000000,
		Epoch: shardEpoch + 1, Validators: []*types.NodeInfo{{NodeID: testNodeID, SigKey: pub, Stake: 1}}}
	req := HandoffPoPRequest{Domain: evmassign.PoPDomain, NodeID: testNodeID, Successor: succ,
		Context: evmassign.PoPContext{Network: uint64(testNetworkID), Attempt: 2, Predecessor: [32]byte{1}}}
	return a, req, pub
}

// The proof the authority signs is exactly the one a handoff verifies: the same message, for the authority's own key.
func TestHandoffPoPVerifiesInTheHandoff(t *testing.T) {
	a, req, pub := popFixture(t)
	pop, err := a.SignHandoffPoP(req)
	require.NoError(t, err)
	require.Equal(t, testNodeID, pop.NodeID)
	require.Equal(t, pub, []byte(pop.Key))
	require.NoError(t, evmassign.VerifyPoPs(req.Context, req.Successor, []evmassign.PoP{pop}), "the handoff accepts the authority's proof")
	// Bound to its context: the same proof does not verify for another attempt, predecessor or frozen parent.
	for name, mutate := range map[string]func(*evmassign.PoPContext){
		"attempt":     func(c *evmassign.PoPContext) { c.Attempt++ },
		"predecessor": func(c *evmassign.PoPContext) { c.Predecessor = [32]byte{9} },
	} {
		other := req.Context
		mutate(&other)
		require.ErrorIs(t, evmassign.VerifyPoPs(other, req.Successor, []evmassign.PoP{pop}), evmassign.ErrPoP, name)
	}
	// It signs no certification round: the signing record is untouched.
	require.False(t, a.Status().HasReservation)
}

func TestHandoffPoPRefusesAWrongDomain(t *testing.T) {
	a, req, _ := popFixture(t)
	for _, domain := range []string{"", "UNICITY_H3_EVM_ASSIGNMENT", "UNICITY_H3_EVM_ASSIGNMENT_POP ", "certification", "UNICITY_H3_EVM_ASSIGNMENT_POP\x00"} {
		req.Domain = domain
		_, err := a.SignHandoffPoP(req)
		require.ErrorIs(t, err, ErrPoPDomain, "domain %q", domain)
	}
}

// Each context check refuses on its own, with the sentinel the contract names.
func TestHandoffPoPRefusesAWrongContext(t *testing.T) {
	cases := map[string]func(*HandoffPoPRequest, []byte){
		"another node":             func(r *HandoffPoPRequest, _ []byte) { r.NodeID = "someone-else" },
		"another network (ctx)":    func(r *HandoffPoPRequest, _ []byte) { r.Context.Network++ },
		"another network (succ)":   func(r *HandoffPoPRequest, _ []byte) { r.Successor.NetworkID++ },
		"another partition":        func(r *HandoffPoPRequest, _ []byte) { r.Successor.PartitionID++ },
		"another shard":            func(r *HandoffPoPRequest, _ []byte) { r.Successor.ShardID, _ = (types.ShardID{}).Split() },
		"not the next shard epoch": func(r *HandoffPoPRequest, _ []byte) { r.Successor.Epoch += 1 },
		"a shard epoch two ahead":  func(r *HandoffPoPRequest, _ []byte) { r.Successor.Epoch = shardEpoch + 2 },
		"no predecessor":           func(r *HandoffPoPRequest, _ []byte) { r.Context.Predecessor = [32]byte{} },
		"no successor":             func(r *HandoffPoPRequest, _ []byte) { r.Successor = nil },
		"the successor names another key": func(r *HandoffPoPRequest, _ []byte) {
			other, err := New(Enrollment{AuthorityID: "x", NodeID: "x", NetworkID: testNetworkID, PartitionID: testPartitionID, RootEpoch: PinRootEpoch(rootEpoch), Profile: ProfileLegacyBCRv1}, trustStub{})
			if err == nil {
				k, _ := other.SigningPublicKey()
				r.Successor.Validators[0].SigKey = k
			}
		},
		"the successor omits this node": func(r *HandoffPoPRequest, _ []byte) { r.Successor.Validators[0].NodeID = "not-this-node" },
		"an invalid assignment":         func(r *HandoffPoPRequest, _ []byte) { r.Successor.Validators[0].Stake = 2 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a, req, pub := popFixture(t)
			mutate(&req, pub)
			_, err := a.SignHandoffPoP(req)
			require.ErrorIs(t, err, ErrContextMismatch)
		})
	}
	t.Run("a closed authority has no key to sign with", func(t *testing.T) {
		a, req, _ := popFixture(t)
		a.Close()
		_, err := a.SignHandoffPoP(req)
		require.ErrorIs(t, err, ErrKeyLost)
	})
	t.Run("a joining validator's pending authority proves for its enrolled epoch", func(t *testing.T) {
		f := newFixture(t, 1)
		pending := f.enroll
		pending.ShardConfHash = nil
		pending.ShardEpoch = shardEpoch + 1
		a, err := New(pending, trustStub{tb: f.tb})
		require.NoError(t, err)
		pub, err := a.SigningPublicKey()
		require.NoError(t, err)
		succ := &types.PartitionDescriptionRecord{Version: 1, NetworkID: testNetworkID, PartitionID: testPartitionID, PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 2500000000,
			Epoch: shardEpoch + 1, Validators: []*types.NodeInfo{{NodeID: testNodeID, SigKey: pub, Stake: 1}}}
		req := HandoffPoPRequest{Domain: evmassign.PoPDomain, NodeID: testNodeID, Successor: succ,
			Context: evmassign.PoPContext{Network: uint64(testNetworkID), Predecessor: [32]byte{1}}}
		pop, err := a.SignHandoffPoP(req)
		require.NoError(t, err)
		require.NoError(t, evmassign.VerifyPoPs(req.Context, succ, []evmassign.PoP{pop}))
	})
}
