package weightvalidation

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// members returns len(weights) ordered nodes with distinct valid keys and the given weights.
func members(t *testing.T, weights ...uint64) []*types.NodeInfo {
	t.Helper()
	out := make([]*types.NodeInfo, len(weights))
	for i, w := range weights {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		key, err := v.MarshalPublicKey()
		require.NoError(t, err)
		out[i] = &types.NodeInfo{NodeID: fmt.Sprintf("n%03d", i), SigKey: key, Stake: w}
	}
	return out
}

func trustBase(t *testing.T, nodes []*types.NodeInfo, threshold uint64) *types.RootTrustBaseV1 {
	t.Helper()
	return &types.RootTrustBaseV1{Version: 1, NetworkID: 5, Epoch: 1, RootNodes: nodes, QuorumThreshold: threshold}
}

func pdr(nodes []*types.NodeInfo) *types.PartitionDescriptionRecord {
	return &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, PartitionTypeID: 8,
		TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 5 * time.Second, Epoch: 3, EpochStart: 11, Validators: nodes}
}

func TestUnitModeIsGoBaseUnchanged(t *testing.T) {
	n := members(t, 1, 2, 1)
	for _, role := range []Role{RoleRoot, RoleEVM} {
		require.NoError(t, Node(n[0], role, ModeUnit), "acceptance control")
		// the very error go-base gives, not a rewording of it
		require.EqualError(t, Node(n[1], role, ModeUnit), n[1].IsValid().Error())
	}
	require.EqualError(t, PDR(pdr(n), RoleEVM, ModeUnit), pdr(n).IsValid().Error())
	require.ErrorContains(t, EVMSet(n, ModeUnit), "validator 1")
	require.Equal(t, evmassign.ValidateSet(n), EVMSet(n, ModeUnit))
	require.NoError(t, PDR(pdr(members(t, 1, 1, 1)), RoleEVM, ModeUnit))
	require.NoError(t, EVMSet(members(t, 1, 1, 1), ModeUnit))
}

func TestWeightedAcceptsTheCoupledFixture(t *testing.T) {
	// (6,1,1,1): W=9, root threshold 7
	n := members(t, 6, 1, 1, 1)
	total, err := Nodes(n, RoleRoot, ModeWeighted)
	require.NoError(t, err)
	require.Equal(t, uint64(9), total)
	require.NoError(t, RootTrustBase(trustBase(t, n, 7), ModeWeighted))
	require.NoError(t, PDR(pdr(n), RoleEVM, ModeWeighted))
	require.NoError(t, EVMSet(n, ModeWeighted))
	big := members(t, evmroot.MaxMemberWeight, 1)
	require.NoError(t, EVMSet(big, ModeWeighted), "a member at the cap is allowed")
}

func TestWeightedRefusals(t *testing.T) {
	good := func() []*types.NodeInfo { return members(t, 6, 1, 1, 1) }
	t.Run("zero weight", func(t *testing.T) {
		n := good()
		n[1].Stake = 0
		require.ErrorIs(t, Node(n[1], RoleRoot, ModeWeighted), ErrWeight)
		require.ErrorIs(t, EVMSet(n, ModeWeighted), ErrWeight)
		require.ErrorIs(t, PDR(pdr(n), RoleEVM, ModeWeighted), ErrWeight)
	})
	t.Run("member above the cap", func(t *testing.T) {
		n := good()
		n[0].Stake = evmroot.MaxMemberWeight + 1
		require.ErrorIs(t, Node(n[0], RoleRoot, ModeWeighted), ErrWeight)
		_, err := Nodes(n, RoleRoot, ModeWeighted)
		require.ErrorIs(t, err, ErrWeight)
	})
	t.Run("total above the cap", func(t *testing.T) {
		w := make([]uint64, 257) // 257 * 2^40 > 2^48, each member at the cap
		for i := range w {
			w[i] = evmroot.MaxMemberWeight
		}
		n := members(t, w...)
		_, err := Nodes(n, RoleRoot, ModeWeighted)
		require.ErrorIs(t, err, ErrTotalWeight)
		require.NotErrorIs(t, err, ErrWeight, "each member alone is in range")
		_, err = Nodes(n[:256], RoleRoot, ModeWeighted)
		require.NoError(t, err, "exactly the cap is allowed")
	})
	t.Run("duplicate node id", func(t *testing.T) {
		n := good()
		n[2].NodeID = n[1].NodeID
		_, err := Nodes(n, RoleRoot, ModeWeighted)
		require.ErrorIs(t, err, ErrMembers)
	})
	t.Run("shared signing key", func(t *testing.T) {
		n := good()
		n[2].SigKey = n[1].SigKey
		_, err := Nodes(n, RoleRoot, ModeWeighted)
		require.ErrorIs(t, err, ErrMembers)
	})
	t.Run("invalid key stays refused", func(t *testing.T) {
		n := good()
		n[1].SigKey = []byte{1, 2, 3}
		err := Node(n[1], RoleRoot, ModeWeighted)
		require.ErrorIs(t, err, ErrMember)
		require.ErrorContains(t, err, "signing key is invalid")
		require.NotErrorIs(t, err, ErrWeight)
	})
	t.Run("nil member and empty set", func(t *testing.T) {
		err := Node(nil, RoleRoot, ModeWeighted)
		require.ErrorIs(t, err, ErrMember)
		require.ErrorContains(t, err, "node info is empty")
		_, err = Nodes([]*types.NodeInfo{nil}, RoleRoot, ModeWeighted)
		require.ErrorIs(t, err, ErrMember)
		require.ErrorContains(t, err, "node info is empty")
		_, err = Nodes(nil, RoleRoot, ModeWeighted)
		require.ErrorIs(t, err, ErrMembers)
	})
	t.Run("EVM set order and size stay go-base's", func(t *testing.T) {
		n := good()
		n[0], n[1] = n[1], n[0]
		require.ErrorIs(t, EVMSet(n, ModeWeighted), evmassign.ErrValidators)
		require.ErrorIs(t, EVMSet(members(t, make([]uint64, 0)...), ModeWeighted), evmassign.ErrValidators)
	})
}

func TestRootTrustBaseThreshold(t *testing.T) {
	n := members(t, 6, 1, 1, 1)
	require.NoError(t, RootTrustBase(trustBase(t, n, 7), ModeWeighted))
	for _, th := range []uint64{0, 6, 8, 9} {
		require.ErrorIs(t, RootTrustBase(trustBase(t, n, th), ModeWeighted), ErrThreshold, "threshold %d", th)
	}
	// legacy unit rule: anything from the minimum up to n
	u := members(t, 1, 1, 1, 1)
	for th, ok := range map[uint64]bool{2: false, 3: true, 4: true, 5: false} {
		err := RootTrustBase(trustBase(t, u, th), ModeUnit)
		if ok {
			require.NoError(t, err, "threshold %d", th)
		} else {
			require.ErrorIs(t, err, ErrThreshold, "threshold %d", th)
		}
	}
	err := RootTrustBase(trustBase(t, n, 7), ModeUnit)
	require.ErrorIs(t, err, ErrMember, "weights are not unit")
	require.ErrorContains(t, err, "node must have stake == 1")
	require.NotErrorIs(t, err, ErrWeight)
	require.ErrorIs(t, RootTrustBase(nil, ModeWeighted), ErrMembers)
	require.ErrorIs(t, RootTrustBase(trustBase(t, nil, 1), ModeWeighted), ErrMembers)
}

func TestRootTrustBaseOrder(t *testing.T) {
	n := members(t, 6, 1, 1, 1)
	require.NoError(t, RootTrustBase(trustBase(t, n, 7), ModeWeighted))
	unordered := append([]*types.NodeInfo(nil), n...)
	sort.Slice(unordered, func(i, j int) bool { return unordered[i].NodeID > unordered[j].NodeID })
	require.ErrorIs(t, RootTrustBase(trustBase(t, unordered, 7), ModeWeighted), ErrMembers)
}

func TestAggregatorsStayUnit(t *testing.T) {
	heavy := members(t, 2, 1, 1)
	unit := members(t, 1, 1, 1)
	for _, mode := range []Mode{ModeUnit, ModeWeighted} {
		require.NoError(t, PDR(pdr(unit), RoleAggregator, mode), "acceptance control, mode %d", mode)
		require.ErrorIs(t, PDR(pdr(heavy), RoleAggregator, mode), ErrNonUnitAggregator, "mode %d", mode)
		require.ErrorIs(t, Node(heavy[0], RoleAggregator, mode), ErrNonUnitAggregator, "mode %d", mode)
		_, err := Nodes(heavy, RoleAggregator, mode)
		require.ErrorIs(t, err, ErrNonUnitAggregator, "mode %d", mode)
	}
	require.NoError(t, PDR(pdr(heavy), RoleEVM, ModeWeighted), "the same set is a valid weighted EVM set")
	// a zero weight is not a weight either
	zero := members(t, 0, 1)
	require.ErrorIs(t, PDR(pdr(zero), RoleAggregator, ModeWeighted), ErrNonUnitAggregator)
}

func TestPDRKeepsGoBaseStructuralRules(t *testing.T) {
	n := members(t, 6, 1, 1, 1)
	p := pdr(n)
	require.NoError(t, PDR(p, RoleEVM, ModeWeighted))
	wantText := map[string]string{"network": "invalid network identifier", "t2 timeout": "t2 timeout value out of allowed range",
		"unit id len": "unit id length", "duplicate id": "duplicate validator"}
	for name, mutate := range map[string]func(*types.PartitionDescriptionRecord){
		"network":      func(p *types.PartitionDescriptionRecord) { p.NetworkID = 0 },
		"t2 timeout":   func(p *types.PartitionDescriptionRecord) { p.T2Timeout = time.Millisecond },
		"unit id len":  func(p *types.PartitionDescriptionRecord) { p.UnitIDLen = 7 },
		"duplicate id": func(p *types.PartitionDescriptionRecord) { p.Validators[1].NodeID = p.Validators[0].NodeID },
	} {
		t.Run(name, func(t *testing.T) {
			q := pdr(members(t, 6, 1, 1, 1))
			mutate(q)
			err := PDR(q, RoleEVM, ModeWeighted)
			require.ErrorIs(t, err, ErrPartition)
			require.ErrorContains(t, err, wantText[name])
			require.NotErrorIs(t, err, ErrWeight)
		})
	}
	require.ErrorIs(t, PDR(nil, RoleEVM, ModeWeighted), types.ErrSystemDescriptionIsNil)
	require.Equal(t, uint64(6), p.Validators[0].Stake, "validation leaves the input weights untouched")
}

func TestUnknownContextIsRefused(t *testing.T) {
	n := members(t, 1, 1)
	require.ErrorIs(t, Node(n[0], 0, ModeUnit), ErrContext)
	require.ErrorIs(t, Node(n[0], RoleRoot, 0), ErrContext)
	require.ErrorIs(t, Node(n[0], RoleAggregator+1, ModeWeighted), ErrContext)
	require.ErrorIs(t, Node(n[0], RoleRoot, ModeWeighted+1), ErrContext)
	_, err := Nodes(n, 0, 0)
	require.ErrorIs(t, err, ErrContext)
	require.ErrorIs(t, RootTrustBase(trustBase(t, n, 2), 0), ErrContext)
	require.ErrorIs(t, PDR(pdr(n), RoleRoot, ModeWeighted), ErrContext)
	require.ErrorIs(t, EVMSet(n, 0), ErrContext)
}

func TestUnitModeKeepsGoBaseErrors(t *testing.T) {
	bad := members(t, 1, 1)[0]
	bad.SigKey = []byte{1, 2, 3}
	require.Equal(t, bad.IsValid(), Node(bad, RoleRoot, ModeUnit), "legacy Node is NodeInfo.IsValid, unwrapped")
	require.NotErrorIs(t, Node(bad, RoleRoot, ModeUnit), ErrMember)
	q := pdr(members(t, 1, 1, 1))
	q.NetworkID = 0
	require.Equal(t, q.IsValid(), PDR(q, RoleEVM, ModeUnit), "legacy PDR is PartitionDescriptionRecord.IsValid, unwrapped")
	require.NotErrorIs(t, PDR(q, RoleEVM, ModeUnit), ErrPartition)
	require.ErrorIs(t, PDR(nil, RoleEVM, ModeUnit), types.ErrSystemDescriptionIsNil)
}
