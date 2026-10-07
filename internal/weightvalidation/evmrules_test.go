package weightvalidation

import (
	"bytes"
	"crypto/sha256"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/testutils/identityfix"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// coupledWorld is a successor EVM assignment of weights `weights`, its coupled root committee of the same weights, the
// possession proofs and the installed assignment it replaces.
type coupledWorld struct {
	current  *types.PartitionDescriptionRecord
	succ     *types.PartitionDescriptionRecord
	root     []evmassign.RootMember
	bindings []evmassign.Binding
	pops     []evmassign.PoP
	pop      evmassign.PoPContext
	ids      []evmassign.Identity
	auth     *evmassign.Authorization
}

func (w *coupledWorld) lifecycle() evmassign.Lifecycle { return identityfix.Primary(w.ids, w.auth) }

func newCoupledWorld(t *testing.T, weights ...uint64) *coupledWorld {
	t.Helper()
	key := func() (abcrypto.Signer, []byte) {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		pub, err := v.MarshalPublicKey()
		require.NoError(t, err)
		return s, pub
	}
	var infos []*types.NodeInfo
	signers := map[string]abcrypto.Signer{}
	for i := 0; i < 4; i++ {
		s, pub := key()
		id := string(rune('a' + i))
		infos = append(infos, &types.NodeInfo{NodeID: id, SigKey: pub, Stake: 1})
		signers[id] = s
	}
	current := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 5 * time.Second, Epoch: 0, EpochStart: 1, PartitionParams: map[string]string{"seal_registry_genesis": "g"}, Validators: infos}
	w := &coupledWorld{current: current, pop: evmassign.PoPContext{Network: 5, Predecessor: sha256.Sum256([]byte("p")), Attempt: 1}}
	var next []*types.NodeInfo
	for i, weight := range weights {
		s, pub := key()
		id := string(rune('w' + i))
		next = append(next, &types.NodeInfo{NodeID: id, SigKey: pub, Stake: weight})
		signers[id] = s
		w.root = append(w.root, evmassign.RootMember{NodeID: "r" + id, Key: bytes.Repeat([]byte{byte(40 + i)}, 33), Weight: weight})
		w.bindings = append(w.bindings, evmassign.Binding{RootNodeID: "r" + id, EVMNodeID: id})
	}
	sort.Slice(w.bindings, func(i, j int) bool { return w.bindings[i].RootNodeID < w.bindings[j].RootNodeID })
	succ, err := evmassign.NewSuccessor(current, next)
	require.NoError(t, err)
	w.succ = succ
	w.ids = identityfix.Identities(w.root, succ, w.bindings)
	digest, err := evmassign.IdentitiesDigest(w.ids)
	require.NoError(t, err)
	w.pop.Identities = digest
	var oldRoot []evmassign.RootMember
	var oldBindings []evmassign.Binding
	for i, v := range current.Validators {
		oldRoot = append(oldRoot, evmassign.RootMember{NodeID: "o" + v.NodeID, Key: bytes.Repeat([]byte{byte(80 + i)}, 33), Weight: 1})
		oldBindings = append(oldBindings, evmassign.Binding{RootNodeID: "o" + v.NodeID, EVMNodeID: v.NodeID})
	}
	incumbent := identityfix.Identities(oldRoot, current, oldBindings)
	incDigest, err := evmassign.IdentitiesDigest(incumbent)
	require.NoError(t, err)
	baseHash, err := evmassign.AssignmentHash(current, incDigest)
	require.NoError(t, err)
	w.auth = identityfix.Authorization(5, w.pop.Predecessor[:], baseHash, incumbent)
	for _, v := range succ.Validators {
		pop, err := evmassign.SignPoP(signers[v.NodeID], w.pop, succ, v.NodeID)
		require.NoError(t, err)
		w.pops = append(w.pops, pop)
	}
	return w
}

func (w *coupledWorld) candidate(r evmassign.Rules) (evmassign.Candidate, error) {
	return evmassign.NewCandidateWith(r, w.pop, w.root, w.current, w.succ, w.pops, nil, w.bindings, w.lifecycle(), nil)
}

// A coupled successor with mirrored weights is a candidate only under the weighted rules; the unit rules (the default of every
// existing caller, and the aggregator's always) refuse every weight. Each refusal differs from the control in one thing.
func TestWeightedRulesAdmitAMirroredAssignmentAndUnitRulesDoNot(t *testing.T) {
	w := newCoupledWorld(t, 6, 1, 1, 1)
	c, err := w.candidate(EVMRules(ModeWeighted))
	require.NoError(t, err, "acceptance control")

	_, err = w.candidate(evmassign.UnitRules)
	require.ErrorIs(t, err, evmassign.ErrAssignment, "the unit rules refuse a weight of 6")
	_, err = evmassign.NewCandidate(w.pop, w.root, w.current, w.succ, w.pops, nil, w.bindings, w.lifecycle(), nil)
	require.ErrorIs(t, err, evmassign.ErrAssignment, "the unit entry point is unchanged")

	raw, err := c.Encode()
	require.NoError(t, err)
	digest := sha256.Sum256(raw)
	ctx := evmassign.BindingContext{PoPContext: w.pop, SuccessorRoot: w.root, Digest: digest[:], ControlPartition: evmroot.D4ControlPartition}
	_, _, err = evmassign.VerifyBinding(raw, ctx)
	require.ErrorIs(t, err, evmassign.ErrAssignment, "the binding context defaults to the unit rules")
	ctx.Rules = EVMRules(ModeWeighted)
	_, succ, err := evmassign.VerifyBinding(raw, ctx)
	require.NoError(t, err)
	require.NoError(t, evmassign.VerifyInstalledWith(EVMRules(ModeWeighted), c, succ, w.current, nil))
	require.ErrorIs(t, evmassign.VerifyInstalled(c, succ, w.current, nil), evmassign.ErrAssignment)
	require.ErrorIs(t, evmassign.ValidateAssignmentWith(evmassign.UnitRules, succ), evmassign.ErrAssignment)
	require.NoError(t, evmassign.ValidateAssignmentWith(EVMRules(ModeWeighted), succ))
	require.NoError(t, evmassign.ValidateSuccessorWith(EVMRules(ModeWeighted), w.current, succ))

	t.Run("a unit successor is a weighted candidate too", func(t *testing.T) {
		_, err := newCoupledWorld(t, 1, 1, 1, 1).candidate(EVMRules(ModeWeighted))
		require.NoError(t, err)
	})
	for name, tc := range map[string]struct {
		weights []uint64
		want    error
	}{
		"a zero weight":          {[]uint64{6, 1, 1, 0}, ErrWeight},
		"a weight above the cap": {[]uint64{evmroot.MaxMemberWeight + 1, 1, 1, 1}, ErrWeight},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newCoupledWorld(t, tc.weights...).candidate(EVMRules(ModeWeighted))
			require.ErrorIs(t, err, tc.want)
		})
	}
	t.Run("the coupling still binds every weight to its root member", func(t *testing.T) {
		bent := newCoupledWorld(t, 6, 1, 1, 1)
		bent.root[0].Weight = 5
		_, err := bent.candidate(EVMRules(ModeWeighted))
		require.ErrorIs(t, err, evmassign.ErrCoupling, "weights are admitted, a mismatch with the root committee is not")
	})
	t.Run("a unit EVM mode is the unit rules", func(t *testing.T) {
		_, err := w.candidate(EVMRules(ModeUnit))
		require.ErrorIs(t, err, evmassign.ErrAssignment)
	})
}
