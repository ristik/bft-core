package storage

import (
	"bytes"
	"crypto"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// aggregatorShard is an existing aggregator shard (partition 9) of the fixture's chain, certified under its own key.
type aggregatorShard struct {
	conf    *types.PartitionDescriptionRecord
	key     types.PartitionShardID
	oldKey  evmKey
	nextKey evmKey
}

// addAggregator installs an aggregator shard next to the EVM shard (real orchestration and committed state) and returns it.
func (f *assignmentFixture) addAggregator(t *testing.T) aggregatorShard {
	t.Helper()
	a := aggregatorShard{oldKey: newEVMKey(t, "agg-old"), nextKey: newEVMKey(t, "agg-new")}
	a.conf = &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 9, PartitionTypeID: 9, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 2500 * time.Millisecond, Epoch: 0, EpochStart: 1,
		PartitionParams: map[string]string{"proof_type": "aggregator_rsmt_v1"}, Validators: []*types.NodeInfo{a.oldKey.info}}
	require.NoError(t, f.orch.AddShardConfig(a.conf))
	evmShard := f.shard
	f.installShard(t, a.conf, func(*ShardInfo) {})
	a.key = f.shard
	f.shard = evmShard
	return a
}

// replace builds the candidate change replacing the shard's key set; every successor key signs the possession proof for the
// fixture's context. mutate edits the successor before it is signed.
func (f *assignmentFixture) replace(t *testing.T, a aggregatorShard, installed *types.PartitionDescriptionRecord, mutate func(*types.PartitionDescriptionRecord)) evmassign.Change {
	t.Helper()
	succ, err := evmassign.NewSuccessor(installed, []*types.NodeInfo{a.nextKey.info})
	require.NoError(t, err)
	if mutate != nil {
		mutate(succ)
	}
	p, err := evmassign.SignPoP(a.nextKey.signer, f.pop, succ, a.nextKey.id)
	require.NoError(t, err)
	ch, err := evmassign.EncodeReplaceShardValidators(installed.PartitionID, installed.ShardID, installed, succ, []evmassign.PoP{p})
	require.NoError(t, err)
	return ch
}

func TestFreezeAdmitsAnAggregatorKeyReplacementOnlyWhenItReplacesTheInstalledConfiguration(t *testing.T) {
	cases := []struct {
		name   string
		change func(t *testing.T, f *assignmentFixture, a aggregatorShard) []evmassign.Change
		want   error
	}{
		{"a key replacement of an existing shard", func(t *testing.T, f *assignmentFixture, a aggregatorShard) []evmassign.Change {
			return []evmassign.Change{f.replace(t, a, a.conf, nil)}
		}, nil},
		{"a proof_type change", func(t *testing.T, f *assignmentFixture, a aggregatorShard) []evmassign.Change {
			return []evmassign.Change{f.replace(t, a, a.conf, func(s *types.PartitionDescriptionRecord) { s.PartitionParams["proof_type"] = "sp1" })}
		}, evmassign.ErrConfig},
		{"a replacement of a configuration that is not the installed one", func(t *testing.T, f *assignmentFixture, a aggregatorShard) []evmassign.Change {
			stale := *a.conf
			stale.T2Timeout += time.Second
			return []evmassign.Change{f.replace(t, a, &stale, nil)}
		}, evmassign.ErrContext},
		{"a shard that does not exist", func(t *testing.T, f *assignmentFixture, a aggregatorShard) []evmassign.Change {
			ghost := *a.conf
			ghost.PartitionID = 77
			return []evmassign.Change{f.replace(t, a, &ghost, nil)}
		}, evmassign.ErrChange},
		{"a reserved kind", func(t *testing.T, f *assignmentFixture, a aggregatorShard) []evmassign.Change {
			ch := f.replace(t, a, a.conf, nil)
			ch.Kind = evmassign.ChangeSplitShard
			return []evmassign.Change{ch}
		}, evmassign.ErrUnsupportedChange},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAssignmentFixture(t)
			f.useRealOrchestration(t)
			f.seedFees(t)
			a := f.addAggregator(t)
			f.changes = tc.change(t, f, a)
			err := f.admit(t, f.build(t, f.candidate(t)))
			if tc.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrHandoffRecord)
			require.ErrorIs(t, err, tc.want)
		})
	}
	t.Run("an aggregator whose previous replacement is not acknowledged", func(t *testing.T) {
		f := newAssignmentFixture(t)
		f.useRealOrchestration(t)
		f.seedFees(t)
		a := f.addAggregator(t)
		f.installShard(t, a.conf, func(si *ShardInfo) { si.TR.Epoch = si.IR.Epoch + 1 })
		f.shard = types.PartitionShardID{PartitionID: 8, ShardID: f.current.ShardID.Key()}
		f.changes = []evmassign.Change{f.replace(t, a, a.conf, nil)}
		err := f.admit(t, f.build(t, f.candidate(t)))
		require.ErrorIs(t, err, ErrAssignmentAckPending)
	})
	t.Run("a supersession carries no aggregator changes", func(t *testing.T) {
		p := installPendingAssignment(t)
		a := p.f.addAggregator(t)
		binding, err := p.chain(t).Supersession()
		require.NoError(t, err)
		_ = p.supersedeWith(t, binding, 8) // builds the supersession fixture state (committee shift, new EVM set)
		p.f.changes = []evmassign.Change{p.f.replace(t, a, a.conf, nil)}
		built := p.f.build(t, p.f.candidate(t))
		p.store.handoffAuth = fixedParentAuthority{predecessor: p.body1, parent: p.f.parent, root: p.f.baseCommittee}
		s := supersession{p: p, built: built}
		_, err = s.addEpoch2(t, p.store, 8, built.prepare.Bytes())
		require.NoError(t, err)
		_, err = s.addEpoch2(t, p.store, 9, built.freeze.Bytes(), built.companion)
		require.ErrorIs(t, err, ErrHandoffRecord)
		require.ErrorIs(t, err, evmassign.ErrChange)
	})
}

// B3: the retired key's first post-boundary request is refused. The replacement activates with the assignment: the shard's
// technical record advances to the successor epoch and the new trust base is installed at once, so the old key cannot certify
// the first block after the boundary. Unchanged shards are untouched, and a restart rebuilds the configuration from history.
func TestAggregatorKeyReplacementActivatesAtTheBoundaryAndSurvivesRestart(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	a := f.addAggregator(t)
	f.changes = []evmassign.Change{f.replace(t, a, a.conf, nil)}
	h := f.commitAssignment(t)
	anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)

	confs, err := f.orch.ShardConfigs(7)
	require.NoError(t, err)
	require.EqualValues(t, 1, confs[a.key].Epoch)
	require.EqualValues(t, 7, confs[a.key].EpochStart)
	require.Equal(t, a.nextKey.id, confs[a.key].Validators[0].NodeID)
	before, err := f.orch.ShardConfigs(6)
	require.NoError(t, err)
	require.EqualValues(t, 0, before[a.key].Epoch, "the retired key stays authoritative before the boundary")

	restart := func() *BlockStore {
		s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
		require.NoError(t, err)
		return s
	}
	s := restart()
	first := f.addSuccessorBlock(t, s, 7, anchor)
	newHash, err := evmassign.PDRHash(confs[a.key])
	require.NoError(t, err)
	check := func(block *ExecutedBlock, when string) {
		t.Helper()
		si := block.ShardState.States[a.key]
		require.Equal(t, newHash[:], []byte(si.ShardConfHash), when)
		require.EqualValues(t, 1, si.TR.Epoch, when)
		require.EqualValues(t, 0, si.IR.Epoch, when+": the shard's input record is unchanged until it certifies at the new epoch")
		require.Contains(t, si.nodeIDs, a.nextKey.id, when)
		require.NotContains(t, si.nodeIDs, a.oldKey.id, when)
		require.ErrorIs(t, si.Verify(a.oldKey.id, func(abcrypto.Verifier) error { return nil }), ErrNodeNotInTrustBase, when+": the retired key is refused")
		require.NoError(t, si.Verify(a.nextKey.id, func(abcrypto.Verifier) error { return nil }), when)
	}
	check(first, "activation block")
	for round := uint64(8); round <= 10; round++ {
		check(f.addSuccessorBlock(t, s, round, nil), "later block")
	}
	check(mustBlock(t, restart(), 10), "after restart")

	t.Run("a lost derived index is repaired from committed data, both configurations", func(t *testing.T) {
		lost := freshOrchestration(t, f, a.conf)
		before, err := lost.ShardConfigs(7)
		require.NoError(t, err)
		require.EqualValues(t, 0, before[a.key].Epoch)
		_, err = New(crypto.SHA256, f.store.storage, lost, logger.New(t), ProfileHandoff)
		require.NoError(t, err)
		repaired, err := lost.ShardConfigs(7)
		require.NoError(t, err)
		require.EqualValues(t, 1, repaired[f.shard].Epoch)
		require.EqualValues(t, 1, repaired[a.key].Epoch)
		got, err := evmassign.PDRHash(repaired[a.key])
		require.NoError(t, err)
		require.Equal(t, newHash, got, "the repaired aggregator entry is the identical derived configuration")
	})

	t.Run("a restart verifies every shard's configuration hash, not only the EVM shard's (B2)", func(t *testing.T) {
		block := mustBlock(t, restart(), 10)
		require.NoError(t, initBlock(block, f.orch), "the committed configurations match")
		tampered := func(key types.PartitionShardID) *ExecutedBlock {
			clone := *block
			states := make(map[types.PartitionShardID]*ShardInfo, len(block.ShardState.States))
			for k, si := range block.ShardState.States {
				c := *si
				states[k] = &c
			}
			states[key].ShardConfHash = bytes.Repeat([]byte{0x99}, 32)
			clone.ShardState = ShardStates{States: states, Changed: block.ShardState.Changed, Control: block.ShardState.Control}
			return &clone
		}
		require.ErrorIs(t, initBlock(tampered(a.key), f.orch), ErrAssignmentHistory, "an aggregator whose stored hash differs from history stops the root")
		require.ErrorIs(t, initBlock(tampered(f.shard), f.orch), ErrAssignmentHistory)
		// Outside the handoff profile (no control state) nothing changes.
		legacy := tampered(a.key)
		legacy.ShardState.Control = nil
		require.NoError(t, initBlock(legacy, f.orch))
	})
	t.Run("a different installed aggregator configuration refuses the install", func(t *testing.T) {
		// History says the change replaced a.conf; an orchestration that holds another genesis entry for the shard must not
		// install it on top.
		moved := *a.conf
		moved.T2Timeout += time.Second
		other := freshOrchestration(t, f, &moved)
		_, err := New(crypto.SHA256, f.store.storage, other, logger.New(t), ProfileHandoff)
		require.ErrorIs(t, err, ErrAssignmentHistory)
	})
}

// signedRequest is an IR change request whose block certification requests are signed by the given keys.
func signedRequest(t *testing.T, key types.PartitionShardID, signers ...evmKey) *rctypes.IRChangeReq {
	t.Helper()
	reqs := make([]*certification.BlockCertificationRequest, 0, len(signers))
	for _, k := range signers {
		req := &certification.BlockCertificationRequest{PartitionID: key.PartitionID, ShardID: types.ShardID{}, NodeID: k.id,
			InputRecord: &types.InputRecord{Version: 1, RoundNumber: 1, Hash: bytes.Repeat([]byte{0x41}, 32), PreviousHash: bytes.Repeat([]byte{0x40}, 32),
				BlockHash: bytes.Repeat([]byte{0x42}, 32), SummaryValue: []byte{}}}
		require.NoError(t, req.Sign(k.signer))
		reqs = append(reqs, req)
	}
	return &rctypes.IRChangeReq{Partition: key.PartitionID, Shard: types.ShardID{}, CertReason: rctypes.Quorum, Requests: reqs}
}

// acceptingVerifier judges the request the way the real verifier does in the activation block: against the committed (anchor)
// state, which accepts it.
var acceptingVerifier = mockIRVerifier{verify: func(_ uint64, req *rctypes.IRChangeReq) (*types.InputRecord, error) {
	return req.Requests[0].InputRecord, nil
}}

func addBlockWithRequests(t *testing.T, s *BlockStore, round uint64, anchor *rctypes.EpochAnchor, reqs ...*rctypes.IRChangeReq) *ExecutedBlock {
	t.Helper()
	block := &rctypes.BlockData{Version: 2, Round: round, Epoch: 2, Payload: &rctypes.Payload{Version: 2, Requests: reqs}}
	if anchor != nil {
		block.Anchor = anchor
	} else {
		prior := mustBlock(t, s, round-1)
		block.Qc = &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round - 1, Epoch: 2, CurrentRootHash: prior.RootHash}}
	}
	_, err := s.Add(block, acceptingVerifier)
	require.NoError(t, err)
	return mustBlock(t, s, round)
}

// B1 (#329 review): requests are verified against the LAST COMMITTED shard state, which is still the pre-activation anchor in the
// activation block, so a request set signed by a RETIRED key passed that verifier. The executor therefore also requires every
// signer to verify under the ACTIVE configuration of the shard (the state it executes against); a retired key's request is skipped
// (not certified, no state change) identically on every root, in the activation block and the one after it, for an aggregator
// shard and for the EVM shard.
func TestRetiredKeyRequestIsNotCertifiedInTheActivationBlockOrTheNext(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	a := f.addAggregator(t)
	f.changes = []evmassign.Change{f.replace(t, a, a.conf, nil)}
	h := f.commitAssignment(t)
	anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)

	evm := f.shard
	retiredEVM := f.oldKeys[1:]            // three of the four retired EVM keys: a quorum of the old set
	for _, round := range []uint64{7, 8} { // the activation block, then the next
		var a0 *rctypes.EpochAnchor
		if round == 7 {
			a0 = anchor
		}
		activated := map[types.PartitionShardID]uint64{}
		if round == 8 {
			for _, key := range []types.PartitionShardID{a.key, evm} {
				activated[key] = mustBlock(t, s, 7).ShardState.States[key].TR.Round
			}
		}
		block := addBlockWithRequests(t, s, round, a0, signedRequest(t, a.key, a.oldKey), signedRequest(t, evm, retiredEVM...))
		for name, key := range map[string]types.PartitionShardID{"aggregator": a.key, "EVM": evm} {
			si := block.ShardState.States[key]
			if round == 8 { // the activation block re-certifies every shard; afterwards an ignored request changes nothing
				require.NotContains(t, block.ShardState.Changed, key, "%s round %d: a retired key's request is not certified", name, round)
				require.Equal(t, activated[key], si.TR.Round, "%s round %d: the technical record did not advance", name, round)
			}
			require.EqualValues(t, 1, si.TR.Epoch, "%s round %d", name, round)
			require.EqualValues(t, 0, si.IR.Epoch, "%s round %d: the input record is untouched", name, round)
			require.NotEqual(t, bytes.Repeat([]byte{0x42}, 32), []byte(si.IR.BlockHash), "%s round %d", name, round)
		}
	}
	t.Run("a request of the new members is still certified", func(t *testing.T) {
		block := addBlockWithRequests(t, s, 9, nil, signedRequest(t, a.key, a.nextKey), signedRequest(t, evm, f.nextKeys[1:]...))
		for name, key := range map[string]types.PartitionShardID{"aggregator": a.key, "EVM": evm} {
			require.Contains(t, block.ShardState.Changed, key, "%s: the active members' request is processed", name)
		}
	})
}

// B1' (#329 review): a rotation that keeps a node id and changes only its signing key must refuse the retired key. Membership by
// node id alone passed it; the signature must verify under the key of the ACTIVE configuration for that node, in the activation
// block and the next, for an aggregator shard and for the EVM shard.
func TestRotationKeepingTheNodeIDRefusesTheRetiredKey(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	a := f.addAggregator(t)
	// The aggregator keeps its node id "agg-old" and gets a new key; EVM validator ev-a keeps its id with a new key too.
	rotatedAgg := newEVMKey(t, a.oldKey.id)
	rotated := aggregatorShard{conf: a.conf, key: a.key, oldKey: a.oldKey, nextKey: rotatedAgg}
	rotatedEVM := newEVMKey(t, "ev-a")
	// the replacing root entity takes over old-a's place and delegates the rotated ev-a (same id, new key); the others are unchanged
	f.replacedRoot, f.replacementEVM = "old-a", "ev-a"
	f.nextKeys = []evmKey{rotatedEVM, f.oldKeys[1], f.oldKeys[2], f.oldKeys[3]}
	succ, err := evmassign.NewSuccessor(f.current, []*types.NodeInfo{f.nextKeys[0].info, f.nextKeys[1].info, f.nextKeys[2].info, f.nextKeys[3].info})
	require.NoError(t, err)
	f.succ = succ
	f.changes = []evmassign.Change{f.replace(t, rotated, a.conf, nil)}
	h := f.commitAssignment(t)
	anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	evm := f.shard

	for _, round := range []uint64{7, 8} {
		var a0 *rctypes.EpochAnchor
		if round == 7 {
			a0 = anchor
		}
		block := addBlockWithRequests(t, s, round, a0, signedRequest(t, a.key, a.oldKey), signedRequest(t, evm, f.oldKeys[0]))
		for name, key := range map[string]types.PartitionShardID{"aggregator": a.key, "EVM": evm} {
			si := block.ShardState.States[key]
			require.NotEqual(t, bytes.Repeat([]byte{0x42}, 32), []byte(si.IR.BlockHash), "%s round %d: the old key under the kept node id certified nothing", name, round)
			require.EqualValues(t, 0, si.IR.Epoch, "%s round %d", name, round)
		}
	}
	block := addBlockWithRequests(t, s, 9, nil, signedRequest(t, a.key, rotatedAgg), signedRequest(t, evm, rotatedEVM))
	for name, key := range map[string]types.PartitionShardID{"aggregator": a.key, "EVM": evm} {
		require.Contains(t, block.ShardState.Changed, key, "%s: the new key under the kept node id is accepted", name)
	}
}
