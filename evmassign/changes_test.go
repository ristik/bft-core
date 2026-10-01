package evmassign

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

const testControlPartition types.PartitionID = 0x7fff

// aggregatorFixture is an existing aggregator shard (partition 9, one validator, proof_type aggregator_rsmt_v1) and a
// key replacement for it.
type aggregatorFixture struct {
	current *types.PartitionDescriptionRecord
	succ    *types.PartitionDescriptionRecord
	keys    []keyed
	ctx     PoPContext
}

func newAggregatorFixture(t *testing.T) aggregatorFixture {
	t.Helper()
	old := newKey(t, "agg-old")
	current := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 9, PartitionTypeID: 9, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 2500 * time.Millisecond, Epoch: 0, EpochStart: 1,
		PartitionParams: map[string]string{"proof_type": "aggregator_rsmt_v1"}, Validators: []*types.NodeInfo{old.info}}
	next := []keyed{newKey(t, "agg-new")}
	succ, err := NewSuccessor(current, []*types.NodeInfo{next[0].info})
	require.NoError(t, err)
	return aggregatorFixture{current: current, succ: succ, keys: next,
		ctx: PoPContext{Network: 5, Attempt: 1, Predecessor: [32]byte{1}, Parent: [32]byte{9}}}
}

func (a aggregatorFixture) change(t *testing.T) Change {
	t.Helper()
	var pops []PoP
	for _, k := range a.keys {
		p, err := SignPoP(k.signer, a.ctx, a.succ, k.id)
		require.NoError(t, err)
		pops = append(pops, p)
	}
	ch, err := EncodeReplaceShardValidators(a.current.PartitionID, a.current.ShardID, a.current, a.succ, pops)
	require.NoError(t, err)
	return ch
}

func TestValidateChangesAcceptsOneKeyReplacement(t *testing.T) {
	a := newAggregatorFixture(t)
	got, err := ValidateChanges([]Change{a.change(t)}, nil, a.ctx, testControlPartition)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.NoError(t, VerifyChangeInstalled(got[0], a.current))
	// No changes at all is the common case.
	none, err := ValidateChanges(nil, nil, a.ctx, testControlPartition)
	require.NoError(t, err)
	require.Empty(t, none)
}

func TestValidateChangesRefusals(t *testing.T) {
	a := newAggregatorFixture(t)
	good := a.change(t)
	t.Run("reserved and unknown kinds are unsupported", func(t *testing.T) {
		for _, kind := range []uint64{ChangeAddPartition, ChangeSplitShard, 0, 99} {
			_, err := ValidateChanges([]Change{{Kind: kind, Payload: good.Payload}}, nil, a.ctx, testControlPartition)
			require.ErrorIs(t, err, ErrUnsupportedChange, "kind %d", kind)
		}
	})
	t.Run("a source reference is reserved", func(t *testing.T) {
		_, err := ValidateChanges([]Change{good}, []byte{1}, a.ctx, testControlPartition)
		require.ErrorIs(t, err, ErrSourceRef)
	})
	t.Run("count is bounded", func(t *testing.T) {
		many := make([]Change, MaxChanges+1)
		for i := range many {
			many[i] = good
		}
		_, err := ValidateChanges(many, nil, a.ctx, testControlPartition)
		require.ErrorIs(t, err, ErrChange)
	})
	t.Run("two changes for one shard", func(t *testing.T) {
		_, err := ValidateChanges([]Change{good, good}, nil, a.ctx, testControlPartition)
		require.ErrorIs(t, err, ErrChange)
	})
	t.Run("the EVM shard and the control partition are not targets", func(t *testing.T) {
		evm := newAggregatorFixture(t)
		evm.current.PartitionTypeID = EVMPartitionTypeID
		evmSucc, err := NewSuccessor(evm.current, []*types.NodeInfo{evm.keys[0].info})
		require.NoError(t, err)
		evm.succ = evmSucc
		_, err = ValidateChanges([]Change{evm.change(t)}, nil, evm.ctx, testControlPartition)
		require.ErrorIs(t, err, ErrChange)
		control := newAggregatorFixture(t)
		control.current.PartitionID = testControlPartition
		cs, err := NewSuccessor(control.current, []*types.NodeInfo{control.keys[0].info})
		require.NoError(t, err)
		control.succ = cs
		_, err = ValidateChanges([]Change{control.change(t)}, nil, control.ctx, testControlPartition)
		require.ErrorIs(t, err, ErrChange)
	})
	t.Run("every successor key proves possession in this context", func(t *testing.T) {
		other := a.ctx
		other.Attempt++
		_, err := ValidateChanges([]Change{good}, nil, other, testControlPartition)
		require.ErrorIs(t, err, ErrPoP, "a proof for another attempt")
		missing := a
		ch, err := EncodeReplaceShardValidators(9, a.current.ShardID, a.current, missing.succ, nil)
		require.NoError(t, err)
		_, err = ValidateChanges([]Change{ch}, nil, a.ctx, testControlPartition)
		require.ErrorIs(t, err, ErrPoP, "a missing proof")
	})
	t.Run("payload shape", func(t *testing.T) {
		_, err := ValidateChanges([]Change{{Kind: ChangeReplaceShardValidators, Payload: append(bytes.Clone(good.Payload), 0)}}, nil, a.ctx, testControlPartition)
		require.ErrorIs(t, err, ErrChange, "trailing byte")
		_, err = ValidateChanges([]Change{{Kind: ChangeReplaceShardValidators, Payload: nil}}, nil, a.ctx, testControlPartition)
		require.ErrorIs(t, err, ErrChange, "empty")
		var r ReplaceShardValidators
		require.NoError(t, types.Cbor.Unmarshal(good.Payload, &r))
		r.Version = 2
		raw, err := types.Cbor.Marshal(r)
		require.NoError(t, err)
		_, err = ValidateChanges([]Change{{Kind: ChangeReplaceShardValidators, Payload: raw}}, nil, a.ctx, testControlPartition)
		require.ErrorIs(t, err, ErrChange, "unknown payload version")
		r.Version, r.Partition = 1, 10
		raw, err = types.Cbor.Marshal(r)
		require.NoError(t, err)
		_, err = ValidateChanges([]Change{{Kind: ChangeReplaceShardValidators, Payload: raw}}, nil, a.ctx, testControlPartition)
		require.ErrorIs(t, err, ErrChange, "the successor names another shard")
	})
}

// Validators only: the successor must be the installed configuration with only validators and epoch changed, so a proof_type
// (or any other parameter) change cannot ride in a handoff.
func TestVerifyChangeInstalledIsValidatorsOnly(t *testing.T) {
	a := newAggregatorFixture(t)
	decode := func(c Change) DecodedChange {
		got, err := ValidateChanges([]Change{c}, nil, a.ctx, testControlPartition)
		require.NoError(t, err)
		return got[0]
	}
	require.NoError(t, VerifyChangeInstalled(decode(a.change(t)), a.current))

	t.Run("a proof_type change is refused", func(t *testing.T) {
		b := a
		b.succ = clonePDR(t, a.succ)
		b.succ.PartitionParams["proof_type"] = "sp1"
		d := decode(b.change(t))
		require.ErrorIs(t, VerifyChangeInstalled(d, a.current), ErrConfig)
	})
	t.Run("the installed configuration must be the expected one", func(t *testing.T) {
		moved := clonePDR(t, a.current)
		moved.T2Timeout += time.Second
		require.ErrorIs(t, VerifyChangeInstalled(decode(a.change(t)), moved), ErrContext)
	})
	t.Run("the successor epoch is the installed one plus one", func(t *testing.T) {
		later := clonePDR(t, a.current)
		later.Epoch = 3
		d := decode(a.change(t))
		d.Replace.ExpectedOldPDRHash = mustHash(t, later)
		require.ErrorIs(t, VerifyChangeInstalled(d, later), ErrEpoch)
	})
	t.Run("a missing or EVM target is refused", func(t *testing.T) {
		require.ErrorIs(t, VerifyChangeInstalled(decode(a.change(t)), nil), ErrChange)
		evm := clonePDR(t, a.current)
		evm.PartitionTypeID = EVMPartitionTypeID
		require.ErrorIs(t, VerifyChangeInstalled(decode(a.change(t)), evm), ErrChange)
	})
}

func mustHash(t *testing.T, p *types.PartitionDescriptionRecord) []byte {
	t.Helper()
	h, err := PDRHash(p)
	require.NoError(t, err)
	return h[:]
}

// A root key is no entity's EVM key, whichever binding it belongs to: globally distinct across roles.
func TestCouplingKeysAreGloballyDistinctAcrossRoles(t *testing.T) {
	f := newFixture(t)
	root := rootOf("r", 2)
	bindings := bindingsFor(root, f.succ)
	require.NoError(t, ValidateCoupling(root, f.succ, bindings))
	// Root entity r1 uses the key of the EVM validator bound to r3: not its own pair, still refused.
	shared := append([]RootMember(nil), root...)
	shared[0].Key = bytes.Clone(f.succ.Validators[2].SigKey)
	require.ErrorIs(t, ValidateCoupling(shared, f.succ, bindings), ErrCoupling)
	require.ErrorContains(t, ValidateCoupling(shared, f.succ, bindings), "signing key of root entity")
}
