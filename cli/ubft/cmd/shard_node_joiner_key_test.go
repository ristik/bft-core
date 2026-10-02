package cmd

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/signingauthority"
)

type joinerFixture struct {
	self   string
	key    abcrypto.Verifier
	bundle handoffdelivery.Bundle
	step   handoff.AssignmentStep
	conf   *types.PartitionDescriptionRecord
}

// newJoinerFixture is a verified-shaped assignment bundle whose activated configuration names `self` with `key` (or does not, when
// named is false), and the step that carries its hash.
func newJoinerFixture(t *testing.T, named bool) joinerFixture {
	t.Helper()
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	key, err := signer.Verifier()
	require.NoError(t, err)
	pub, err := key.MarshalPublicKey()
	require.NoError(t, err)
	other, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	ov, err := other.Verifier()
	require.NoError(t, err)
	opub, err := ov.MarshalPublicKey()
	require.NoError(t, err)
	self := peerIDOf(t).String()
	validators := []*types.NodeInfo{{NodeID: peerIDOf(t).String(), SigKey: opub, Stake: 1}}
	if named {
		validators = append(validators, &types.NodeInfo{NodeID: self, SigKey: pub, Stake: 1})
	}
	succ := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 2500 * time.Millisecond, Epoch: 1, Validators: validators}
	raw, err := types.Cbor.Marshal(succ)
	require.NoError(t, err)
	candidate, err := evmassign.Candidate{Version: evmassign.CandidateVersion, Assignment: raw}.Encode()
	require.NoError(t, err)
	bundle := handoffdelivery.Bundle{Candidate: candidate}
	bundle.Proof.Record.ActivationRound = 7
	_, activated, err := evmassign.ActivatedFromPreimage(candidate, 7)
	require.NoError(t, err)
	hash, err := activated.Hash(crypto.SHA256)
	require.NoError(t, err)
	step := handoff.AssignmentStep{Assignment: true, OldShardEpoch: 0, NewShardEpoch: 1, NewActiveConfHash: [32]byte(hash)}
	return joinerFixture{self: self, key: key, bundle: bundle, step: step, conf: activated}
}

// stubAuthorityClient is a client that is never called: binding a key needs no authority.
type stubAuthorityClient struct{}

func (stubAuthorityClient) Reserve(context.Context, signingauthority.Request) (*signingauthority.Authorization, error) {
	return nil, errors.New("not called")
}
func (stubAuthorityClient) Sign(context.Context) error           { return errors.New("not called") }
func (stubAuthorityClient) RetainResponse(context.Context) error { return errors.New("not called") }
func (stubAuthorityClient) Release(context.Context, uint64, [32]byte) ([]byte, error) {
	return nil, errors.New("not called")
}

func deferredSigning(t *testing.T, self string) *certificationSigning {
	t.Helper()
	d, err := shardnode.NewDeferredAuthoritySigner(stubAuthorityClient{})
	require.NoError(t, err)
	return &certificationSigning{authority: d, deferred: d, nodeID: self, close: func() {}}
}

func installedHash(f joinerFixture) func(uint64) ([]byte, bool) {
	return func(epoch uint64) ([]byte, bool) {
		if epoch == f.step.NewShardEpoch {
			return bytes.Clone(f.step.NewActiveConfHash[:]), true
		}
		return nil, false
	}
}

// boundTo reports which key the deferred signer holds by trying to bind the other one: a conflict means it was bound to the first.
func boundTo(t *testing.T, s *certificationSigning, other abcrypto.Verifier) bool {
	t.Helper()
	err := s.deferred.BindKey(other)
	return err != nil
}

func TestAJoinersKeyIsBoundFromTheVerifiedActivatedConfiguration(t *testing.T) {
	f := newJoinerFixture(t, true)
	stranger, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	strangerKey, err := stranger.Verifier()
	require.NoError(t, err)

	t.Run("the configuration names this node: its key is bound", func(t *testing.T) {
		s := deferredSigning(t, f.self)
		require.NoError(t, noteJoinerStep(s, f.bundle, f.step, installedHash(f)))
		require.False(t, s.deferred.Bound(), "recorded, not bound: binding waits for the replay to complete")
		require.NoError(t, finishJoinerKey(s))
		require.True(t, boundTo(t, s, strangerKey), "bound: another key conflicts")
		require.NoError(t, s.deferred.BindKey(f.key), "and it is the key the configuration names")
	})
	t.Run("replaying the step (restore, then catch-up) is harmless", func(t *testing.T) {
		s := deferredSigning(t, f.self)
		require.NoError(t, noteJoinerStep(s, f.bundle, f.step, installedHash(f)))
		require.NoError(t, noteJoinerStep(s, f.bundle, f.step, installedHash(f)))
		require.NoError(t, finishJoinerKey(s))
		require.NoError(t, finishJoinerKey(s), "binding the same key twice is harmless")
	})
	t.Run("a hash that is not the one the verified step names is refused and binds nothing", func(t *testing.T) {
		s := deferredSigning(t, f.self)
		bad := f.step
		bad.NewActiveConfHash[0] ^= 1
		require.ErrorIs(t, noteJoinerStep(s, f.bundle, bad, installedHash(f)), ErrJoinerConf)
		require.NoError(t, finishJoinerKey(&certificationSigning{}), "(not deferred)")
		require.ErrorIs(t, finishJoinerKey(s), ErrJoinerUnnamed, "nothing was recorded")
	})
	t.Run("a hash that is not the one INSTALLED for the epoch is refused and binds nothing", func(t *testing.T) {
		s := deferredSigning(t, f.self)
		wrong := func(uint64) ([]byte, bool) { return bytes.Repeat([]byte{9}, 32), true }
		require.ErrorIs(t, noteJoinerStep(s, f.bundle, f.step, wrong), ErrJoinerConf)
		missing := func(uint64) ([]byte, bool) { return nil, false }
		require.ErrorIs(t, noteJoinerStep(s, f.bundle, f.step, missing), ErrJoinerConf, "no installed configuration for the epoch")
		require.ErrorIs(t, finishJoinerKey(s), ErrJoinerUnnamed)
	})
	t.Run("an epoch other than the step's is refused", func(t *testing.T) {
		s := deferredSigning(t, f.self)
		bad := f.step
		bad.NewShardEpoch = 2
		require.ErrorIs(t, noteJoinerStep(s, f.bundle, bad, installedHash(f)), ErrJoinerConf)
	})
	t.Run("a configuration that does not name this node binds nothing", func(t *testing.T) {
		g := newJoinerFixture(t, false)
		s := deferredSigning(t, g.self)
		require.NoError(t, noteJoinerStep(s, g.bundle, g.step, installedHash(g)))
		require.ErrorIs(t, finishJoinerKey(s), ErrJoinerUnnamed)
	})
	t.Run("a root-only bundle, and a signer that is not deferred, are left alone", func(t *testing.T) {
		s := deferredSigning(t, f.self)
		require.NoError(t, noteJoinerStep(s, handoffdelivery.Bundle{}, f.step, installedHash(f)))
		require.ErrorIs(t, finishJoinerKey(s), ErrJoinerUnnamed)
		require.NoError(t, noteJoinerStep(&certificationSigning{nodeID: f.self}, f.bundle, f.step, installedHash(f)), "a node the genesis configuration names has no deferred signer")
		require.NoError(t, noteJoinerStep(nil, f.bundle, f.step, installedHash(f)))
	})
}

// The OnInstalled path binds the joiner's key from the verified bundle; without that call a restored joiner would never sign.
func TestShardNodeRunBindsTheJoinersKeyFromTheInstalledAssignment(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "shard_node_run.go", nil, 0)
	require.NoError(t, err)
	var called bool
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "noteJoinerStep" {
				called = true
			}
		}
		return true
	})
	require.True(t, called)
}

// A plain restart of a joiner replays the persisted verified steps (the same install path) and then binds; a node no installed step
// names is refused, and a node the genesis configuration names is untouched.
func TestAPlainRestartOfAJoinerNeedsAnInstalledStepThatNamesIt(t *testing.T) {
	f := newJoinerFixture(t, true)
	s := deferredSigning(t, f.self)
	require.ErrorIs(t, finishJoinerKey(s), ErrJoinerUnnamed, "before any step is replayed")
	require.NoError(t, noteJoinerStep(s, f.bundle, f.step, installedHash(f)), "the replay of the persisted step")
	require.NoError(t, finishJoinerKey(s))
	require.True(t, s.deferred.Bound())

	notNamed := newJoinerFixture(t, false)
	other := deferredSigning(t, notNamed.self)
	require.NoError(t, noteJoinerStep(other, notNamed.bundle, notNamed.step, installedHash(notNamed)))
	require.ErrorIs(t, finishJoinerKey(other), ErrJoinerUnnamed, "every replayed step lacks this node")

	require.NoError(t, finishJoinerKey(nil))
	require.NoError(t, finishJoinerKey(&certificationSigning{}), "a node the genesis configuration names")
}

// Two installed steps name the node with different keys (a later rotation): the LATEST is bound, after the replay, and a later attempt to
// bind the earlier one fails. Binding as each step replayed would have bound the oldest key first.
func TestTheLatestInstalledStepThatNamesTheNodeIsBoundAndBindsOnce(t *testing.T) {
	first := newJoinerFixture(t, true)
	second := newJoinerFixture(t, true)
	// the same node, a later epoch, another key
	later := second
	later.self = first.self
	signing := deferredSigning(t, first.self)

	// re-name the second fixture's configuration for the first one's node at epoch 3
	validators := []*types.NodeInfo{{NodeID: first.self, SigKey: pubOf(t, second.key), Stake: 1}}
	succ := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 2500 * time.Millisecond, Epoch: 3, Validators: validators}
	raw, err := types.Cbor.Marshal(succ)
	require.NoError(t, err)
	candidate, err := evmassign.Candidate{Version: evmassign.CandidateVersion, Assignment: raw}.Encode()
	require.NoError(t, err)
	bundle := handoffdelivery.Bundle{Candidate: candidate}
	bundle.Proof.Record.ActivationRound = 9
	_, activated, err := evmassign.ActivatedFromPreimage(candidate, 9)
	require.NoError(t, err)
	hash, err := activated.Hash(crypto.SHA256)
	require.NoError(t, err)
	step := handoff.AssignmentStep{Assignment: true, OldShardEpoch: 1, NewShardEpoch: 3, NewActiveConfHash: [32]byte(hash)}
	installed := func(epoch uint64) ([]byte, bool) {
		switch epoch {
		case first.step.NewShardEpoch:
			return bytes.Clone(first.step.NewActiveConfHash[:]), true
		case 3:
			return bytes.Clone(hash), true
		}
		return nil, false
	}

	require.NoError(t, noteJoinerStep(signing, first.bundle, first.step, installed), "epoch 1 names the node with key A")
	require.False(t, signing.deferred.Bound(), "nothing binds while the replay is going on")
	require.NoError(t, noteJoinerStep(signing, bundle, step, installed), "epoch 3 names it with key B")
	require.NoError(t, finishJoinerKey(signing))
	require.ErrorIs(t, signing.deferred.BindKey(first.key), shardnode.ErrAuthorityKeyConflict, "key A (epoch 1) is not what is bound")
	require.NoError(t, signing.deferred.BindKey(second.key), "key B (the latest step's) is")
	require.ErrorIs(t, signing.deferred.BindKey(first.key), shardnode.ErrAuthorityKeyConflict, "and a later re-bind attempt still fails")
}

func pubOf(t *testing.T, v abcrypto.Verifier) []byte {
	t.Helper()
	pub, err := v.MarshalPublicKey()
	require.NoError(t, err)
	return pub
}

// An installed configuration that names this node with its LOCAL key-configuration key is refused eagerly, with a clear error.
func TestAJoinersInstalledConfigurationNamingTheLocalKeyIsRefused(t *testing.T) {
	f := newJoinerFixture(t, true)
	s := deferredSigning(t, f.self)
	s.localKey = pubOf(t, f.key)
	require.ErrorIs(t, noteJoinerStep(s, f.bundle, f.step, installedHash(f)), ErrJoinerLocalKey)
	require.ErrorIs(t, finishJoinerKey(s), ErrJoinerUnnamed, "nothing was recorded")
}

// The key is bound at BOTH points where the replay completes: after the persisted steps of a plain start, and after the catch-up of a restore.
func TestShardNodeRunBindsTheJoinersKeyAfterTheReplayOnAPlainStartAndOnARestore(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "shard_node_run.go", nil, 0)
	require.NoError(t, err)
	calls := 0
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "finishJoinerKey" {
				calls++
			}
		}
		return true
	})
	require.Equal(t, 2, calls)
}

// A plain start with verified handoff history defers the key as a restore does: shardNodeRun passes Restore OR TrustHistoryProfile2.
func TestShardNodeRunDefersTheJoinersKeyOnAPlainStartWithHandoffHistory(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "shard_node_run.go", nil, 0)
	require.NoError(t, err)
	var seen []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "buildCertificationSigning" {
			require.Len(t, call.Args, 4)
			bin, ok := call.Args[3].(*ast.BinaryExpr)
			require.True(t, ok, "the derive flag is Restore || TrustHistoryProfile2")
			for _, e := range []ast.Expr{bin.X, bin.Y} {
				seen = append(seen, e.(*ast.SelectorExpr).Sel.Name)
			}
		}
		return true
	})
	require.ElementsMatch(t, []string{"Restore", "TrustHistoryProfile2"}, seen)
}
