package signingauthority

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate/evmstatetest"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestPendingJoinScopeRefresh(t *testing.T) {
	f := coupledFixture(t)
	conf := f.ShardConf
	raw := bundleOf(t, f)
	for _, proveFirst := range []bool{false, true} {
		name := "a missed activation advances the pending target"
		if proveFirst {
			name = "a signed target cannot be moved by a concurrent refresh"
		}
		t.Run(name, func(t *testing.T) {
			enroll := Enrollment{AuthorityID: "joiner", NodeID: "fresh-joiner",
				NetworkID: conf.NetworkID, PartitionID: conf.PartitionID, ShardID: conf.ShardID,
				ShardEpoch: f.Successor.Epoch, RootEpoch: PinRootEpoch(1), Profile: ProfileLegacyBCRv1}

			var prove func()
			a, err := New(enroll, currentTrust{base: f.Old}, WithLineage(f.Old, f.UTB), WithPendingJoinScope(),
				WithAdvanceHook(func() {
					if prove != nil {
						prove()
						prove = nil
					}
				}))
			require.NoError(t, err)
			before := a.Status()
			key, err := a.SigningPublicKey()
			require.NoError(t, err)
			succ := *f.Successor
			succ.Validators = []*types.NodeInfo{{NodeID: enroll.NodeID, SigKey: key, Stake: 1}}
			req := HandoffPoPRequest{Domain: evmassign.PoPDomain, Successor: &succ, NodeID: enroll.NodeID,
				Context: evmassign.PoPContext{Network: uint64(enroll.NetworkID), Predecessor: [32]byte{1}}}

			succ.Epoch++
			_, err = a.SignHandoffPoP(req)
			require.ErrorIs(t, err, ErrContextMismatch, "pending possession may only name its exact target")
			_, err = a.AdvanceWithProof(t.Context(), []byte("not a proof"))
			require.ErrorIs(t, err, ErrLineageUnverified)
			require.Equal(t, before, a.Status())
			_, err = a.ReplaceSession()
			require.ErrorIs(t, err, ErrEnrollmentIncomplete)

			if proveFirst {
				succ.Epoch--
				prove = func() {
					_, err := a.SignHandoffPoP(req)
					require.NoError(t, err)
				}
				_, err = a.AdvanceWithProof(t.Context(), raw)
				require.ErrorContains(t, err, "already proved possession")
				require.Equal(t, before, a.Status())
				return
			}

			refresh, err := a.AdvanceWithProof(t.Context(), raw)
			require.NoError(t, err)
			require.True(t, refresh.Advanced)
			require.Equal(t, uint64(2), refresh.RootEpoch)
			require.Equal(t, succ.Epoch, refresh.ShardEpoch)
			after := a.Status()
			require.False(t, a.Enrollment().complete())
			require.False(t, after.SessionIssued)
			require.False(t, after.HasReservation)
			afterKey, err := a.SigningPublicKey()
			require.NoError(t, err)
			require.Equal(t, key, afterKey)
			replay, err := a.AdvanceWithProof(t.Context(), raw)
			require.NoError(t, err)
			require.True(t, replay.Replay)
			require.Equal(t, after, a.Status())

			succ.Epoch--
			_, err = a.SignHandoffPoP(req)
			require.ErrorIs(t, err, ErrContextMismatch, "the stale target no longer signs")
			require.ErrorIs(t, a.CompleteEnrollment(&succ), ErrContextMismatch)
			succ.Epoch++
			_, err = a.SignHandoffPoP(req)
			require.NoError(t, err)
			require.NoError(t, a.CompleteEnrollment(&succ))
			require.ErrorIs(t, a.CompleteEnrollment(&succ), ErrContextMismatch)
		})
	}
}

func TestPendingJoinAuthorityCannotSkipItsOwnActivation(t *testing.T) {
	f := coupledFixture(t)
	kept, _ := keptAndDropped(t, f)
	conf := f.ShardConf
	enroll := Enrollment{AuthorityID: "joiner", NodeID: conf.Validators[kept].NodeID,
		NetworkID: conf.NetworkID, PartitionID: conf.PartitionID, ShardID: conf.ShardID,
		ShardEpoch: f.Successor.Epoch, RootEpoch: PinRootEpoch(1), Profile: ProfileLegacyBCRv1}
	a, err := New(enroll, currentTrust{base: f.Old}, WithLineage(f.Old, f.UTB), WithPendingJoinScope())
	require.NoError(t, err)
	giveKey(t, a, f.GenesisEVM[kept].Signer)
	before := a.Status()
	_, err = a.AdvanceWithProof(t.Context(), bundleOf(t, f))
	require.ErrorContains(t, err, "complete enrollment for that configuration")
	require.Equal(t, before, a.Status())
}

func TestPendingJoinElectionPoPFreezesScope(t *testing.T) {
	publication := evmstatetest.Load(t, publicationFixture)
	chainID := new(big.Int).SetBytes(publication.Deployment.ChainID[:])
	f := q3fixture.New(t, q3fixture.Options{Assignment: true, Params: map[string]string{"chain_id": chainID.String()}})
	conf := f.ShardConf
	enroll := Enrollment{AuthorityID: "joiner", NodeID: "fresh-joiner", NetworkID: conf.NetworkID,
		PartitionID: conf.PartitionID, ShardID: conf.ShardID, ShardEpoch: f.Successor.Epoch,
		RootEpoch: PinRootEpoch(1), Profile: ProfileLegacyBCRv1}
	prove := func() {}
	candidate, deployment := publication.Candidate, publication.Deployment
	src := &fakePos{view: PosDeploymentView{Network: deployment.NetworkWord, ChainID: deployment.ChainID, Election: deployment.Election}}
	a, err := New(enroll, currentTrust{base: f.Old}, WithLineage(f.Old, f.UTB),
		WithPendingJoinScope(), WithRequirePosPolicy(), WithPosSource(src, chainID.Uint64()), WithAdvanceHook(func() { prove() }))
	require.NoError(t, err)
	key := mustPub(t, a)
	candidate.Network, candidate.Predecessor = uint64(conf.NetworkID), bytes32(1)
	candidate.Identities[0].EVMNodeID, candidate.Identities[0].EVMKey = enroll.NodeID, key
	succ := *f.Successor
	succ.Validators = []*types.NodeInfo{{NodeID: enroll.NodeID, SigKey: key, Stake: 1}}
	candidate.Assignment, err = types.Cbor.Marshal(&succ)
	require.NoError(t, err)
	req := ElectionPoPRequest{Candidate: candidate, Deployment: deployment, Attempt: 3}

	_, err = a.SignElectionPoP(req)
	require.ErrorIs(t, err, ErrPosPolicy)
	_, id, err := evmassign.ElectionPoPDigest(candidate, deployment, req.Attempt, key, enroll.NodeID)
	require.NoError(t, err)
	src.bound = map[uint64]bool{id: true}
	pin := PosPolicy{Network: deployment.NetworkWord, ChainID: deployment.ChainID, Election: deployment.Election, IDs: []uint64{id}}
	require.NoError(t, a.SetPosPolicy(t.Context(), pin))
	future := req
	succ.Epoch++
	future.Candidate.Assignment, err = types.Cbor.Marshal(&succ)
	require.NoError(t, err)
	_, err = a.SignElectionPoP(future)
	require.ErrorIs(t, err, ErrContextMismatch)
	before := a.Status()
	prove = func() {
		_, err := a.SignElectionPoP(req)
		require.NoError(t, err)
	}
	_, err = a.AdvanceWithProof(t.Context(), bundleOf(t, f))
	require.ErrorContains(t, err, "already proved possession")
	require.Equal(t, before, a.Status())
}

func TestPendingJoinChecksAuthenticatedExecutionChain(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{Assignment: true, Params: map[string]string{"chain_id": "7"}})
	conf := f.ShardConf
	enroll := Enrollment{AuthorityID: "joiner", NodeID: "fresh-joiner", NetworkID: conf.NetworkID,
		PartitionID: conf.PartitionID, ShardID: conf.ShardID, ShardEpoch: f.Successor.Epoch,
		RootEpoch: PinRootEpoch(1), Profile: ProfileLegacyBCRv1}
	for _, tc := range []struct {
		name         string
		profile, pin uint64
		wantErr      error
	}{
		{"matches profile and pin", 7, 7, nil},
		{"contradicts startup profile", 8, 7, ErrContextMismatch},
		{"contradicts profile and verified pin", 8, 8, ErrStateUntrusted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pin := posPin()
			pin.ChainID = vrschema.U64(tc.pin)
			src := newFakePos()
			src.view.ChainID = pin.ChainID
			a, err := New(enroll, currentTrust{base: f.Old}, WithLineage(f.Old, f.UTB),
				WithPendingJoinScope(), WithPendingJoinChainID(tc.profile), WithPosSource(src, tc.pin))
			require.NoError(t, err)
			t.Cleanup(a.Close)
			require.NoError(t, a.SetPosPolicy(t.Context(), pin))
			_, err = a.SignPosPoP(posRequest())
			require.NoError(t, err)
			before := a.Status()
			beforeEnrollment := a.Enrollment()
			result, err := a.AdvanceWithProof(t.Context(), bundleOf(t, f))
			if tc.wantErr == nil {
				require.NoError(t, err)
				require.True(t, result.Advanced)
				require.NoError(t, a.SetPosPolicy(t.Context(), pin))
				other := pin
				other.ChainID = vrschema.U64(8)
				require.ErrorIs(t, a.SetPosPolicy(t.Context(), other), ErrPosPolicyConflict)
			} else {
				require.ErrorIs(t, err, tc.wantErr)
				before.Faulted = tc.wantErr == ErrStateUntrusted
				require.Equal(t, before, a.Status())
				require.Equal(t, beforeEnrollment, a.Enrollment())
				_, err = a.SignPosPoP(posRequest())
				if before.Faulted {
					require.ErrorIs(t, err, ErrStateUntrusted)
				} else {
					require.NoError(t, err)
				}
			}
		})
	}
}

func TestPendingJoinRechecksPinBeforeLatchingProofFault(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{Assignment: true, Params: map[string]string{"chain_id": "8"}})
	conf := f.ShardConf
	enroll := Enrollment{AuthorityID: "joiner", NodeID: "fresh-joiner", NetworkID: conf.NetworkID,
		PartitionID: conf.PartitionID, ShardID: conf.ShardID, ShardEpoch: f.Successor.Epoch,
		RootEpoch: PinRootEpoch(1), Profile: ProfileLegacyBCRv1}
	var installPin func()
	a, err := New(enroll, currentTrust{base: f.Old}, WithLineage(f.Old, f.UTB), WithPendingJoinScope(),
		WithPosSource(newFakePos(), posChain), WithAdvanceHook(func() { installPin() }))
	require.NoError(t, err)
	t.Cleanup(a.Close)
	installPin = func() { require.NoError(t, a.SetPosPolicy(t.Context(), posPin())) }
	before := a.Status()
	bundle := bundleOf(t, f)
	_, err = a.AdvanceWithProof(t.Context(), bundle)
	require.ErrorIs(t, err, ErrConflict)
	require.Equal(t, before, a.Status())

	_, err = a.AdvanceWithProof(t.Context(), bundle)
	require.ErrorIs(t, err, ErrStateUntrusted)
	before.Faulted = true
	require.Equal(t, before, a.Status())
}

func TestPendingJoinEnrollmentLatchesVerifiedPinContradiction(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{Assignment: true, Params: map[string]string{"chain_id": "8"}})
	conf := *f.Successor
	enroll := Enrollment{AuthorityID: "joiner", NodeID: "fresh-joiner", NetworkID: conf.NetworkID,
		PartitionID: conf.PartitionID, ShardID: conf.ShardID, ShardEpoch: conf.Epoch,
		RootEpoch: PinRootEpoch(1), Profile: ProfileLegacyBCRv1}
	a, err := New(enroll, currentTrust{base: f.Old}, WithLineage(f.Old, f.UTB),
		WithPendingJoinScope(), WithPosSource(newFakePos(), posChain))
	require.NoError(t, err)
	t.Cleanup(a.Close)
	require.NoError(t, a.SetPosPolicy(t.Context(), posPin()))
	_, err = a.SignPosPoP(posRequest())
	require.NoError(t, err)
	before := a.Status()
	beforeEnrollment := a.Enrollment()
	conf.Validators = []*types.NodeInfo{{NodeID: enroll.NodeID, SigKey: mustPub(t, a), Stake: 1}}

	conf.Epoch++
	require.ErrorIs(t, a.CompleteEnrollment(&conf), ErrContextMismatch)
	conf.Epoch--
	conf.Validators[0].NodeID = "other"
	require.ErrorIs(t, a.CompleteEnrollment(&conf), ErrContextMismatch)
	conf.Validators[0].NodeID = enroll.NodeID
	require.Equal(t, before, a.Status(), "check scope and membership before latching a contradiction")

	require.ErrorIs(t, a.CompleteEnrollment(&conf), ErrStateUntrusted)
	before.Faulted = true
	require.Equal(t, before, a.Status())
	require.Equal(t, beforeEnrollment, a.Enrollment())
	_, err = a.SignPosPoP(posRequest())
	require.ErrorIs(t, err, ErrStateUntrusted)
}

func TestPendingJoinChecksDeferredB1ProfileBeforePinning(t *testing.T) {
	for _, tc := range []struct {
		name, chain string
		matches     bool
	}{
		{"matching configuration", "7", true}, {"mismatching configuration", "8", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := q3fixture.New(t, q3fixture.Options{Assignment: true, Params: map[string]string{"chain_id": tc.chain}})
			conf := f.ShardConf
			enroll := Enrollment{AuthorityID: "joiner", NodeID: "fresh-joiner", NetworkID: conf.NetworkID,
				PartitionID: conf.PartitionID, ShardID: conf.ShardID, ShardEpoch: f.Successor.Epoch,
				RootEpoch: PinRootEpoch(1), Profile: ProfileLegacyBCRv1}
			a, err := New(enroll, currentTrust{base: f.Old}, WithLineage(f.Old, f.UTB), WithPendingJoinScope())
			require.NoError(t, err)
			t.Cleanup(a.Close)
			require.NoError(t, a.ProvisionPosSource(newFakePos(), posChain))
			before := a.Status()
			result, err := a.AdvanceWithProof(t.Context(), bundleOf(t, f))
			if tc.matches {
				require.NoError(t, err)
				require.True(t, result.Advanced)
			} else {
				require.ErrorIs(t, err, ErrContextMismatch)
				require.ErrorContains(t, err, "differs from B1 profile")
				require.Equal(t, before, a.Status())
			}

			own := *f.Successor
			own.Epoch = a.Enrollment().ShardEpoch
			own.Validators = []*types.NodeInfo{{NodeID: enroll.NodeID, SigKey: mustPub(t, a), Stake: 1}}
			before = a.Status()
			beforeEnrollment := a.Enrollment()
			err = a.CompleteEnrollment(&own)
			if tc.matches {
				require.NoError(t, err)
				require.True(t, a.Enrollment().complete())
			} else {
				require.ErrorIs(t, err, ErrContextMismatch)
				require.ErrorContains(t, err, "differs from B1 profile")
				require.Equal(t, before, a.Status())
				require.Equal(t, beforeEnrollment, a.Enrollment())
			}
		})
	}
}
