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
	chainID := new(big.Int).SetBytes(publication.Deployment.ChainID[:]).String()
	f := q3fixture.New(t, q3fixture.Options{Assignment: true, Params: map[string]string{"chain_id": chainID}})
	conf := f.ShardConf
	enroll := Enrollment{AuthorityID: "joiner", NodeID: "fresh-joiner", NetworkID: conf.NetworkID,
		PartitionID: conf.PartitionID, ShardID: conf.ShardID, ShardEpoch: f.Successor.Epoch,
		RootEpoch: PinRootEpoch(1), Profile: ProfileLegacyBCRv1}
	prove := func() {}
	a, err := New(enroll, currentTrust{base: f.Old}, WithLineage(f.Old, f.UTB),
		WithPendingJoinScope(), WithRequirePosPolicy(), WithLatePosPolicy(), WithAdvanceHook(func() { prove() }))
	require.NoError(t, err)
	key := mustPub(t, a)
	candidate, deployment := publication.Candidate, publication.Deployment
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
	pin := PosPolicy{Network: deployment.NetworkWord, ChainID: deployment.ChainID, Election: deployment.Election, IDs: []uint64{id}}
	require.NoError(t, a.SetPosPolicy(pin))
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
	}{
		{"both match", 7, 7}, {"wrong b1 profile", 8, 7}, {"wrong P85 pin", 7, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pin := posPin()
			pin.ChainID = vrschema.U64(tc.pin)
			a, err := New(enroll, currentTrust{base: f.Old}, WithLineage(f.Old, f.UTB),
				WithPendingJoinScope(), WithPendingJoinChainID(tc.profile), WithPosPolicy(pin))
			require.NoError(t, err)
			before := a.Status()
			result, err := a.AdvanceWithProof(t.Context(), bundleOf(t, f))
			if tc.profile == 7 && tc.pin == 7 {
				require.NoError(t, err)
				require.True(t, result.Advanced)
				require.NoError(t, a.SetPosPolicy(pin))
				other := pin
				other.ChainID = vrschema.U64(8)
				require.ErrorIs(t, a.SetPosPolicy(other), ErrPosPolicyConflict)
			} else {
				require.ErrorIs(t, err, ErrContextMismatch)
				require.Equal(t, before, a.Status())
			}
		})
	}
}
