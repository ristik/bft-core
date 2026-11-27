package signingauthority

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
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
			require.False(t, after.EnrollmentComplete)
			require.False(t, after.SessionIssued)
			require.False(t, after.HasReservation)
			require.Equal(t, before.SigningKeyFingerprint, after.SigningKeyFingerprint)
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
