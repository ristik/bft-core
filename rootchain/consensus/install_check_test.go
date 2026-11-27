package consensus

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3active"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
)

var _ q3active.RootChecker = (*ConsensusManager)(nil)

// An install that fetches its activation from a root peer authenticates each answer before it chooses one (#1080 review): the Q3 path
// through the runtime's history and the manager's install checks, without staging or installing anything, so an invalid first answer is
// passed over and the valid one is then installed exactly as before.
func TestQ3AuthenticateRefusesAnInvalidAnswerAndInstallsNothing(t *testing.T) {
	ctx := context.Background()
	f := q3fixture.New(t, q3fixture.Options{})
	r := newQ3Replica(t, f, f.NewNodes[0])
	r.mustOpen(true)
	t.Cleanup(r.close)
	require.NoError(t, r.rt.Recover(ctx))

	good := r.bundle()
	tampered := *f.Snapshot // the envelope authenticates; the snapshot is not the committed checkpoint
	tampered.ShardInfo = append([]abdrc.ShardInfo(nil), f.Snapshot.ShardInfo...)
	tampered.ShardInfo[0].IRTR.Round++
	badSnapshot := good
	badSnapshot.Snapshot = &tampered
	stranger := q3fixture.New(t, q3fixture.Options{}) // another old committee's activation: the history refuses it
	badEnvelope := q3active.Bundle{Envelope: stranger.EnvelopeBytes, Snapshot: stranger.Snapshot, Candidate: stranger.Candidate}

	require.ErrorIs(t, r.rt.Authenticate(badSnapshot), handoffdelivery.ErrBundle, "the manager's snapshot check, run before anything is staged")
	require.ErrorIs(t, r.rt.Authenticate(badEnvelope), q3active.ErrBundle)
	require.NoError(t, r.rt.Authenticate(good))

	_, activated := r.rt.Activated(2)
	require.False(t, activated, "authenticating extends no history")
	staged, ok, err := r.rt.StagedBundleAt(ctx, 2)
	require.NoError(t, err)
	require.False(t, ok, "and stages nothing: %v", staged)
	_, err = r.trust.GetByEpoch(2)
	require.ErrorIs(t, err, tbstore.ErrNotFound, "and installs no trust base")
	require.Nil(t, r.manager.epochAnchor)

	require.NoError(t, r.rt.Activate(ctx, good), "the chosen answer installs as before")
	_, activated = r.rt.Activated(2)
	require.True(t, activated)
}

// The manager's read-only check refuses what the install refuses and leaves the stores as they were.
func TestCheckVerifiedEpochRefusesWhatTheInstallRefusesAndWritesNothing(t *testing.T) {
	w := newGuardWorld(t)
	r := w.replica(t)
	tampered := *w.f.Snapshot
	tampered.ShardInfo = append([]abdrc.ShardInfo(nil), w.f.Snapshot.ShardInfo...)
	tampered.ShardInfo[0].IRTR.Round++
	require.ErrorIs(t, r.manager.CheckVerifiedEpoch(w.activated, w.other.Proof, w.f.Snapshot, nil), ErrNotVerifiedEpoch)
	require.ErrorIs(t, r.manager.CheckVerifiedEpoch(w.activated, w.f.Proof, &tampered, nil), handoffdelivery.ErrBundle)
	require.ErrorIs(t, r.manager.CheckVerifiedEpoch(w.activated, w.f.Proof, nil, nil), ErrNoCheckpoint)
	require.ErrorIs(t, r.manager.CheckVerifiedEpoch(w.activated, w.f.Proof, w.f.Snapshot, []byte{1}), ErrQ3Candidate)
	r.manager.pacemaker.Reset(context.Background(), 3, nil, nil)
	require.NoError(t, r.manager.CheckVerifiedEpoch(w.activated, w.f.Proof, w.f.Snapshot, nil), "a check needs no stopped manager")
	_, err := r.trust.GetByEpoch(2)
	require.ErrorIs(t, err, tbstore.ErrNotFound)
	require.Nil(t, r.manager.epochAnchor)
}

// The profile-2 path: CheckEpochBundle refuses a bundle whose snapshot is not the committed checkpoint and installs nothing; the valid
// bundle then installs.
func TestCheckEpochBundleRefusesAnInvalidAnswerAndInstallsNothing(t *testing.T) {
	replicas, _, _ := newAnchorReplicas(t, 4)
	var source *anchorReplica
	for id, replica := range replicas {
		if replica.oldSigners[id.String()] != nil {
			source = replica
			break
		}
	}
	require.NotNil(t, source)
	good := laterSuffixBundle(t, source)
	cm := stoppedHandoffReplica(t, source)

	tampered := *good.Snapshot
	tampered.ShardInfo = append([]abdrc.ShardInfo(nil), good.Snapshot.ShardInfo...)
	tampered.ShardInfo[0].IRTR.Round++
	bad := good
	bad.Snapshot = &tampered
	require.Error(t, cm.CheckEpochBundle(bad))
	otherProof := good
	otherProof.Proof.CommitQC = nil
	require.Error(t, cm.CheckEpochBundle(otherProof))
	require.NoError(t, cm.CheckEpochBundle(good))
	_, err := cm.trustBaseStore.GetByEpoch(2)
	require.Error(t, err, "checking installs no trust base")
	require.Nil(t, cm.epochAnchor)

	_, err = cm.InstallEpochBundle(good)
	require.NoError(t, err)
	require.NotNil(t, cm.epochAnchor)
}
