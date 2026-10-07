package cmd

import (
	"context"
	"crypto"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3format"
)

func TestTheShardSinkDelegatesInstallRestoreAndHoldsToTheNodesOwnInstall(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	held := map[uint64]bool{}
	var applied []uint64
	sink := &shardQ3Sink{
		verify: func(_ context.Context, e q3format.Entry, _ handoff.OldCommitProof, head *abdrc.CommittedBlock, _ []byte) error {
			if head == nil {
				return errors.New("no checkpoint")
			}
			applied = append(applied, e.Epoch())
			held[e.Epoch()] = true
			return nil
		},
		holds: func(epoch uint64) bool { return held[epoch] },
	}
	// an entry only the history mints; the fixture's history yields it
	h, err := q3format.NewHistory(f.Old)
	require.NoError(t, err)
	h, err = h.VerifyEnvelope(f.Envelope)
	require.NoError(t, err)
	entry, err := h.ForEpoch(f.Claim.Epoch)
	require.NoError(t, err)

	require.ErrorIs(t, sink.HoldsVerifiedEpoch(entry), ErrQ3ShardEpoch, "nothing is held before the install")
	anchor, err := sink.InstallVerifiedEpoch(entry, f.Proof, f.Snapshot, nil)
	require.NoError(t, err)
	_, g, _ := entry.Handoff()
	require.Equal(t, g.ID(), anchor.GenesisID)
	require.Equal(t, g.Start-1, anchor.Slot)
	require.NoError(t, sink.HoldsVerifiedEpoch(entry))

	held = map[uint64]bool{} // a restart loses the state
	require.Error(t, sink.HoldsVerifiedEpoch(entry))
	require.NoError(t, sink.RestoreVerifiedEpoch(entry, f.Proof, f.Snapshot, nil))
	require.NoError(t, sink.HoldsVerifiedEpoch(entry))
	require.Equal(t, []uint64{f.Claim.Epoch, f.Claim.Epoch}, applied)

	_, err = sink.InstallVerifiedEpoch(entry, f.Proof, nil, nil)
	require.Error(t, err, "an install the node refuses reports no anchor")
}

func TestTheNextConfigurationIsTheCandidatesActivatedAssignmentOrTheUnchangedOne(t *testing.T) {
	active := make([]byte, 32)
	active[0] = 7
	got, err := q3NextConf(active, handoff.OldCommitProof{}, nil)
	require.NoError(t, err)
	require.Equal(t, active, got)
	got[0] = 9
	require.Equal(t, byte(7), active[0], "a copy, never the caller's slice")

	f := q3fixture.New(t, q3fixture.Options{Assignment: true})
	next, err := q3NextConf(active, f.Proof, f.Candidate)
	require.NoError(t, err)
	_, activated, err := evmassign.ActivatedFromPreimage(f.Candidate, f.Proof.Record.ActivationRound)
	require.NoError(t, err)
	want, err := activated.Hash(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, want, next)
	require.NotEqual(t, active, next)

	_, err = q3NextConf(active, f.Proof, []byte("not a candidate"))
	require.Error(t, err)
}
