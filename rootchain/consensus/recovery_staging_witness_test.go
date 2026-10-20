package consensus

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// The staged validation of a recovery state executes its pending blocks as the replay will, so the witnesses of their controls have to be held
// when it runs: a recovering root that lacks one must fetch it before the staging, not refuse a state it can recover from (rev2's #650 B1).
func TestRecoveryFetchesThePendingWitnessesBeforeTheStaging(t *testing.T) {
	c := newAnchorCluster(t)
	cm := latchProbe(t, c)
	state := c.pastTheFirstSuccessor()
	require.NotEmpty(t, state.Pending)
	// the tip of the state carries a control whose witness this root does not hold
	data := []byte("the witness of a pending control")
	hash := sha256.Sum256(data)
	tip := *state.Pending[len(state.Pending)-1]
	payload := *tip.Payload
	payload.PosControls = append([]drctypes.PosControl(nil), tip.Payload.PosControls...)
	payload.PosControls = append(payload.PosControls, validControl(&tip, hash))
	tip.Payload = &payload
	pending := &tip
	state = &abdrc.StateMsg{CommittedHead: state.CommittedHead, Pending: append(append([]*drctypes.BlockData(nil), state.Pending[:len(state.Pending)-1]...), pending)}
	head := state.CommittedHead.Block
	require.False(t, cm.blockStore.HasWitness(hash), "premise: the root does not hold the witness")

	fetched := 0
	cm.witnesses = func(_ context.Context, h [32]byte, _ []peer.ID, _ int) ([]byte, error) {
		fetched++
		require.Equal(t, hash, h)
		return data, nil
	}
	errStop := errors.New("staging reached")
	var heldAtStaging bool
	cm.stageRecovery = func(*abdrc.StateMsg) error {
		heldAtStaging = cm.blockStore.HasWitness(hash)
		return errStop
	}
	_, err := cm.recovery.Set(&drctypes.QuorumCert{VoteInfo: &drctypes.RoundInfo{RoundNumber: pending.Round, ParentRoundNumber: pending.Round - 1, Epoch: head.Epoch}})
	require.NoError(t, err)
	err = cm.onStateResponse(context.Background(), state)
	// the state itself may be refused earlier by verification in this fixture; what is pinned is the order of fetch and staging when it gets that far
	if errors.Is(err, errStop) {
		require.Equal(t, 1, fetched, "the witness was fetched")
		require.True(t, heldAtStaging, "and it is held when the staging runs")
	} else {
		t.Fatalf("the recovery did not reach the staging: %v", err)
	}

	// a witness nobody has stops the recovery before the staging, as unavailable (not as an invalid state)
	cm.witnesses = func(context.Context, [32]byte, []peer.ID, int) ([]byte, error) {
		return nil, errors.New("nobody has it")
	}
	other := sha256.Sum256([]byte("withheld"))
	pending.Payload.PosControls[0].WitnessHash = other
	staged := false
	cm.stageRecovery = func(*abdrc.StateMsg) error { staged = true; return nil }
	cm.recovery.Clear() // the refused state left the root in recovery
	_, err = cm.recovery.Set(&drctypes.QuorumCert{VoteInfo: &drctypes.RoundInfo{RoundNumber: pending.Round, ParentRoundNumber: pending.Round - 1, Epoch: head.Epoch}})
	require.NoError(t, err)
	err = cm.onStateResponse(context.Background(), state)
	require.ErrorIs(t, err, storage.ErrWitnessUnavailable)
	require.False(t, staged, "nothing was staged on a state whose witness is not held")
}
