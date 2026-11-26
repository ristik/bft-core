package storage

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/vradmit"
)

// BlockStore.VRCandidateCheck (#1306) judges over the block of the parent round with the store's orchestration and handoff authority: a
// round the store does not hold is unavailable, never a refusal; over a held parent the candidate itself is judged (here one that does not
// decode, which item (5) refuses).
func TestBlockStoreVRCandidateCheckJudgesOverTheParentBlock(t *testing.T) {
	s := profileStore(t)
	installTestFrozenShard(t, s, bytes.Repeat([]byte{7}, 32))
	root := s.tree().Root()
	require.NotNil(t, root.ShardState.Control, "premise: a handoff-profile root carries a control state")

	err := s.VRCandidateCheck(root.GetRound()+100, root.GetRound()+101, []byte{1}, q3format.BodyV3{}, 0, nil)
	require.ErrorIs(t, err, ErrVRUnavailable, "no parent block: the check cannot judge")
	require.NotErrorIs(t, err, vradmit.ErrAdmission)

	err = s.VRCandidateCheck(root.GetRound(), root.GetRound()+1, []byte{1}, q3format.BodyV3{}, 0, nil)
	require.ErrorIs(t, err, vradmit.ErrH3, "the held parent's check judges the candidate")

	saved := s.handoffAuth
	s.handoffAuth = nil
	require.ErrorIs(t, s.VRCandidateCheck(root.GetRound(), root.GetRound()+1, []byte{1}, q3format.BodyV3{}, 0, nil), ErrVRUnavailable,
		"no handoff authority: unavailable")
	s.handoffAuth = saved
}
