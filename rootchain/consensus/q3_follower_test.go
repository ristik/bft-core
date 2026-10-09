package consensus

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

type signStub struct{ signed int }

func (s *signStub) Sign(abcrypto.Signer) error { s.signed++; return nil }

// refusesToSign: every signing path of the module (vote, timeout, a message without voting rules) refuses a root the epoch's committee does
// not name, with the one sentinel and without signing or recording anything.
func refusesToSign(t *testing.T, r *q3Replica, epoch uint64) {
	t.Helper()
	m := r.manager.safety
	stub := &signStub{}
	require.ErrorIs(t, m.Sign(epoch, stub), ErrNotAMember)
	require.Zero(t, stub.signed)
	_, err := m.MakeVote(&drctypes.BlockData{Version: 2, Epoch: epoch, Round: 3}, make([]byte, 32), nil, nil)
	require.ErrorIs(t, err, ErrNotAMember)
	qc := &drctypes.QuorumCert{VoteInfo: &drctypes.RoundInfo{Version: 1, RoundNumber: 2, ParentRoundNumber: 1, Epoch: epoch}, Signatures: map[string]hex.Bytes{}}
	tmo := abdrc.NewTimeoutMsg(drctypes.NewTimeout(3, epoch, qc), r.id().String(), nil)
	require.ErrorIs(t, m.SignTimeout(tmo, nil), ErrNotAMember)
	require.Empty(t, tmo.Signature, "nothing was signed")
}

// A joiner root before its activation: it starts (a manager over the verified history, its key absent from the committee), reports itself as
// a follower, stages the candidate that names it and signs nothing; once the activation is installed and its key is in the committee it signs
// as a member of the new epoch and still not as one of the old. A removed validator is the mirror image.
func TestAJoinerRootFollowsStagesSignsNothingAndIsPromotedAfterInstall(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	ctx := context.Background()
	joiner := newQ3Replica(t, f, f.NewNodes[3]) // a node of the successor that the genesis committee does not name
	joiner.mustOpen(true)
	t.Cleanup(joiner.close)
	require.NoError(t, joiner.rt.Recover(ctx))

	member := newQ3Replica(t, f, f.NewNodes[0]) // the control: an incumbent the successor keeps
	member.mustOpen(true)
	t.Cleanup(member.close)
	require.NoError(t, member.rt.Recover(ctx))

	t.Run("before the activation the joiner is a follower and signs nothing; a member signs", func(t *testing.T) {
		st, err := joiner.manager.Q3Status()
		require.NoError(t, err)
		require.True(t, st.Follower)
		require.EqualValues(t, 1, st.ActiveEpoch)
		refusesToSign(t, joiner, 1)
		cst, err := member.manager.Q3Status()
		require.NoError(t, err)
		require.False(t, cst.Follower)
		require.NoError(t, member.manager.safety.Sign(1, &signStub{}), "a validator of the epoch signs")
	})
	t.Run("it stages the candidate that names it and refuses one that does not", func(t *testing.T) {
		digest := [32]byte(f.Evidence.CandidateDigest)
		require.NoError(t, joiner.manager.StageV3Candidate(f.Body.Encode(), digest, 0, nil))
		st, err := joiner.manager.Q3Status()
		require.NoError(t, err)
		require.NotNil(t, st.Staged)
		require.Equal(t, digest, st.Staged.CandidateDigest)
		require.True(t, st.Follower, "staging does not promote")
		other := f.Body
		other.Members = append(other.Members[:0:0], other.Members[:3]...) // a successor that does not name the joiner
		wrong := sha256.Sum256([]byte("x"))
		require.Error(t, joiner.manager.StageV3Candidate(other.Encode(), wrong, 0, nil))
	})
	t.Run("a joiner never signs under a flag: the refusal is derived from the trust base alone", func(t *testing.T) {
		require.NoError(t, joiner.rt.Activate(ctx, joiner.bundle()))
		st, err := joiner.manager.Q3Status()
		require.NoError(t, err)
		require.False(t, st.Follower, "the installed epoch names the joiner")
		require.EqualValues(t, 2, st.ActiveEpoch)
		require.NoError(t, joiner.manager.safety.Sign(2, &signStub{}), "promoted: it signs as a member of the new epoch")
		refusesToSignEpoch1 := &signStub{}
		require.ErrorIs(t, joiner.manager.safety.Sign(1, refusesToSignEpoch1), ErrNotAMember, "and never as a member of the old one")
		require.Zero(t, refusesToSignEpoch1.signed)
	})
	t.Run("a validator the successor removes becomes a follower", func(t *testing.T) {
		removed := newQ3Replica(t, f, f.OldNodes[3])
		removed.mustOpen(true)
		t.Cleanup(removed.close)
		require.NoError(t, removed.rt.Recover(ctx))
		require.NoError(t, removed.manager.safety.Sign(1, &signStub{}), "a member of epoch 1")
		require.NoError(t, removed.rt.Activate(ctx, removed.bundle()))
		st, err := removed.manager.Q3Status()
		require.NoError(t, err)
		require.True(t, st.Follower)
		refusesToSign(t, removed, 2)
	})
}
