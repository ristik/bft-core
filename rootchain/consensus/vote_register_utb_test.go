package consensus

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// utbVote is a version 3 vote of a UTB epoch endorsing entry (nil: no handoff). The register does not verify signatures; they are distinct per author.
func utbVote(t *testing.T, author string, entry []byte) *abdrc.VoteMsg {
	v := NewDummyVote(t, author, 7, []byte{1, 2, 3})
	v.Envelope = votesig.EnvelopeUTB
	if entry != nil {
		v.UTB = &drctypes.UTBVote{Unsigned: entry, Signature: []byte("endorsement-" + author)}
	}
	return v
}

func TestRegisterAggregatesTheEndorsementsOfOneEntry(t *testing.T) {
	r := NewVoteRegister()
	q := NewDummyQuorum(3, 0)
	entry := []byte("entry-A")
	for _, a := range []string{"n1", "n2"} {
		qc, err := r.InsertVote(utbVote(t, a, entry), q)
		require.NoError(t, err)
		require.Nil(t, qc)
	}
	qc, err := r.InsertVote(utbVote(t, "n3", entry), q)
	require.NoError(t, err)
	require.NotNil(t, qc)
	require.EqualValues(t, votesig.EnvelopeUTB, qc.Envelope)
	require.NotNil(t, qc.UTB)
	require.Equal(t, entry, []byte(qc.UTB.Unsigned))
	require.Len(t, qc.UTB.Signatures, 3)
	for a := range qc.Signatures {
		require.Contains(t, qc.UTB.Signatures, a, "the endorsers are exactly the voters")
	}
	require.Equal(t, []byte("endorsement-n2"), []byte(qc.UTB.Signatures["n2"]))
}

func TestRegisterNeverCombinesDifferentEndorsements(t *testing.T) {
	q := NewDummyQuorum(3, 0)
	t.Run("two different entries", func(t *testing.T) {
		r := NewVoteRegister()
		for i, a := range []string{"n1", "n2", "n3", "n4"} {
			entry := []byte("entry-A")
			if i%2 == 1 {
				entry = []byte("entry-B")
			}
			qc, err := r.InsertVote(utbVote(t, a, entry), q)
			require.NoError(t, err)
			require.Nil(t, qc, "2 + 2 endorsements of different entries never reach 3")
		}
	})
	t.Run("endorsing and not endorsing", func(t *testing.T) {
		r := NewVoteRegister()
		for _, v := range []*abdrc.VoteMsg{utbVote(t, "n1", []byte("A")), utbVote(t, "n2", nil), utbVote(t, "n3", []byte("A"))} {
			qc, err := r.InsertVote(v, q)
			require.NoError(t, err)
			require.Nil(t, qc)
		}
	})
	t.Run("version 3 and version 1/2 votes", func(t *testing.T) {
		r := NewVoteRegister()
		plain := NewDummyVote(t, "n2", 7, []byte{1, 2, 3})
		for _, v := range []*abdrc.VoteMsg{utbVote(t, "n1", nil), plain, utbVote(t, "n3", nil)} {
			qc, err := r.InsertVote(v, q)
			require.NoError(t, err)
			require.Nil(t, qc)
		}
	})
	t.Run("a voter who changes its endorsement is an equivocator", func(t *testing.T) {
		r := NewVoteRegister()
		_, err := r.InsertVote(utbVote(t, "n1", []byte("A")), q)
		require.NoError(t, err)
		_, err = r.InsertVote(utbVote(t, "n1", []byte("B")), q)
		require.ErrorContains(t, err, "equivocating vote")
		_, err = r.InsertVote(utbVote(t, "n1", nil), q)
		require.ErrorContains(t, err, "equivocating vote")
	})
	t.Run("an endorsement outside the version 3 envelope", func(t *testing.T) {
		v := utbVote(t, "n1", []byte("A"))
		v.Envelope = 0
		_, err := NewVoteRegister().InsertVote(v, q)
		require.ErrorIs(t, err, votesig.ErrEnvelope)
	})
}

func TestRegisterFormsVersion3CertificatesWithoutAHandoff(t *testing.T) {
	r := NewVoteRegister()
	q := NewDummyQuorum(3, 0)
	var qc *drctypes.QuorumCert
	for _, a := range []string{"n1", "n2", "n3"} {
		var err error
		qc, err = r.InsertVote(utbVote(t, a, nil), q)
		require.NoError(t, err)
	}
	require.NotNil(t, qc)
	require.EqualValues(t, votesig.EnvelopeUTB, qc.Envelope)
	require.Nil(t, qc.UTB)
}
