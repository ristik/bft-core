package q3format

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-go-base/types"
)

// worldAt is a world whose genesis trust base the test keeps a pointer to, as a caller of NewHistory would.
func worldAt(t *testing.T) (*world, *types.RootTrustBaseV1) {
	t.Helper()
	s := newSigners(t, "a", "b", "c", "d")
	genesis := genesisTB(t, s, 0)
	h, err := NewHistory(genesis)
	require.NoError(t, err)
	return &world{t: t, h: h, signers: map[uint64]signers{1: s}}, genesis
}

// The history owns its authority: changing what the caller passed to NewHistory afterwards, before or after extending it, must not
// change who can mint an activation.
func TestHistoryOwnsItsGenesisAuthority(t *testing.T) {
	w, genesis := worldAt(t)
	_, err := w.h.WithV3(w.link(spec{}))
	require.NoError(t, err, "acceptance control: three of four genesis members")

	short := w.link(spec{signedBy: []string{"a"}})
	_, err = w.h.WithV3(short)
	require.ErrorIs(t, err, ErrActivation, "one of four is below the threshold")

	genesis.QuorumThreshold = 1
	_, err = w.h.WithV3(short)
	require.ErrorIs(t, err, ErrActivation, "the caller lowering its threshold changes nothing")

	for _, n := range genesis.RootNodes {
		n.Stake = 9
		for i := range n.SigKey {
			n.SigKey[i] ^= 0xff
		}
	}
	for k := range genesis.Signatures {
		genesis.Signatures[k][0] ^= 1
	}
	genesis.StateHash = []byte{1}
	_, err = w.h.WithV3(w.link(spec{}))
	require.NoError(t, err, "nor do the caller's keys, stakes or signatures")

	ext := w.append(spec{})
	genesis.RootNodes = nil
	_, err = w.h.WithV3(short)
	require.ErrorIs(t, err, ErrActivation, "mutation after extending")
	require.Equal(t, uint64(2), ext.Tip().Epoch())
	require.NotNil(t, w.h.Tip().tb)
	require.Len(t, w.h.Tip().tb.RootNodes, 4)
}

// A link for a retained epoch must carry that epoch's body, record and evidence; a matching claim alone is not enough.
func TestRetainedLinkIsCheckedAgainstTheEntry(t *testing.T) {
	w := newWorld(t, 0)
	l := w.claimed(spec{})
	h, err := w.h.VerifyEnvelope(envelopeOf(l))
	require.NoError(t, err)
	_, err = h.VerifyEnvelope(envelopeOf(l))
	require.NoError(t, err, "acceptance control: the same link again")

	for name, mutate := range map[string]func(*Link){
		"substituted body":    func(l *Link) { l.Body.StateSummary = fill(0x23) },
		"substituted members": func(l *Link) { l.Body.Members = l.Body.Members[:3] },
		"dropped receipt":     func(l *Link) { l.Receipts = l.Receipts[:3] },
		// same body, boundary and attempt: only the ordering round of the committed record differs
		"other record": func(l *Link) {
			l.Proof = w.link(spec{record: func(r *evmroot.OrderedHandoffRecord) { r.OrderedRound++ }, committee: w.signers[2]}).Proof
		},
		"other evidence":  func(l *Link) { l.Evidence.Summary = fill(0x56) },
		"other candidate": func(l *Link) { l.Evidence.CandidateDigest = fill(0x45) },
		// same body, another committed record
		"other proof":       func(l *Link) { l.Proof = w.link(spec{activate: 26, committee: w.signers[2]}).Proof },
		"claim of the body": func(l *Link) { l.Body.Epoch = 3; l.Claim.Epoch = 3 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := l
			bad.Body.Members = append(evmroot.WeightSet(nil), l.Body.Members...)
			bad.Proof = append([]byte(nil), l.Proof...)
			mutate(&bad)
			_, err := h.VerifyEnvelope(envelopeOf(bad))
			if name == "claim of the body" {
				require.ErrorIs(t, err, ErrPrior) // epoch 3 extends the tip: a new link refused for its predecessor, never a retained match
				require.NotErrorIs(t, err, ErrConflict)
				return
			}
			require.ErrorIs(t, err, ErrConflict)
			if name == "substituted body" {
				require.ErrorContains(t, err, "body identity", "refused for the body itself, not only for what follows from it")
			}
			if name == "dropped receipt" {
				require.ErrorIs(t, err, ErrReceiptMissing)
			}
		})
	}
}

// The record id does not commit to the commit QC's signatures or the inclusion path, so a retained link must authenticate the
// proof it supplies as a fresh activation would: genuine replay passes, forged evidence under the right record is a conflict.
func TestRetainedLinkRejectsForgedCommitEvidence(t *testing.T) {
	w := newWorld(t, 0)
	l := w.claimed(spec{})
	h, err := w.h.VerifyEnvelope(envelopeOf(l))
	require.NoError(t, err)
	_, err = h.VerifyEnvelope(envelopeOf(l))
	require.NoError(t, err, "control: the genuine proof again")

	forged := func(edit func(*handoff.OldCommitProof)) Link {
		p, err := decodeProof(l.Proof)
		require.NoError(t, err)
		edit(&p)
		raw, err := types.Cbor.Marshal(p)
		require.NoError(t, err)
		bad := l
		bad.Proof = raw
		return bad
	}
	flip := func(p *handoff.OldCommitProof) {
		for _, sig := range p.CommitQC.Signatures {
			sig[0] ^= 1
			return
		}
		t.Fatal("no signatures")
	}
	bad := forged(flip)
	require.Equal(t, mustRecord(t, l.Proof), mustRecord(t, bad.Proof), "only the signature differs: record, body, evidence, receipts and claim are unchanged")
	_, err = w.h.VerifyEnvelope(envelopeOf(bad))
	require.ErrorIs(t, err, ErrActivation, "control: a fresh history refuses it")
	_, err = h.VerifyEnvelope(envelopeOf(bad))
	require.ErrorIs(t, err, ErrConflict)
	require.ErrorIs(t, err, ErrActivation)

	_, err = h.VerifyEnvelope(envelopeOf(forged(func(p *handoff.OldCommitProof) { p.Control.PreviousDigest = fill(9) })))
	require.ErrorIs(t, err, ErrConflict, "a forged control leaf under the right record")
}

func mustRecord(t *testing.T, proof []byte) []byte {
	t.Helper()
	p, err := decodeProof(proof)
	require.NoError(t, err)
	return p.Record.ID()
}
