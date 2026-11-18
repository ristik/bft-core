package vradmit

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// evmassign's candidate v6 view decoder (which cannot import vrschema) and vrschema's decoder agree on the encoding: every canonical v6
// the schema writes decodes to vradmit.V5Of, and an encoding the schema refuses as non-canonical (null lists) the view refuses too.
func TestTheV6ViewDecoderIsTheSchemas(t *testing.T) {
	w := newWorld(t)
	for _, c := range []vrschema.CandidateV6{w.cand, func() vrschema.CandidateV6 { c := w.cand; c.PoPs = nil; c.RegistryChanges = nil; return c }()} {
		raw, err := c.Encode()
		require.NoError(t, err)
		want, err := vrschema.DecodeCandidateV6(raw)
		require.NoError(t, err)
		view, ref, rc, err := evmassign.DecodeCandidateV6View(raw)
		require.NoError(t, err)
		require.Equal(t, V5Of(want), view)
		require.Equal(t, want.SourceRef, ref)
		require.Len(t, rc, len(want.RegistryChanges))
		for i := range rc {
			require.Equal(t, want.RegistryChanges[i].ID, rc[i].ID)
			require.Equal(t, want.RegistryChanges[i].Payload, rc[i].Payload)
			require.Equal(t, want.RegistryChanges[i].Verdict, rc[i].Verdict)
		}
	}
}
