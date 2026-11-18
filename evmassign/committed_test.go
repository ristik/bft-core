package evmassign

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

// The committed-candidate decoder reads a VR chain's candidate v6 without vrschema or vradmit being linked (this package's tests link
// neither): the frozen unsigned candidate v6 vector decodes to its view, a null PoP list is refused as non-canonical, and a v5 candidate
// still decodes as before.
func TestDecodeCommittedCandidateReadsTheFrozenV6WithoutVRLinked(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testvectors", "validator-registry", "encoding.json"))
	require.NoError(t, err)
	var f struct {
		Vectors []struct {
			Name, Op      string
			Input, Expect map[string]any
		}
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	n := 0
	for _, v := range f.Vectors {
		if v.Op != "handoff.candidateV6" {
			continue
		}
		if b, ok := v.Expect["bytes"].(string); ok {
			data := common.FromHex(b)
			c, err := DecodeCommittedCandidate(data)
			require.NoError(t, err, v.Name)
			require.EqualValues(t, CandidateVersion, c.Version, "the view is a v5 candidate")
			require.Nil(t, c.Changes)
			view, ref, rc, err := DecodeCandidateV6View(data)
			require.NoError(t, err)
			require.Equal(t, c, view)
			require.Len(t, ref, 32)
			require.NotEmpty(t, rc)
			sum := sha256.Sum256(data)
			require.Equal(t, v.Expect["digest"], "0x"+common.Bytes2Hex(sum[:]), "the bound digest is of the v6 bytes")
			_, err = DecodeCandidate(data)
			require.Error(t, err, "the strict v5 decoder refuses v6")
			n++
		}
		if b, ok := v.Input["bytes"].(string); ok {
			_, err := DecodeCommittedCandidate(common.FromHex(b))
			require.ErrorIs(t, err, ErrCandidate, v.Name)
			n++
		}
	}
	require.Equal(t, 2, n)
}
