package engineapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// pairVectors is ureth#52's testdata/pair-binding-vectors.json at the head the lane is pinned to (eb6b5c35). Its encoder shares no code with
// either implementation; its root input is a Go-produced vector.
type pairVectors struct {
	Fields struct {
		NetworkID            uint64 `json:"networkId"`
		RootGenesisID        string `json:"rootGenesisId"`
		ExecutionGenesisHash string `json:"executionGenesisHash"`
		ParentHash           string `json:"parentHash"`
		ParentNumber         uint64 `json:"parentNumber"`
		OriginRootEpoch      uint64 `json:"originRootEpoch"`
		OriginRootRound      uint64 `json:"originRootRound"`
		ConfigurationID      string `json:"configurationId"`
		ActivationID         string `json:"activationId"`
		RootInputHash        string `json:"rootInputHash"`
		TransitionsHash      string `json:"transitionsHash"`
	} `json:"fields"`
	Transition           string `json:"transition"`
	EmptyTransitionsHash string `json:"emptyTransitionsHash"`
	OneTransitionHash    string `json:"oneTransitionHash"`
	Attributes           struct {
		Timestamp             uint64 `json:"timestamp"`
		PrevRandao            string `json:"prevRandao"`
		SuggestedFeeRecipient string `json:"suggestedFeeRecipient"`
		ParentBeaconBlockRoot string `json:"parentBeaconBlockRoot"`
		Digest                string `json:"digest"`
	} `json:"attributes"`
	BlockHash string            `json:"blockHash"`
	Build     string            `json:"build"`
	Import    string            `json:"import"`
	Invalid   map[string]string `json:"invalid"`
}

func hx(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	require.NoError(t, err)
	return raw
}

func w32(t *testing.T, s string) (out [32]byte) {
	t.Helper()
	raw := hx(t, s)
	require.Len(t, raw, 32)
	copy(out[:], raw)
	return out
}

func loadPairVectors(t *testing.T) pairVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/pair-binding-vectors.json")
	require.NoError(t, err)
	var v pairVectors
	require.NoError(t, json.Unmarshal(raw, &v))
	return v
}

func vectorBinding(t *testing.T, v pairVectors, kind PairSubjectKind) PairBinding {
	f := v.Fields
	b := PairBinding{NetworkID: f.NetworkID, RootGenesisID: w32(t, f.RootGenesisID), ExecutionGenesisHash: w32(t, f.ExecutionGenesisHash),
		ParentHash: w32(t, f.ParentHash), ParentNumber: f.ParentNumber, OriginRootEpoch: f.OriginRootEpoch, OriginRootRound: f.OriginRootRound,
		ConfigurationID: w32(t, f.ConfigurationID), ActivationID: w32(t, f.ActivationID), RootInputHash: w32(t, f.RootInputHash),
		TransitionsHash: w32(t, f.TransitionsHash), Kind: kind}
	if kind == PairBuild {
		b.SubjectID = w32(t, v.Attributes.Digest)
	} else {
		b.SubjectID = w32(t, v.BlockHash)
	}
	return b
}

func TestPairBindingEncodingMatchesTheIndependentVector(t *testing.T) {
	v := loadPairVectors(t)
	for name, tc := range map[string]struct {
		kind PairSubjectKind
		want string
	}{"build": {PairBuild, v.Build}, "import": {PairImport, v.Import}} {
		got, err := vectorBinding(t, v, tc.kind).Encode()
		require.NoError(t, err, name)
		require.Equal(t, hx(t, tc.want), got, name)
		back, err := DecodePairBinding(got)
		require.NoError(t, err, name)
		require.Equal(t, vectorBinding(t, v, tc.kind), back, name)
	}
}

func TestPairBindingIdentitiesMatchTheIndependentVector(t *testing.T) {
	v := loadPairVectors(t)
	empty, err := TransitionsHash(nil)
	require.NoError(t, err)
	require.Equal(t, w32(t, v.EmptyTransitionsHash), empty)
	one, err := TransitionsHash([][]byte{hx(t, v.Transition)})
	require.NoError(t, err)
	require.Equal(t, w32(t, v.OneTransitionHash), one)
	var recipient [20]byte
	copy(recipient[:], hx(t, v.Attributes.SuggestedFeeRecipient))
	digest, err := AttributesDigest(v.Attributes.Timestamp, w32(t, v.Attributes.PrevRandao), recipient, w32(t, v.Attributes.ParentBeaconBlockRoot))
	require.NoError(t, err)
	require.Equal(t, w32(t, v.Attributes.Digest), digest)
}

func TestPairBindingRootInputHashIsTheGoCommitment(t *testing.T) {
	v := loadPairVectors(t)
	raw, err := os.ReadFile("testdata/pair-binding-vectors.json")
	require.NoError(t, err)
	var generic map[string]any
	require.NoError(t, json.Unmarshal(raw, &generic))
	input := hx(t, generic["rootInput"].(string))
	// the vector's rootInputHash is the SHA-256 of the exact bytes Go produced, which is evmroot.RootInputV2.ExtraData
	got := sha256Of(input)
	require.Equal(t, w32(t, v.Fields.RootInputHash), got)
}

func TestPairBindingDecodeRefusesEveryInvalidVector(t *testing.T) {
	v := loadPairVectors(t)
	require.NotEmpty(t, v.Invalid)
	for name, raw := range v.Invalid {
		_, err := DecodePairBinding(hx(t, raw))
		require.ErrorIs(t, err, ErrPairBinding, name)
	}
}

func TestPairBindingEncodingRefusesNothingElseAndDecodeIsStrict(t *testing.T) {
	v := loadPairVectors(t)
	good, err := vectorBinding(t, v, PairBuild).Encode()
	require.NoError(t, err)
	for name, mutate := range map[string]func([]byte) []byte{
		"trailing byte": func(b []byte) []byte { return append(append([]byte(nil), b...), 0) },
		"truncated":     func(b []byte) []byte { return b[:len(b)-1] },
		"empty":         func([]byte) []byte { return nil },
		"oversized":     func(b []byte) []byte { return append(append([]byte(nil), b...), make([]byte, MaxPairBindingBytes)...) },
	} {
		_, err := DecodePairBinding(mutate(good))
		require.ErrorIs(t, err, ErrPairBinding, name)
	}
	for _, kind := range []PairSubjectKind{0, 3} {
		b := vectorBinding(t, v, PairBuild)
		b.Kind = kind
		raw, err := b.Encode()
		require.NoError(t, err)
		_, err = DecodePairBinding(raw)
		require.ErrorIs(t, err, ErrPairBinding, "subject kind %d", kind)
	}
}

func TestPairPinsAreComparedWithTheNodesOwn(t *testing.T) {
	net := uint64(3)
	root := data32(w32(t, "0x5151515151515151515151515151515151515151515151515151515151515151"))
	c := &PairConfig{Pins: PairPins{NetworkID: 3, RootGenesisID: [32]byte(root)}}
	require.NoError(t, c.checkPins(pairConfigWire{NetworkID: &net, RootGenesisID: &root}))
	other := uint64(4)
	require.ErrorIs(t, c.checkPins(pairConfigWire{NetworkID: &other, RootGenesisID: &root}), ErrPairPins)
	flipped := root
	flipped[0] ^= 1
	require.ErrorIs(t, c.checkPins(pairConfigWire{NetworkID: &net, RootGenesisID: &flipped}), ErrPairPins)
	require.ErrorIs(t, c.checkPins(pairConfigWire{}), ErrPairPins, "a client that reports no pins")
	require.NoError(t, (*PairConfig)(nil).checkPins(pairConfigWire{}), "no binding configured: nothing to compare")
}

func TestPairBindingTravelsOnlyInItsOwnJSONField(t *testing.T) {
	plain, err := json.Marshal(SealBuildInput{RootInput: data{1}, Transitions: nil})
	require.NoError(t, err)
	require.NotContains(t, string(plain), "pairBinding", "an empty binding keeps the request byte-identical to the pre-binding one")
	paired, err := json.Marshal(SealBuildInput{RootInput: data{1}, Pair: data{0x80}})
	require.NoError(t, err)
	require.Contains(t, string(paired), `"pairBinding":"0x80"`)
	companion, err := json.Marshal(SealCompanion{RootInput: data{1}, Provenance: "newPayload", Pair: data{0x80}})
	require.NoError(t, err)
	require.Contains(t, string(companion), `"pairBinding":"0x80"`)
	// the disseminated companion is decoded from a block without a binding and never carries one
	var back SealCompanion
	require.NoError(t, json.Unmarshal(companion, &back))
	require.Empty(t, back.Pair)
}

func sha256Of(b []byte) [32]byte { return sha256.Sum256(b) }
