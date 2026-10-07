package bridgeprofile

import (
	"bytes"
	stdcrypto "crypto"
	stdhex "encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"sort"
	"strconv"

	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
)

// This file isolates the trust-authority decisions that the native-bridge
// design still has open, so each changes in exactly one place. Trust-base
// evolution (epochs, appended records, fetching newer bases, arbitrary
// weights) is common SDK functionality for later: this profile verifies against
// one SDK trust base supplied by the caller and builds no bridge-private epoch
// bundle and no bridge-owned weighted verifier.

// verifyNativeUC is the Go SDK's own UC verification, used as is. The repository
// routes every production UC verification through quorumweight.Checked, which
// guards stake overflow and rejects unknown signers (the SDK skips them); it adds no weighted-authority logic, and full seal
// acceptance parity with the SDK is not claimed.
func verifyNativeUC(tb types.RootTrustBase, uc *types.UnicityCertificate, partition types.PartitionID, shard types.ShardID, conf []byte) error {
	return uc.Verify(quorumweight.Checked(tb), stdcrypto.SHA256, partition, shard, conf)
}

// TrustInput is the one pinned SDK RootTrustBase document of the supported
// profile: the exact installed bytes B (the SDK's JSON representation,
// published once and pinned by the manifest) and the base parsed from them.
// trustBaseId = SHA256(B) identifies those exact bytes; it is an integrity
// binding, not authentication of the base, which stays the application's
// provisioning decision. Verification hashes the installed B, never a
// reconstructed object.
type TrustInput struct {
	JSON []byte
	Base types.RootTrustBase
}

// ID is trustBaseId = SHA256(B).
func (t *TrustInput) ID() [32]byte { return H(t.JSON) }

// RenderTrustBaseJSON renders tb exactly as the pinned JS SDK 3.0.1 emits it,
// UTF8(JSON.stringify(RootTrustBase.fromJSON(source).toJSON())): top-level
// order changeRecordHash, epoch, epochStartRound, networkId, previousEntryHash,
// quorumThreshold, rootNodes, signatures, stateHash, version; node fields
// nodeId, sigKey, stake; uint64 values and the version as decimal strings,
// networkId as a number, hex lowercase without a prefix, absent hashes null,
// no whitespace. The native-bridge-plugins tooling checks that every document
// in the corpus is byte-identical to the SDK's own emission; the oracle
// consumes the published B as opaque bytes.
func RenderTrustBaseJSON(tb *types.RootTrustBaseV1) ([]byte, error) {
	var w bytes.Buffer
	str := func(s string) {
		e := json.NewEncoder(&w)
		e.SetEscapeHTML(false)
		_ = e.Encode(s)
		w.Truncate(w.Len() - 1) // Encode appends a newline
	}
	opt := func(b hex.Bytes) {
		if len(b) == 0 {
			w.WriteString("null")
			return
		}
		str(stdhex.EncodeToString(b))
	}
	num := func(u uint64) { str(strconv.FormatUint(u, 10)) }
	w.WriteString(`{"changeRecordHash":`)
	opt(tb.ChangeRecordHash)
	w.WriteString(`,"epoch":`)
	num(tb.Epoch)
	w.WriteString(`,"epochStartRound":`)
	num(tb.EpochStart)
	w.WriteString(`,"networkId":` + strconv.FormatUint(uint64(tb.NetworkID), 10))
	w.WriteString(`,"previousEntryHash":`)
	opt(tb.PreviousEntryHash)
	w.WriteString(`,"quorumThreshold":`)
	num(tb.QuorumThreshold)
	w.WriteString(`,"rootNodes":[`)
	for i, n := range tb.RootNodes {
		if i > 0 {
			w.WriteByte(',')
		}
		w.WriteString(`{"nodeId":`)
		str(n.NodeID)
		w.WriteString(`,"sigKey":`)
		str(stdhex.EncodeToString(n.SigKey))
		w.WriteString(`,"stake":`)
		num(n.Stake)
		w.WriteByte('}')
	}
	w.WriteString(`],"signatures":{`)
	ids := make([]string, 0, len(tb.Signatures))
	for id := range tb.Signatures {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for i, id := range ids {
		if i > 0 {
			w.WriteByte(',')
		}
		str(id)
		w.WriteByte(':')
		str(stdhex.EncodeToString(tb.Signatures[id]))
	}
	w.WriteString(`},"stateHash":`)
	str(stdhex.EncodeToString(tb.StateHash))
	w.WriteString(`,"version":`)
	num(uint64(tb.Version))
	w.WriteByte('}')
	return w.Bytes(), nil
}

// sdkTrustDoc is the SDK's JSON representation of a RootTrustBase.
type sdkTrustDoc struct {
	ChangeRecordHash  *string           `json:"changeRecordHash"`
	Epoch             string            `json:"epoch"`
	EpochStart        string            `json:"epochStartRound"`
	NetworkID         uint64            `json:"networkId"`
	PreviousEntryHash *string           `json:"previousEntryHash"`
	QuorumThreshold   string            `json:"quorumThreshold"`
	RootNodes         []sdkTrustNode    `json:"rootNodes"`
	Signatures        map[string]string `json:"signatures"`
	StateHash         string            `json:"stateHash"`
	Version           string            `json:"version"`
}

type sdkTrustNode struct {
	NodeID string `json:"nodeId"`
	SigKey string `json:"sigKey"`
	Stake  string `json:"stake"`
}

func sdkUint(s string) (uint64, bool) {
	u, err := strconv.ParseUint(s, 10, 64)
	return u, err == nil && strconv.FormatUint(u, 10) == s
}

func sdkHex(s string) (hex.Bytes, bool) {
	b, err := stdhex.DecodeString(s)
	return b, err == nil && stdhex.EncodeToString(b) == s
}

// LoadTrustInput parses the installed bytes B (the SDK JSON representation)
// and checks the fixed profile at installation: version 1, an epoch, N
// distinct validators each of weight 1 and quorumThreshold = N - (N-1)/3.
// Anything else is unsupported (never flattened into unit weights):
// trust-base evolution and arbitrary weights are common SDK work for later.
func LoadTrustInput(b []byte) (*TrustInput, error) {
	var d sdkTrustDoc
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, ErrTrustConfig
	}
	// Exactly one JSON value: anything after it, a stray bracket included, is rejected as the SDK's parser rejects it.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrTrustConfig
	}
	// Range checks precede every narrowing conversion: an out-of-range number is never read as its low bits.
	if d.NetworkID > math.MaxUint16 {
		return nil, ErrTrustConfig
	}
	tb := types.RootTrustBaseV1{NetworkID: types.NetworkID(d.NetworkID), Signatures: map[string]hex.Bytes{}}
	var ok [5]bool
	var ver uint64
	ver, ok[0] = sdkUint(d.Version)
	tb.Epoch, ok[1] = sdkUint(d.Epoch)
	tb.EpochStart, ok[2] = sdkUint(d.EpochStart)
	tb.QuorumThreshold, ok[3] = sdkUint(d.QuorumThreshold)
	tb.StateHash, ok[4] = sdkHex(d.StateHash)
	for _, k := range ok {
		if !k {
			return nil, ErrTrustConfig
		}
	}
	if ver != 1 {
		return nil, ErrTrustConfig
	}
	tb.Version = types.Version(ver)
	for _, h := range []struct {
		src *string
		dst *hex.Bytes
	}{{d.ChangeRecordHash, &tb.ChangeRecordHash}, {d.PreviousEntryHash, &tb.PreviousEntryHash}} {
		if h.src != nil {
			v, k := sdkHex(*h.src)
			if !k {
				return nil, ErrTrustConfig
			}
			*h.dst = v
		}
	}
	for id, s := range d.Signatures {
		v, k := sdkHex(s)
		if !k {
			return nil, ErrTrustConfig
		}
		tb.Signatures[id] = v
	}
	seen := map[string]bool{}
	for _, n := range d.RootNodes {
		key, k1 := sdkHex(n.SigKey)
		stake, k2 := sdkUint(n.Stake)
		if !k1 || !k2 || stake != 1 || seen[n.NodeID] {
			return nil, ErrTrustConfig
		}
		seen[n.NodeID] = true
		tb.RootNodes = append(tb.RootNodes, &types.NodeInfo{NodeID: n.NodeID, SigKey: key, Stake: stake})
	}
	n := uint64(len(tb.RootNodes))
	if tb.Version != 1 || tb.Epoch == 0 || n == 0 || tb.QuorumThreshold != n-(n-1)/3 {
		return nil, ErrTrustConfig
	}
	return &TrustInput{JSON: bytes.Clone(b), Base: &tb}, nil
}

// checkFixedProfile guards use outside the one pinned base (it implements no
// epoch evolution): the proof names exactly this document, and the seal's
// network and root epoch equal the base's with a root round at or after the
// base's epoch start.
func checkFixedProfile(p *LockProof, t *TrustInput, uc *types.UnicityCertificate) error {
	if t == nil || t.Base == nil || p.TrustBaseID != t.ID() {
		return ErrTrustBaseDigest
	}
	if uc.UnicitySeal.NetworkID != t.Base.GetNetworkID() || uc.GetRootEpoch() != t.Base.GetEpoch() ||
		uc.UnicitySeal.RootChainRoundNumber < t.Base.GetEpochStart() {
		return ErrEpochMismatch
	}
	return nil
}
