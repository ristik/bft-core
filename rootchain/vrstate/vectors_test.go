package vrstate

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate/evmstatetest"
	"github.com/unicitynetwork/bft-core/vrschema"
)

const vectorDir = "../../testvectors/validator-registry"

type vectorFile struct {
	Vectors []struct {
		Name   string          `json:"name"`
		Op     string          `json:"op"`
		Input  json.RawMessage `json:"input"`
		Expect json.RawMessage `json:"expect"`
	} `json:"vectors"`
}

func loadVectors(t *testing.T, file string) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorDir, file))
	require.NoError(t, err)
	var f vectorFile
	require.NoError(t, json.Unmarshal(raw, &f))
	return f
}

func word(t *testing.T, s string) (w [32]byte) {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	require.NoError(t, err)
	require.Len(t, b, 32)
	copy(w[:], b)
	return w
}

func addr(t *testing.T, s string) (a [20]byte) {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	require.NoError(t, err)
	require.Len(t, b, 20)
	copy(a[:], b)
	return a
}

// storageWorld is the frozen storage scenarios (storage-flat.json) as a real EVM state, with VR at its pinned address.
func storageWorld(t *testing.T) (*evmstatetest.World, map[[20]byte][32]byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorDir, "storage-flat.json"))
	require.NoError(t, err)
	var flat struct {
		Scenarios map[string]struct {
			Account string   `json:"account"`
			Slots   []string `json:"slots"`
			Words   []string `json:"words"`
		} `json:"scenarios"`
	}
	require.NoError(t, json.Unmarshal(raw, &flat))
	var cs []evmstatetest.Contract
	codes := map[[20]byte][32]byte{}
	for name, s := range flat.Scenarios {
		require.Len(t, s.Words, len(s.Slots))
		st := map[[32]byte][32]byte{}
		for i := range s.Slots {
			st[word(t, s.Slots[i])] = word(t, s.Words[i])
		}
		a := addr(t, s.Account)
		code := vrschema.Keccak([]byte("code/" + name))
		codes[a] = code
		cs = append(cs, evmstatetest.Contract{Addr: a, CodeHash: code, Storage: st})
	}
	return evmstatetest.NewWorld(t, cs...), codes
}

// recording logs the slots a reader asks for.
type recording struct {
	r     evmstate.SlotReader
	slots [][32]byte
}

func (r *recording) Word(s [32]byte) ([32]byte, error) {
	r.slots = append(r.slots, s)
	return r.r.Word(s)
}

func idOf(s string) uint64 {
	if s == "2^64-1" {
		return ^uint64(0)
	}
	var v uint64
	fmt.Sscan(s, &v)
	return v
}

func indices(name string) []string {
	var out []string
	for _, p := range strings.Split(name, "[")[1:] {
		out = append(out, strings.SplitN(p, "]", 2)[0])
	}
	return out
}

// TestStorageReadVectors runs every storage.read vector through this package's reader over a witness verified against a real state
// root: the reader asks for exactly the vector's slots, the proven words are the vector's words, and the reader accepts or refuses as
// the vector does (the refusal text included).
func TestStorageReadVectors(t *testing.T) {
	w, codes := storageWorld(t)
	f := loadVectors(t, "storage.json")
	n := 0
	for _, v := range f.Vectors {
		if v.Op != "storage.read" {
			continue
		}
		var in struct {
			Account string   `json:"account"`
			Slots   []string `json:"slots"`
		}
		var ex struct {
			Error   string          `json:"error"`
			Words   []string        `json:"words"`
			Decoded json.RawMessage `json:"decoded"`
		}
		require.NoError(t, json.Unmarshal(v.Input, &in), v.Name)
		require.NoError(t, json.Unmarshal(v.Expect, &ex), v.Name)
		a := addr(t, in.Account)
		var slots [][32]byte
		for _, s := range in.Slots {
			slots = append(slots, word(t, s))
		}
		raw, err := evmstate.BuildAccounts(context.Background(), w, [][20]byte{a}, func(rs []evmstate.SlotReader) error {
			for _, s := range slots {
				if _, err := rs[0].Word(s); err != nil {
					return err
				}
			}
			return nil
		})
		require.NoError(t, err, v.Name)
		accs, err := evmstate.VerifyAccounts(raw, w.Root(), a)
		require.NoError(t, err, v.Name)
		require.Equal(t, codes[a], accs[0].CodeHash())
		for i, s := range slots {
			got, err := accs[0].Word(s)
			require.NoError(t, err)
			require.Equal(t, word(t, ex.Words[i]), got, "%s: proven word %d", v.Name, i)
		}
		rec := &recording{r: accs[0]}
		r := Reader{rec}
		name := strings.TrimPrefix(strings.TrimPrefix(v.Name, "vr "), "liability ")
		var got any
		switch {
		case name == "network" || name == "openOutput" || name == "lastAcked" || name == "pendingPair":
			k := map[string]uint64{"network": vrschema.SlotNetwork, "openOutput": vrschema.SlotOpenOutput, "lastAcked": vrschema.SlotLastAcked,
				"pendingPair": vrschema.SlotPendingPair}[name]
			x, e := r.Scalar(k)
			got, err = fmt.Sprintf("0x%x", x), e
		case name == "committeeLimits":
			got, err = r.CommitteeLimits()
		case name == "status":
			got, err = r.Status()
		case strings.HasPrefix(name, "outputs[R]"):
			_, ps, e := w.Proof(context.Background(), a, [][32]byte{vrschema.VRSlot(vrschema.SlotOpenOutput)})
			require.NoError(t, e)
			got, err = r.Output(ps[0].Value) // R is VR's open output in the scenario
		case strings.HasPrefix(name, "changePayload["):
			got, err = r.Bytes(vrschema.ChangePayloadSlot(idOf(indices(name)[0])), vrschema.MaxChangePayload)
			if err == nil {
				got = fmt.Sprintf("0x%x", got)
			}
		case strings.HasPrefix(name, "activations["):
			got, err = r.Activation(uint32(idOf(indices(name)[0])))
		case strings.HasPrefix(name, "holders["):
			got, err = r.Holder(uint8(idOf(indices(name)[0])))
		case strings.HasPrefix(name, "retired["):
			ix := indices(name)
			got, err = r.Retired(uint8(idOf(ix[0])), idOf(ix[1]), idOf(ix[2]))
		case name == "cursor":
			cw, e := rec.Word(vrschema.LiabilityCursorSlot())
			require.NoError(t, e)
			got, err = vrschema.DecodeLiabilityCursor(cw)
		case strings.HasPrefix(name, "facts["):
			ix := indices(name)
			id, gen := idOf(ix[0]), idOf(ix[1])
			var fw [2]vrschema.Word
			for j := range fw {
				fw[j], _ = rec.Word(vrschema.LiabilityFactsSlot(id, gen, uint64(j)))
			}
			got, err = vrschema.DecodeLiabilityFacts(fw)
		default:
			// outputs[N], outputs[unknown], changes[..], counters, fees, hookLimits, activeModule: the words alone (checked above)
			continue
		}
		n++
		require.Equal(t, slots, rec.slots, "%s: the reader asks for exactly the vector's slots", v.Name)
		if ex.Error != "" {
			require.Error(t, err, v.Name)
			require.Contains(t, err.Error(), ex.Error, v.Name)
			continue
		}
		require.NoError(t, err, v.Name)
		switch d := got.(type) {
		case string:
			var want string
			require.NoError(t, json.Unmarshal(ex.Decoded, &want))
			require.Equal(t, want, d, v.Name)
		case bool:
			var want bool
			require.NoError(t, json.Unmarshal(ex.Decoded, &want))
			require.Equal(t, want, d, v.Name)
		case uint64:
			var want uint64
			require.NoError(t, json.Unmarshal(ex.Decoded, &want))
			require.Equal(t, want, d, v.Name)
		case vrschema.Status, vrschema.CommitteeLimits:
			b, _ := json.Marshal(d)
			require.JSONEq(t, string(ex.Decoded), string(b), v.Name)
		case vrschema.LiabilityFacts:
			var want struct {
				Requested bool   `json:"requested"`
				Live      uint32 `json:"liveExposures"`
				Lots      uint32 `json:"lotReferences"`
				Anchor    string `json:"maxLiabilityAnchor"`
				RefDigest string `json:"refDigest"`
			}
			require.NoError(t, json.Unmarshal(ex.Decoded, &want))
			require.Equal(t, want.Requested, d.Requested, v.Name)
			require.Equal(t, want.Live, d.LiveExposures, v.Name)
			require.Equal(t, want.Lots, d.LotReferences, v.Name)
			require.Equal(t, want.Anchor, fmt.Sprint(d.MaxLiabilityAnchor), v.Name)
			require.Equal(t, want.RefDigest, fmt.Sprintf("0x%x", d.RefDigest), v.Name)
		case vrschema.OutputRecord:
			var want map[string]any
			require.NoError(t, json.Unmarshal(ex.Decoded, &want))
			require.Equal(t, want["state"], vrschema.OutputStateNames[d.State], v.Name)
			require.Equal(t, want["attempt"], fmt.Sprint(d.Attempt), v.Name)
			require.Equal(t, want["outputCommit"], fmt.Sprintf("0x%x", d.OutputCommit), v.Name)
			require.Equal(t, want["membersDigest"], fmt.Sprintf("0x%x", d.MembersDigest), v.Name)
		case vrschema.Activation:
			var want map[string]any
			require.NoError(t, json.Unmarshal(ex.Decoded, &want))
			require.EqualValues(t, want["changeId"], d.ChangeID, v.Name)
			require.Equal(t, want["releaseDigest"], fmt.Sprintf("0x%x", d.ReleaseDigest), v.Name)
		case vrschema.Holder:
			var want map[string]any
			require.NoError(t, json.Unmarshal(ex.Decoded, &want))
			require.Equal(t, want["codeHash"], fmt.Sprintf("0x%x", d.CodeHash), v.Name)
			require.Equal(t, want["holder"], fmt.Sprintf("0x%x", d.Holder), v.Name)
		default:
			t.Fatalf("%s: unchecked type %T", v.Name, got)
		}
	}
	require.GreaterOrEqual(t, n, 20, "most storage.read vectors are judged through the reader")
	t.Logf("%d storage.read vectors judged through the reader", n)
}

// TestChangeReadsVerifiedPayload: Change returns the record with its payload bytes, verified by length and payloadHash.
func TestChangeReadsVerifiedPayload(t *testing.T) {
	w, _ := storageWorld(t)
	raw, err := evmstate.BuildAccounts(context.Background(), w, [][20]byte{vrschema.ValidatorRegistry}, func(rs []evmstate.SlotReader) error {
		_, _, err := Reader{rs[0]}.Change(3)
		return err
	})
	require.NoError(t, err)
	accs, err := evmstate.VerifyAccounts(raw, w.Root(), vrschema.ValidatorRegistry)
	require.NoError(t, err)
	c, payload, err := Reader{accs[0]}.Change(3)
	require.NoError(t, err)
	require.Equal(t, vrschema.ChBound, c.State)
	require.Len(t, payload, int(c.PayloadLength))
	require.Equal(t, c.PayloadHash, vrschema.PayloadHash(payload))
	require.NoError(t, accs[0].Unused())
}
