package m2contract

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"testing"

	"github.com/unicitynetwork/bft-core/evmroot"
)

type oracleEncoded struct {
	CBOR     string `json:"cbor"`
	Identity string `json:"identity"`
}
type oracle struct {
	FirstPredecessor                                     string `json:"firstPredecessor"`
	Body, Body2                                          oracleEncoded
	ExecutionConfig, ChangedFeeProfile, ChangedCollector oracleEncoded
	QuorumSubsets                                        [][]string `json:"quorumSubsets"`
}

func fixture(t *testing.T) oracle {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v oracle
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func member(i int) evmroot.Member {
	return evmroot.Member{StakingID: "stake-" + string(rune('0'+i)), NodeID: "node-" + string(rune('0'+i)), ConsensusKey: bytes.Repeat([]byte{byte(2 + i)}, 33), Weight: 1}
}
func history(t *testing.T) TrustHistory {
	t.Helper()
	a := evmroot.V1Anchor{Version: 1, NetworkID: 3, Epoch: 4, HashIncludingSigs: bytes.Repeat([]byte{0xa1}, 32)}
	p, e := evmroot.FirstV2PredecessorHash(a)
	if e != nil {
		t.Fatal(e)
	}
	members := evmroot.WeightSet{member(0), member(1), member(2), member(3)}
	b := evmroot.TrustBaseBodyV2{Version: 2, NetworkID: 3, Epoch: 5, EarliestActivation: 70, Members: members, RootThreshold: 3, StateSummary: bytes.Repeat([]byte{0xc3}, 32), ChangeRecordHash: bytes.Repeat([]byte{0xd4}, 32), PredecessorHash: p}
	id := b.Identity()
	b2 := evmroot.TrustBaseBodyV2{Version: 2, NetworkID: 3, Epoch: 6, EarliestActivation: 160, Members: members, RootThreshold: 3, StateSummary: bytes.Repeat([]byte{0xe5}, 32), ChangeRecordHash: bytes.Repeat([]byte{0xf6}, 32), PredecessorHash: id[:]}
	id2 := b2.Identity()
	return TrustHistory{Anchor: a, AnchorStart: 0, AnchorEnd: 120, Intervals: []TrustInterval{
		{Body: b, Activation: evmroot.ActivatedTrustBase{BodyIdentity: id[:], EpochStart: 120, ActivationCommitID: bytes.Repeat([]byte{0x77}, 32)}, End: 200},
		{Body: b2, Activation: evmroot.ActivatedTrustBase{BodyIdentity: id2[:], EpochStart: 200, ActivationCommitID: bytes.Repeat([]byte{0x88}, 32)}, End: 260},
	}}
}
func TestIndependentTrustVectors(t *testing.T) {
	v, h := fixture(t), history(t)
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	p, _ := evmroot.FirstV2PredecessorHash(h.Anchor)
	if !bytes.Equal(p, unhex(t, v.FirstPredecessor)) {
		t.Fatal("first predecessor")
	}
	for i, want := range []oracleEncoded{v.Body, v.Body2} {
		b := h.Intervals[i].Body
		id := b.Identity()
		if !bytes.Equal(b.Encode(), unhex(t, want.CBOR)) || !bytes.Equal(id[:], unhex(t, want.Identity)) {
			t.Fatalf("body %d differs from independent oracle", i)
		}
	}
	bodyID := h.Intervals[0].Body.Identity()
	for _, subset := range v.QuorumSubsets {
		reached, valid := h.Intervals[0].Body.Members.QuorumReached(subset, 3)
		if !valid || !reached || h.Intervals[0].Body.Identity() != bodyID {
			t.Fatal("quorum subset changed body identity")
		}
	}
	for round, want := range map[uint64]uint64{69: 4, 70: 4, 119: 4, 120: 5, 199: 5, 200: 6, 259: 6} {
		got, e := h.At(round)
		if e != nil || got != want {
			t.Fatalf("round %d: %d, %v", round, got, e)
		}
	}
}
func TestTrustHistoryRefusals(t *testing.T) {
	cases := map[string]func(*TrustHistory){
		"forged predecessor":    func(h *TrustHistory) { h.Intervals[0].Body.PredecessorHash = bytes.Repeat([]byte{9}, 32) },
		"gapped epoch":          func(h *TrustHistory) { h.Intervals[1].Body.Epoch = 7 },
		"reordered predecessor": func(h *TrustHistory) { h.Intervals[1].Body.PredecessorHash = h.Intervals[0].Body.PredecessorHash },
		"wrong network":         func(h *TrustHistory) { h.Intervals[1].Body.NetworkID = 4 },
		"overlap":               func(h *TrustHistory) { h.Intervals[0].End = 201 },
		"gap":                   func(h *TrustHistory) { h.Intervals[0].End = 199 },
		"duplicate key": func(h *TrustHistory) {
			h.Intervals[0].Body.Members[1].ConsensusKey = h.Intervals[0].Body.Members[0].ConsensusKey
		},
		"nonunit weight": func(h *TrustHistory) {
			h.Intervals[0].Body.Members[0].Weight = 2
			h.Intervals[0].Body.RootThreshold = 4
		},
		"earliest as actual":    func(h *TrustHistory) { h.Intervals[0].Activation.EpochStart = 70 },
		"wrong body activation": func(h *TrustHistory) { h.Intervals[0].Activation.BodyIdentity = bytes.Repeat([]byte{7}, 32) },
		"missing commit":        func(h *TrustHistory) { h.Intervals[0].Activation.ActivationCommitID = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := history(t)
			mutate(&h)
			if e := h.Validate(); e == nil {
				t.Fatal("invalid history accepted")
			}
			if _, e := h.At(120); e == nil {
				t.Fatal("invalid history authorized")
			}
		})
	}
}
func TestIndependentExecutionConfigVectors(t *testing.T) {
	v := fixture(t)
	var legacy [32]byte
	copy(legacy[:], bytes.Repeat([]byte{0xb2}, 32))
	var collector [20]byte
	copy(collector[:], bytes.Repeat([]byte{0x12}, 20))
	c := ExecutionConfigV2{LegacyConfigIdentity: legacy, Fee: FeeProfile{30_000_000, 2_000_000, 1_000_000, 2, 8}, Collector: collector}
	check := func(name string, w oracleEncoded) {
		t.Helper()
		b, e := c.Encode()
		if e != nil {
			t.Fatal(e)
		}
		id, e := c.Identity()
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(b, unhex(t, w.CBOR)) || !bytes.Equal(id[:], unhex(t, w.Identity)) {
			t.Fatalf("%s differs from oracle", name)
		}
	}
	check("base", v.ExecutionConfig)
	c.Fee.BaseFeeFloor = 2_000_000
	check("fee", v.ChangedFeeProfile)
	c.Fee.BaseFeeFloor = 1_000_000
	copy(c.Collector[:], bytes.Repeat([]byte{0x34}, 20))
	check("collector", v.ChangedCollector)
	c.Fee.Elasticity = 0
	if _, e := c.Identity(); e == nil {
		t.Fatal("invalid fee profile accepted")
	}
}
func TestVectorGeneratorReproducible(t *testing.T) {
	if _, e := exec.LookPath("python3"); e != nil {
		t.Skip("python3 unavailable")
	}
	cmd := exec.Command("python3", "generate_vectors.py", "--check")
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("generator: %v: %s", e, out)
	}
}
