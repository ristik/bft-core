package m2contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/unicitynetwork/bft-core/evmroot"
)

type oracleEncoded struct {
	CBOR     string `json:"cbor"`
	Identity string `json:"identity"`
}
type oracle struct {
	FirstPredecessor                                              string `json:"firstPredecessor"`
	Body, Body2, Interval, OpenInterval, OpenAnchor, ClosedAnchor oracleEncoded
	ExecutionConfig, ChangedFeeProfile, ChangedCollector          oracleEncoded
	QuorumSubsets                                                 [][]string `json:"quorumSubsets"`
	InputMemberOrder                                              []string   `json:"inputMemberOrder"`
	LegacyFixture                                                 struct {
		ExecutionConfigIdentity string `json:"executionConfigIdentity"`
		GenesisOriginIdentity   string `json:"genesisOriginIdentity"`
	} `json:"legacyFixture"`
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
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func member(i int) evmroot.Member {
	return evmroot.Member{StakingID: "stake-" + string(rune('0'+i)), NodeID: "node-" + string(rune('0'+i)), ConsensusKey: bytes.Repeat([]byte{byte(2 + i)}, 33), Weight: 1}
}
func members() evmroot.WeightSet {
	return evmroot.WeightSet{member(0), member(1), member(2), member(3)}
}
func history(t *testing.T) TrustHistory {
	t.Helper()
	a := evmroot.V1Anchor{Version: 1, NetworkID: 3, Epoch: 4, HashIncludingSigs: bytes.Repeat([]byte{0xa1}, 32)}
	p, err := evmroot.FirstV2PredecessorHash(a)
	if err != nil {
		t.Fatal(err)
	}
	b := evmroot.TrustBaseBodyV2{Version: 2, NetworkID: 3, Epoch: 5, EarliestActivation: 70, Members: members(), RootThreshold: 3, StateSummary: bytes.Repeat([]byte{0xc3}, 32), ChangeRecordHash: bytes.Repeat([]byte{0xd4}, 32), PredecessorHash: p}
	id := b.Identity()
	b2 := evmroot.TrustBaseBodyV2{Version: 2, NetworkID: 3, Epoch: 6, EarliestActivation: 160, Members: members(), RootThreshold: 3, StateSummary: bytes.Repeat([]byte{0xe5}, 32), ChangeRecordHash: bytes.Repeat([]byte{0xf6}, 32), PredecessorHash: id[:]}
	id2 := b2.Identity()
	return TrustHistory{Anchor: a, AnchorStart: 0, AnchorEnd: 120, Intervals: []TrustInterval{
		{Body: b, Activation: evmroot.ActivatedTrustBase{BodyIdentity: id[:], EpochStart: 120, ActivationCommitID: bytes.Repeat([]byte{0x77}, 32)}, End: 200},
		{Body: b2, Activation: evmroot.ActivatedTrustBase{BodyIdentity: id2[:], EpochStart: 200, ActivationCommitID: bytes.Repeat([]byte{0x88}, 32)}, End: 260},
	}}
}

// relink refreshes derived identities after a body mutation. It never repairs
// the field being tested: callers use it only for body/context/epoch mutations.
func relink(h *TrustHistory, from int) {
	for i := from; i < len(h.Intervals); i++ {
		if i > from {
			id := h.Intervals[i-1].Body.Identity()
			h.Intervals[i].Body.PredecessorHash = bytes.Clone(id[:])
		}
		id := h.Intervals[i].Body.Identity()
		h.Intervals[i].Activation.BodyIdentity = bytes.Clone(id[:])
	}
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
	for round, want := range map[uint64]uint64{69: 4, 70: 4, 119: 4, 120: 5, 199: 5, 200: 6, 259: 6} {
		got, err := h.At(round)
		if err != nil || got != want {
			t.Fatalf("round %d: %d, %v", round, got, err)
		}
	}
}
func TestMemberPermutationStable(t *testing.T) {
	v, h := fixture(t), history(t)
	if strings.Join(v.InputMemberOrder, ",") == "node-0,node-1,node-2,node-3" {
		t.Fatal("oracle input was already sorted")
	}
	b := h.Intervals[0].Body
	b.Members = evmroot.WeightSet{member(2), member(0), member(3), member(1)}
	id := b.Identity()
	if !bytes.Equal(b.Encode(), unhex(t, v.Body.CBOR)) || !bytes.Equal(id[:], unhex(t, v.Body.Identity)) {
		t.Fatal("permuted members changed canonical body")
	}
}
func TestV1AnchorEncodingVectors(t *testing.T) {
	v, h := fixture(t), history(t)
	for _, tc := range []struct {
		name string
		end  uint64
		want oracleEncoded
	}{{"open", 0, v.OpenAnchor}, {"closed", 120, v.ClosedAnchor}} {
		t.Run(tc.name, func(t *testing.T) {
			r := V1AnchorRecord{Anchor: h.Anchor, Start: 0, End: tc.end}
			raw, err := r.Encode()
			if err != nil {
				t.Fatal(err)
			}
			id := sha256.Sum256(raw)
			if !bytes.Equal(raw, unhex(t, tc.want.CBOR)) || !bytes.Equal(id[:], unhex(t, tc.want.Identity)) {
				t.Fatal("anchor differs from independent oracle")
			}
		})
	}
	h.Intervals = nil
	h.AnchorEnd = 0
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	if got, err := h.At(1000000); err != nil || got != 4 {
		t.Fatalf("open anchor: %d, %v", got, err)
	}
	h.Intervals = history(t).Intervals
	if err := h.Validate(); !errors.Is(err, ErrAnchor) {
		t.Fatalf("open anchor with successor: %v", err)
	}
}
func TestIntervalEncodingVectors(t *testing.T) {
	v, h := fixture(t), history(t)
	for _, tc := range []struct {
		name string
		in   TrustInterval
		want oracleEncoded
	}{{"finite", h.Intervals[0], v.Interval}, {"open", func() TrustInterval { in := h.Intervals[1]; in.End = 0; return in }(), v.OpenInterval}} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := tc.in.Encode()
			if err != nil {
				t.Fatal(err)
			}
			id := sha256.Sum256(raw)
			if !bytes.Equal(raw, unhex(t, tc.want.CBOR)) || !bytes.Equal(id[:], unhex(t, tc.want.Identity)) {
				t.Fatal("interval encoding differs from oracle")
			}
		})
	}
	h.Intervals[1].End = 0
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	if got, err := h.At(1000000); err != nil || got != 6 {
		t.Fatalf("open interval: %d, %v", got, err)
	}
	h.Intervals[0].End = 0
	if err := h.Validate(); !errors.Is(err, ErrIntervalBounds) {
		t.Fatalf("nonfinal open interval: %v", err)
	}
}
func TestTrustHistoryRefusals(t *testing.T) {
	cases := []struct {
		name   string
		want   error
		detail string
		mutate func(*TrustHistory)
	}{
		{"invalid anchor", ErrAnchor, "", func(h *TrustHistory) { h.Anchor.Version = 0 }},
		{"invalid body version", ErrBody, "version", func(h *TrustHistory) { h.Intervals[0].Body.Version = 3; relink(h, 0) }},
		{"forged predecessor", ErrPredecessor, "", func(h *TrustHistory) { h.Intervals[0].Body.PredecessorHash = bytes.Repeat([]byte{9}, 32); relink(h, 0) }},
		{"gapped epoch", ErrEpochGap, "", func(h *TrustHistory) { h.Intervals[1].Body.Epoch = 7; relink(h, 1) }},
		{"reordered intervals", ErrReordered, "", func(h *TrustHistory) { h.Intervals[0], h.Intervals[1] = h.Intervals[1], h.Intervals[0] }},
		{"wrong body network", ErrContext, "", func(h *TrustHistory) { h.Intervals[0].Body.NetworkID = 4; relink(h, 0) }},
		{"wrong anchor network", ErrContext, "", func(h *TrustHistory) {
			h.Anchor.NetworkID = 4
			p, _ := evmroot.FirstV2PredecessorHash(h.Anchor)
			h.Intervals[0].Body.PredecessorHash = p
			relink(h, 0)
		}},
		{"empty finite interval", ErrIntervalBounds, "", func(h *TrustHistory) { h.Intervals = h.Intervals[:1]; h.Intervals[0].End = 120 }},
		{"overlap", ErrIntervalBounds, "", func(h *TrustHistory) { h.Intervals[0].End = 201 }},
		{"gap", ErrIntervalBounds, "", func(h *TrustHistory) { h.Intervals[0].End = 199 }},
		{"duplicate key", ErrBody, "duplicate", func(h *TrustHistory) {
			h.Intervals[0].Body.Members[1].ConsensusKey = bytes.Clone(h.Intervals[0].Body.Members[0].ConsensusKey)
			relink(h, 0)
		}},
		{"duplicate node", ErrBody, "duplicate NodeID", func(h *TrustHistory) {
			h.Intervals[0].Body.Members[1].NodeID = h.Intervals[0].Body.Members[0].NodeID
			relink(h, 0)
		}},
		{"duplicate staking", ErrBody, "duplicate StakingID", func(h *TrustHistory) {
			h.Intervals[0].Body.Members[1].StakingID = h.Intervals[0].Body.Members[0].StakingID
			relink(h, 0)
		}},
		{"nonunit weight", ErrNonUnitWeight, "", func(h *TrustHistory) {
			h.Intervals[0].Body.Members[0].Weight = 2
			h.Intervals[0].Body.RootThreshold = 4
			relink(h, 0)
		}},
		{"activation before earliest", ErrActivationBeforeEarliest, "", func(h *TrustHistory) { h.AnchorEnd = 60; h.Intervals[0].Activation.EpochStart = 60 }},
		{"wrong body activation", ErrActivationBody, "", func(h *TrustHistory) { h.Intervals[0].Activation.BodyIdentity = bytes.Repeat([]byte{7}, 32) }},
		{"missing commit", ErrMissingCommit, "", func(h *TrustHistory) { h.Intervals[0].Activation.ActivationCommitID = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := history(t)
			tc.mutate(&h)
			err := h.Validate()
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if tc.detail != "" && !strings.Contains(err.Error(), tc.detail) {
				t.Fatalf("missing body reason %q: %v", tc.detail, err)
			}
			if _, err = h.At(120); !errors.Is(err, tc.want) {
				t.Fatalf("lookup want %v, got %v", tc.want, err)
			}
		})
	}
}
func TestOutsideHistory(t *testing.T) {
	h := history(t)
	_, err := h.At(260)
	if !errors.Is(err, ErrRoundOutsideHistory) {
		t.Fatalf("want outside-history error, got %v", err)
	}
}
func TestIndependentExecutionConfigVectors(t *testing.T) {
	v := fixture(t)
	var legacy [32]byte
	copy(legacy[:], unhex(t, v.LegacyFixture.ExecutionConfigIdentity))
	var collector [20]byte
	copy(collector[:], bytes.Repeat([]byte{0x12}, 20))
	c := ExecutionConfigV2{LegacyConfigIdentity: legacy, Fee: FeeProfile{30_000_000, 2_000_000, 1_000_000, 2, 8}, Collector: collector}
	check := func(name string, w oracleEncoded) {
		t.Helper()
		b, err := c.Encode()
		if err != nil {
			t.Fatal(err)
		}
		id, err := c.Identity()
		if err != nil {
			t.Fatal(err)
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
	base := c
	base.Collector = collector
	baseID, err := base.Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*ExecutionConfigV2)
	}{
		{"maxGas", func(x *ExecutionConfigV2) { x.Fee.MaxGas += 2 }},
		{"systemGas", func(x *ExecutionConfigV2) { x.Fee.SystemGas += 2 }},
		{"baseFeeFloor", func(x *ExecutionConfigV2) { x.Fee.BaseFeeFloor++ }},
		{"changeDenominator", func(x *ExecutionConfigV2) { x.Fee.ChangeDenominator++ }},
	} {
		t.Run("changes identity/"+tc.name, func(t *testing.T) {
			changed := base
			tc.mutate(&changed)
			id, err := changed.Identity()
			if err != nil || id == baseID {
				t.Fatalf("fee change did not change identity: %x, %v", id, err)
			}
		})
	}
	if id, err := c.Identity(); err != nil || id == baseID {
		t.Fatalf("collector change did not change identity: %x, %v", id, err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*ExecutionConfigV2)
	}{{"maxGas", func(x *ExecutionConfigV2) { x.Fee.MaxGas = 0 }}, {"systemGas", func(x *ExecutionConfigV2) { x.Fee.SystemGas = 0 }}, {"baseFeeFloor", func(x *ExecutionConfigV2) { x.Fee.BaseFeeFloor = 0 }}, {"elasticity", func(x *ExecutionConfigV2) { x.Fee.Elasticity = 0 }}, {"changeDenominator", func(x *ExecutionConfigV2) { x.Fee.ChangeDenominator = 0 }}} {
		t.Run(tc.name, func(t *testing.T) {
			bad := c
			tc.mutate(&bad)
			_, err := bad.Identity()
			if !errors.Is(err, ErrFeeProfile) {
				t.Fatalf("want fee error, got %v", err)
			}
		})
	}
	bad := c
	bad.LegacyConfigIdentity = [32]byte{}
	_, err = bad.Identity()
	if !errors.Is(err, ErrLegacyConfig) {
		t.Fatalf("want legacy config error, got %v", err)
	}
}
func TestVectorGeneratorReproducible(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	cmd := exec.Command("python3", "generate_vectors.py", "--check")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generator: %v: %s", err, out)
	}
}
