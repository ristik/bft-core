package bridgeprofile

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-core/b1ref/b1gen"
	"github.com/unicitynetwork/bft-core/b1ref/tokenvec"
)

// The token-level harness (b1ref/tokenvec) through this package's protocol-4 projection: a real lock-backed return token whose
// leaves lie in the scenario's anchor shards, the RSMT root of each anchor's shard round, the envelope (policy body, history, anchor
// table, leaf paths), and Compose over it. Compose runs everything a vault's verifier runs (framing, policy, the kernel, anchor
// planning, the gate, IR openings and reference times, 0x0102 membership), and its CERT_BATCH_V2 request is the one tokenvec.Check
// then holds to the scenario's anchors, b1ref's verdict on the TokenWorld registry, and the scenario's grouping.

// tvProjection is the Go bridge projection under tokenvec.Check. times gives leaf i's reference time.
type tvProjection struct {
	f      *Fixture
	times  func(s tokenvec.Scenario, i int) uint64
	tokens map[string]*tvToken
	runs   map[string]*tvRun
}

type tvToken struct {
	h     *History
	res   *Result
	trees []*rnode
}

type tvRun struct {
	envelope []byte
	res      *Result
	gate     Gate
	request  []byte
}

// tvAmount and tvRecipient are the locked value and the return's release address of every harness token.
var (
	tvAmount    = big.NewInt(1_000_000_007)
	tvRecipient = [20]byte{0xAA, 19: 0x01}
)

func newTVProjection() *tvProjection {
	return &tvProjection{f: NewFixture(1337, 1, H([]byte("tokenvec-agg-conf"))), tokens: map[string]*tvToken{}, runs: map[string]*tvRun{},
		// each leaf is certified just after its own reference time
		times: func(s tokenvec.Scenario, i int) uint64 { return b1gen.IRTime(s.Anchors[i].Round) - 1 }}
}

// shardBytes is the shard identifier of a bit string: its bits, a terminating 1 bit, zero padding.
func shardBytes(bits string) []byte {
	out := make([]byte, len(bits)/8+1)
	for i, c := range bits {
		if c == '1' {
			out[i/8] |= 0x80 >> uint(i%8)
		}
	}
	out[len(bits)/8] |= 0x80 >> uint(len(bits)%8)
	return out
}

// inPrefix forces a key's leading bits to a shard's bit string.
func inPrefix(k [32]byte, bits string) [32]byte {
	for i, c := range bits {
		m := byte(0x80 >> uint(i%8))
		if c == '1' {
			k[i/8] |= m
		} else {
			k[i/8] &^= m
		}
	}
	return k
}

// token builds the return history whose leaf i lies in anchor i's shard: the mint leaf's state ID follows the nonce, and leaf i > 0
// follows its source owner key, keys[i-1], so each is searched in turn without moving an earlier leaf. The seed is the shard list and
// the reference times, so two scenarios over the same shards and times get the same token.
func (p *tvProjection) token(s tokenvec.Scenario) (*tvToken, error) {
	n := len(s.Anchors)
	if n < 2 {
		return nil, fmt.Errorf("%s: a return history has at least the mint and the burn leaf", s.ID)
	}
	shards := make([]string, n)
	times := make([]string, n)
	for i, a := range s.Anchors {
		shards[i], times[i] = a.Shard, fmt.Sprint(p.times(s, i))
	}
	seed := strings.Join(shards, ",") + "/" + strings.Join(times, ",")
	if t, ok := p.tokens[seed]; ok {
		return t, nil
	}
	keys := make([]*secp256k1.PrivateKey, n-1)
	for i := range keys {
		keys[i] = KeyFromSeed(fmt.Sprintf("tokenvec/%s/key/%d/0", seed, i))
	}
	build := func(nonce uint64) (*History, *Result, error) {
		h, err := p.f.BuildToken(nonce, tvAmount, keys)
		if err != nil {
			return nil, nil, err
		}
		p.f.AppendBurn(h, keys[n-2], tvRecipient, tvAmount)
		h.MintTime = p.times(s, 0)
		for k := range h.Times {
			h.Times[k] = p.times(s, k+1)
		}
		res, err := VerifyReturn(p.f.Cfg, h.Bytes())
		return h, res, err
	}
	in := func(res *Result, i int) bool { return InShard(shardBytes(shards[i]), res.Leaves[i].SID) }
	nonce := uint64(1)
	for ; ; nonce++ {
		_, res, err := build(nonce)
		if err != nil {
			return nil, err
		}
		if in(res, 0) {
			break
		}
		if nonce > 1024 {
			return nil, errors.New("no nonce puts the mint leaf in its shard")
		}
	}
	for i := 1; i < n; i++ {
		for j := 0; ; j++ {
			keys[i-1] = KeyFromSeed(fmt.Sprintf("tokenvec/%s/key/%d/%d", seed, i-1, j))
			_, res, err := build(nonce)
			if err != nil {
				return nil, err
			}
			if in(res, i) {
				break
			}
			if j > 1024 {
				return nil, fmt.Errorf("no key puts leaf %d in its shard", i)
			}
		}
	}
	h, res, err := build(nonce)
	if err != nil {
		return nil, err
	}
	t := &tvToken{h: h, res: res}
	// each anchor's tree: the token's leaf of that anchor and two other leaves of the same shard
	for i, l := range res.Leaves {
		kv := []rsmtKV{{l.SID, l.Value}}
		for k := 0; k < 2; k++ {
			kv = append(kv, rsmtKV{inPrefix(H([]byte(fmt.Sprintf("tokenvec/other/%s/%d/%d", seed, i, k))), shards[i]), H([]byte(fmt.Sprint("other-value-", k)))})
		}
		sort.Slice(kv, func(a, b int) bool { return bytes.Compare(kv[a].key[:], kv[b].key[:]) < 0 })
		t.trees = append(t.trees, rsmtBuild(kv))
	}
	p.tokens[seed] = t
	return t, nil
}

func (p *tvProjection) Roots(s tokenvec.Scenario) ([][32]byte, error) {
	t, err := p.token(s)
	if err != nil {
		return nil, err
	}
	out := make([][32]byte, len(t.trees))
	for i, r := range t.trees {
		out[i] = r.hash
	}
	return out, nil
}

// tvCapture is the B1 boundary of Compose under the harness: anchor authentication records the CERT_BATCH_V2 request Compose
// builds (tokenvec.Check evaluates it with b1ref against the TokenWorld registry), membership is the reference RSMT_MEMBER_V1.
type tvCapture struct{ request []byte }

func (c *tvCapture) AuthenticateAnchors(anchors []Anchor) error {
	c.request = CertBatchRequest(anchors)
	return nil
}

func (c *tvCapture) VerifyMember(root, key, value [32]byte, lp LeafProof) error {
	return RefB1{}.VerifyMember(root, key, value, lp)
}

// envelopeAnchor is the envelope's anchor for a certified TokenWorld anchor.
func envelopeAnchor(a b1gen.Anchor) Anchor {
	sl := int(binary.BigEndian.Uint16(a.Claim[4:6]))
	return Anchor{Partition: a.Partition, Shard: bytes.Clone(a.Claim[6 : 6+sl]), ShardConfHash: a.ShardConf,
		ExpectedStateRoot: a.Spec.StateRoot, ExpectedIRHash: H(a.IR), UC: bytes.Clone(a.UC), InputRecord: bytes.Clone(a.IR)}
}

func (p *tvProjection) Request(s tokenvec.Scenario, anchors []b1gen.Anchor) ([]byte, error) {
	t, err := p.token(s)
	if err != nil {
		return nil, err
	}
	env := &Envelope{PolicyBody: p.f.Policy.Bytes(), History: t.h.Bytes()}
	for i, a := range anchors {
		env.Anchors = append(env.Anchors, envelopeAnchor(a))
		bm, sibs := t.trees[i].proof(t.res.Leaves[i].SID)
		env.LeafProofs = append(env.LeafProofs, LeafProof{AnchorIndex: uint16(i), Bitmap: bm, Siblings: sibs})
	}
	b, err := env.Encode()
	if err != nil {
		return nil, err
	}
	c := &tvCapture{}
	res, err := Compose(p.f.Cfg, OpReturn, b, c)
	if err != nil {
		return nil, fmt.Errorf("compose: %w", err)
	}
	gate, err := GateOf(p.f.Cfg, OpReturn, b)
	if err != nil {
		return nil, fmt.Errorf("gate: %w", err)
	}
	p.runs[s.ID] = &tvRun{envelope: b, res: res, gate: gate, request: c.request}
	return c.request, nil
}

// tvMeasurement is one run's published numbers (acceptance matrix 7e).
type tvMeasurement struct {
	Scenario      string         `json:"scenario"`
	Description   string         `json:"description"`
	Leaves        int            `json:"leaves"`
	HistoryBytes  int            `json:"historyBytes"`
	HistorySHA256 string         `json:"historySha256"`
	EnvelopeBytes int            `json:"envelopeBytes"`
	RequestBytes  int            `json:"requestBytes"`
	RequestSHA256 string         `json:"requestSha256"`
	Grouping      b1ref.Grouping `json:"grouping"`
	NativeCharge  uint64         `json:"nativeCharge"`
	Gate          map[string]any `json:"gate"`
	Nullifier     string         `json:"nullifier"`
}

// tvEnvelope is one run as a projection fixture for the TS and Rust projections: from cfg, op and envelope, a projection must
// reproduce the request, the grouping, the item count and the gate from the kernel's leaves; anchors gives each anchor's TokenWorld
// label.
type tvEnvelope struct {
	Scenario string         `json:"scenario"`
	Op       uint8          `json:"op"`
	Cfg      string         `json:"cfg"`
	Envelope string         `json:"envelope"`
	Request  string         `json:"request"`
	Anchors  []string       `json:"anchors"`
	Grouping b1ref.Grouping `json:"grouping"`
	Gate     map[string]any `json:"gate"`
	Leaves   []tvLeaf       `json:"leaves"`
}

// tvLeaf is one kernel leaf of the run's token, in leaf order: what the kernel exports for planning, time checks and membership.
type tvLeaf struct {
	SID           string `json:"sid"`
	Value         string `json:"value"`
	ReferenceTime uint64 `json:"referenceTime"`
}

const (
	tvMeasurementsFile = "testdata/tokenvec-measurements.json"
	tvEnvelopesFile    = "testdata/tokenvec-envelopes.json"
)

func gateJSON(g Gate) map[string]any {
	return map[string]any{"intrinsic": g.Intrinsic, "items": g.Items, "j": g.J, "b2": g.B2, "batch": g.Batch, "rsmt": g.RSMT,
		"steps": g.Steps, "reserve": GasReserve, "total": g.Total()}
}

// tvGolden compares v with a checked-in file, or rewrites it with BRIDGEPROFILE_TOKENVEC_WRITE=1.
func tvGolden(t *testing.T, file string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	require.NoError(t, err)
	b = append(b, '\n')
	if os.Getenv("BRIDGEPROFILE_TOKENVEC_WRITE") != "" {
		require.NoError(t, os.WriteFile(file, b, 0o644))
		return
	}
	want, err := os.ReadFile(file)
	require.NoError(t, err)
	require.Equal(t, string(want), string(b), "%s changed; regenerate with BRIDGEPROFILE_TOKENVEC_WRITE=1 and review the difference", file)
}

// TestTokenvecThroughTheBridgeProjection: every tokenvec scenario passes tokenvec.Check through the protocol-4 projection (Compose
// accepts the envelope; b1ref accepts Compose's batch on the TokenWorld registry with the scenario's grouping), and so does the
// paired token of TestTokenvecConsolidationPreservesTheToken; the gate's batch term is the reference charge of that same request;
// and the published measurements and projection fixtures are the checked-in files.
func TestTokenvecThroughTheBridgeProjection(t *testing.T) {
	type job struct {
		name string
		s    tokenvec.Scenario
		p    *tvProjection
	}
	var jobs []job
	p := newTVProjection()
	for _, s := range tokenvec.Scenarios {
		jobs = append(jobs, job{s.ID, s, p})
	}
	before := scenario(t, "unconsolidated-eight-seals")
	paired := newTVProjection()
	paired.times = func(_ tokenvec.Scenario, i int) uint64 { return b1gen.IRTime(before.Anchors[i].Round) - 1 }
	jobs = append(jobs, job{"paired/" + before.ID, before, paired}, job{"paired/consolidated-eight-shards", scenario(t, "consolidated-eight-shards"), paired})

	var ms []tvMeasurement
	var envs []tvEnvelope
	for _, j := range jobs {
		t.Run(j.name, func(t *testing.T) {
			rep, err := tokenvec.Check(j.s, j.p)
			require.NoError(t, err)
			run := j.p.runs[j.s.ID]
			require.Equal(t, rep.Request, run.request)
			require.Len(t, run.res.Leaves, len(j.s.Anchors), "one leaf per anchor")
			require.Equal(t, rep.Grouping, run.gate.Grouping, "the gate prices the request Compose built")
			require.Equal(t, rep.Verdict.Gas, run.gate.Batch, "the gate's batch term is the reference charge")
			hist := j.p.tokens[seedOf(j.p, j.s)].h.Bytes()
			ms = append(ms, tvMeasurement{Scenario: j.name, Description: j.s.Description, Leaves: len(run.res.Leaves),
				HistoryBytes: len(hist), HistorySHA256: h32(H(hist)), EnvelopeBytes: len(run.envelope), RequestBytes: len(run.request),
				RequestSHA256: h32(H(run.request)), Grouping: rep.Grouping, NativeCharge: rep.Verdict.Gas, Nullifier: h32(run.res.Nullifier),
				Gate: gateJSON(run.gate)})
			e := tvEnvelope{Scenario: j.name, Op: OpReturn, Cfg: hx(j.p.f.Cfg.Bytes()), Envelope: hx(run.envelope), Request: hx(run.request),
				Grouping: rep.Grouping, Gate: gateJSON(run.gate)}
			for _, a := range j.s.Anchors {
				e.Anchors = append(e.Anchors, fmt.Sprintf("epoch %d round %d shard %q", a.Epoch, a.Round, a.Shard))
			}
			for _, l := range run.res.Leaves {
				e.Leaves = append(e.Leaves, tvLeaf{SID: h32(l.SID), Value: h32(l.Value), ReferenceTime: l.ReferenceTime})
			}
			envs = append(envs, e)
		})
	}
	notes := []string{
		"Generated by bridgeprofile TestTokenvecThroughTheBridgeProjection (BRIDGEPROFILE_TOKENVEC_WRITE=1 rewrites it).",
		"Each run is one lock-backed return token (mint, transfers, burn) whose leaf i is certified by anchor i of the tokenvec scenario; the TokenWorld registry and seals are tokenvec's (seed " + tokenvec.Seed + ").",
		"paired/* is one token proved before and after consolidation (TestTokenvecConsolidationPreservesTheToken): same history bytes and nullifier, different anchors.",
		"Token-level split and merge are not supported by the kernel (TestTokenvecSplitIsUnsupportedByTheKernel): split-* scenarios are multi-epoch and topology-change histories at the anchor level, not executed splits.",
		"nativeCharge is the reference CERT_BATCH_V2 charge (b1ref); gate is the composing verifier's gate for the envelope (protocol 4). Actual transaction gas is measured by the contracts tests, not here.",
	}
	tvGolden(t, tvMeasurementsFile, map[string]any{"format": "bridgeprofile/tokenvec-measurements-v1", "notes": notes, "measurements": ms})
	tvGolden(t, tvEnvelopesFile, map[string]any{"format": "bridgeprofile/tokenvec-envelopes-v1", "notes": notes, "envelopes": envs})
}

func seedOf(p *tvProjection, s tokenvec.Scenario) string {
	shards := make([]string, len(s.Anchors))
	times := make([]string, len(s.Anchors))
	for i, a := range s.Anchors {
		shards[i], times[i] = a.Shard, fmt.Sprint(p.times(s, i))
	}
	return strings.Join(shards, ",") + "/" + strings.Join(times, ",")
}

func scenario(t *testing.T, id string) tokenvec.Scenario {
	for _, s := range tokenvec.Scenarios {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("no scenario %s", id)
	return tokenvec.Scenario{}
}

// TestTokenvecConsolidationPreservesTheToken (acceptance matrix 1c): one token over eight shards, proved unconsolidated (eight seals
// over three epochs) and after consolidation (one seal). Consolidation re-proves the same leaves under later certificates, so the
// token's bytes, leaves (state IDs, transaction hashes, reference times, values) and the kernel outcome (nullifier, release, lock
// digest) are identical; only the anchor table, the paths and the batch differ, and the batch's E/S/Q fall while A stays eight.
func TestTokenvecConsolidationPreservesTheToken(t *testing.T) {
	before, after := scenario(t, "unconsolidated-eight-seals"), scenario(t, "consolidated-eight-shards")
	require.Len(t, after.Anchors, len(before.Anchors))
	for i := range before.Anchors {
		require.Equal(t, before.Anchors[i].Shard, after.Anchors[i].Shard, "the same leaf in the same shard")
	}
	p := newTVProjection()
	// the reference times are the leaves' original certification times, before the earliest anchor of either proof
	p.times = func(_ tokenvec.Scenario, i int) uint64 { return b1gen.IRTime(before.Anchors[i].Round) - 1 }
	rb, err := tokenvec.Check(before, p)
	require.NoError(t, err)
	ra, err := tokenvec.Check(after, p)
	require.NoError(t, err)
	b, a := p.runs[before.ID], p.runs[after.ID]

	require.Len(t, p.tokens, 1, "both proofs carry one token")
	envB, err := DecodeEnvelope(b.envelope)
	require.NoError(t, err)
	envA, err := DecodeEnvelope(a.envelope)
	require.NoError(t, err)
	require.Equal(t, envB.History, envA.History, "the signed transactions and their reference times are byte-identical")
	require.Equal(t, b.res, a.res, "token ID, leaves, nullifier, release and lock digest are unchanged")
	require.NotEqual(t, b.request, a.request, "the anchors differ")

	require.Equal(t, uint64(8), rb.Grouping.A)
	require.Equal(t, uint64(8), ra.Grouping.A, "every leaf still has its own claim")
	require.Equal(t, [2]uint64{3, 1}, [2]uint64{rb.Grouping.E, ra.Grouping.E})
	require.Equal(t, [2]uint64{8, 1}, [2]uint64{rb.Grouping.S, ra.Grouping.S})
	require.Less(t, ra.Grouping.Q, rb.Grouping.Q, "one seal's signatures instead of eight")
	require.Less(t, ra.Verdict.Gas, rb.Verdict.Gas)
	require.Less(t, a.gate.Total(), b.gate.Total())
	t.Logf("before: E/S/Q/A %d/%d/%d/%d charge %d gate %d; after: %d/%d/%d/%d charge %d gate %d",
		rb.Grouping.E, rb.Grouping.S, rb.Grouping.Q, rb.Grouping.A, rb.Verdict.Gas, b.gate.Total(),
		ra.Grouping.E, ra.Grouping.S, ra.Grouping.Q, ra.Grouping.A, ra.Verdict.Gas, a.gate.Total())

	// consolidation is optional: the vault releases once, by whichever proof comes first; the second carries the same nullifier
	require.Equal(t, b.res.Nullifier, a.res.Nullifier)
	require.Equal(t, b.res.Nonce, a.res.Nonce)
}

// SDK 3.0.1 split encodings (@unicitylabs/state-transition-sdk lib/payment): the burn of the source token commits to the split
// manifest tag(39046,[b(root)...]) through its burn predicate and carries the manifest as data (TokenSplit.js); each output token's
// mint reason is tag(39044,[burned source token, [allocation proof...]]) (SplitMintJustification.js).
const (
	sdkTagSplitManifest      = 39046
	sdkTagSplitMintReason    = 39044
	tvSplitAllocationPayload = "allocation-proof"
)

// TestTokenvecSplitIsUnsupportedByTheKernel (acceptance matrix 1b, the kernel's honest result): the bridge kernel has no split. A
// token burned for a split is not a return (its data is the split manifest, not the return reason), and a split output, whose mint
// reason is the SDK's split reason, is not a lock-backed mint, whether presented as a mint or as a return.
func TestTokenvecSplitIsUnsupportedByTheKernel(t *testing.T) {
	f := NewFixture(1337, 1, H([]byte("tokenvec-agg-conf")))
	keys := []*secp256k1.PrivateKey{KeyFromSeed("split-source-0"), KeyFromSeed("split-source-1")}
	src, err := f.BuildToken(11, tvAmount, keys)
	require.NoError(t, err)
	manifest := CTag(sdkTagSplitManifest, CArr(CBytes(sl(H([]byte("split-allocation-root"))))))
	state := src.finalState(f.Cfg)
	require.NoError(t, src.appendTransfer(&state, keys[1], BurnPredicate(H(manifest)), manifest, 1000))
	_, err = VerifyReturn(f.Cfg, src.Bytes())
	require.ErrorIs(t, err, ErrReturnData, "a split burn is not a return")

	// a split output: the lock reason replaced by the SDK split reason over the burned source
	out := []*secp256k1.PrivateKey{KeyFromSeed("split-output-0")}
	child, err := f.BuildToken(12, tvAmount, out)
	require.NoError(t, err)
	child.Mint.Justification = CTag(sdkTagSplitMintReason, CArr(src.Bytes(), CArr(CBytes([]byte(tvSplitAllocationPayload)))))
	require.NoError(t, child.Resign(out))
	_, err = VerifyMint(f.Cfg, child.Bytes())
	require.ErrorIs(t, err, ErrMintJustif, "a split output is not a lock-backed mint")
	f.AppendBurn(child, out[0], tvRecipient, tvAmount)
	_, err = VerifyReturn(f.Cfg, child.Bytes())
	require.ErrorIs(t, err, ErrMintJustif, "nor can it be returned")

	// control: the same child with its lock reason restored is a valid return
	good, err := f.BuildToken(12, tvAmount, out)
	require.NoError(t, err)
	f.AppendBurn(good, out[0], tvRecipient, tvAmount)
	_, err = VerifyReturn(f.Cfg, good.Bytes())
	require.NoError(t, err)
}

// TestTokenvecProjectionRefusals: the projection is not a pass-through. A leaf whose reference time is past its anchor's IR time,
// and an anchor table not in the leaves' shard order, are refused by Compose before any batch is returned to Check.
func TestTokenvecProjectionRefusals(t *testing.T) {
	s := scenario(t, "split-three-epochs")

	late := newTVProjection()
	late.times = func(s tokenvec.Scenario, i int) uint64 { return b1gen.IRTime(s.Anchors[i].Round) + 1 }
	_, err := tokenvec.Check(s, late)
	require.ErrorIs(t, err, ErrIRTime)

	p := newTVProjection()
	roots, err := p.Roots(s)
	require.NoError(t, err)
	specs := append([]b1gen.AnchorSpec(nil), s.Anchors...)
	for i := range specs {
		specs[i].StateRoot = roots[i]
	}
	anchors, err := b1gen.NewTokenWorld(tokenvec.Seed, s.Depth).Certify(specs)
	require.NoError(t, err)
	anchors[0], anchors[1] = anchors[1], anchors[0] // leaf 0 (shard 0) now names the shard-1 anchor
	_, err = p.Request(s, anchors)
	require.ErrorIs(t, err, ErrPolicyLeafIndex)
	require.Nil(t, p.runs[s.ID], "no batch is captured for a refused envelope")
}
