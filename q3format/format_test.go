package q3format

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The vector fixture, mirrored by testdata/generate_vectors.py: the secp256k1 generator multiples G..4G, weights (6,1,1,1).
var vectorKeys = []string{"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
	"02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
	"02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
	"02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"}

func fill(b byte) []byte        { return bytes.Repeat([]byte{b}, 32) }
func arr32(b byte) (a [32]byte) { copy(a[:], fill(b)); return }

const testNetwork = 5

func vectorBody(t *testing.T) BodyV3 {
	t.Helper()
	pred, err := Prior{Network: testNetwork, Epoch: 1, BodyVersion: 1, Identity: fill(0x11)}.Hash()
	require.NoError(t, err)
	var ms evmroot.WeightSet
	for i, w := range []uint64{6, 1, 1, 1} {
		key, err := hex.DecodeString(vectorKeys[i])
		require.NoError(t, err)
		ms = append(ms, evmroot.Member{StakingID: fmt.Sprintf("s%d", i+1), NodeID: fmt.Sprintf("n%d", i+1), ConsensusKey: key, Weight: w})
	}
	return BodyV3{Network: testNetwork, Epoch: 2, EarliestActivation: 20, Members: ms, RootThreshold: 7,
		StateSummary: fill(0x22), ChangeRecordHash: fill(0x33), PredecessorHash: pred, Config: Q3Config(testNetwork, arr32(7))}
}

// signedBody is a valid body whose members have real keys, for the receipt tests.
func signedBody(t *testing.T, weights ...uint64) (BodyV3, map[string]abcrypto.Signer) {
	t.Helper()
	b := vectorBody(t)
	b.Members = nil
	signers := map[string]abcrypto.Signer{}
	var total uint64
	for i, w := range weights {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		key, err := v.MarshalPublicKey()
		require.NoError(t, err)
		id := fmt.Sprintf("n%d", i+1)
		signers[id] = s
		b.Members = append(b.Members, evmroot.Member{StakingID: "s" + id, NodeID: id, ConsensusKey: key, Weight: w})
		total += w
	}
	b.RootThreshold = 2*total/3 + 1
	require.NoError(t, b.Validate())
	return b, signers
}

func TestVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	require.NoError(t, err)
	var want map[string]string
	require.NoError(t, json.Unmarshal(raw, &want))
	b := vectorBody(t)
	h := func(v []byte) string { return hex.EncodeToString(v) }
	id, cfg := b.Identity(), b.Config.Identity()
	ctx := ContextFor(b, 3, arr32(0x44))
	for name, got := range map[string]string{
		"configEncoding":    h(enc(configDomain, b.Config.fields())),
		"configIdentity":    h(cfg[:]),
		"bodyEncoding":      h(b.Encode()),
		"bodyIdentity":      h(id[:]),
		"predecessorFromV1": h(b.PredecessorHash),
		"receiptMessage":    h(ctx.Message("n1")),
		"receiptMessageHash": func() string {
			m := sha256.Sum256(ctx.Message("n1"))
			return h(m[:])
		}(),
	} {
		require.Equal(t, want[name], got, name)
	}
	require.NoError(t, b.Validate())
}

// The V3 body is the V2 field array with the version and the tuple changed: an independent encoder (evmroot's) must agree.
func TestBodyIsTheV2FieldArrayPlusTheTuple(t *testing.T) {
	b := vectorBody(t)
	v2 := evmroot.TrustBaseBodyV2{Version: 2, NetworkID: b.Network, Epoch: b.Epoch, EarliestActivation: b.EarliestActivation,
		Members: b.Members, RootThreshold: b.RootThreshold, StateSummary: b.StateSummary, ChangeRecordHash: b.ChangeRecordHash, PredecessorHash: b.PredecessorHash}
	var fields []any
	require.NoError(t, types.Cbor.Unmarshal(v2.Encode(), &fields))
	require.Len(t, fields, 9)
	fields[0] = uint64(BodyVersion)
	fields = append(fields, b.Config.fields())
	require.Equal(t, enc(bodyDomain, fields), b.Encode())
	reordered := b
	reordered.Members = evmroot.WeightSet{b.Members[3], b.Members[1], b.Members[0], b.Members[2]}
	require.Equal(t, b.Encode(), reordered.Encode(), "members are sorted like V2")
}

func TestConfigIsExactlyTheQ3Tuple(t *testing.T) {
	g := arr32(7)
	require.NoError(t, Q3Config(5, g).Validate(), "acceptance control")
	for name, mutate := range map[string]func(*ProtocolConfig){
		"revision":         func(c *ProtocolConfig) { c.Revision = 1 },
		"signingScheme":    func(c *ProtocolConfig) { c.SigningScheme = 1 },
		"voteCodec":        func(c *ProtocolConfig) { c.VoteCodec = 1 },
		"quorumProfile":    func(c *ProtocolConfig) { c.QuorumProfile = "D2" },
		"leaderPolicy":     func(c *ProtocolConfig) { c.LeaderPolicy = "legacy" },
		"evmRequestPolicy": func(c *ProtocolConfig) { c.EVMRequestPolicy = "unit-v1" },
		"aggregatorPolicy": func(c *ProtocolConfig) { c.AggregatorPolicy = "weighted-v1" },
	} {
		c := Q3Config(5, g)
		mutate(&c)
		err := c.Validate()
		require.ErrorIs(t, err, ErrConfig, name)
		require.ErrorContains(t, err, name)
	}
	require.ErrorIs(t, Q3Config(0, g).Validate(), ErrConfig)
	require.ErrorIs(t, Q3Config(5, [32]byte{}).Validate(), ErrConfig)
}

func TestBodyIdentityBindsEveryField(t *testing.T) {
	base := vectorBody(t)
	id := base.Identity()
	other := func(mutate func(*BodyV3)) [32]byte {
		b := base
		b.Members = append(evmroot.WeightSet(nil), base.Members...)
		mutate(&b)
		return b.Identity()
	}
	for name, mutate := range map[string]func(*BodyV3){
		"network":     func(b *BodyV3) { b.Network++ },
		"epoch":       func(b *BodyV3) { b.Epoch++ },
		"aMin":        func(b *BodyV3) { b.EarliestActivation++ },
		"weight":      func(b *BodyV3) { b.Members[1].Weight = 2 },
		"key":         func(b *BodyV3) { b.Members[1].ConsensusKey = base.Members[2].ConsensusKey },
		"stakingID":   func(b *BodyV3) { b.Members[1].StakingID = "x" },
		"threshold":   func(b *BodyV3) { b.RootThreshold++ },
		"summary":     func(b *BodyV3) { b.StateSummary = fill(1) },
		"change":      func(b *BodyV3) { b.ChangeRecordHash = nil },
		"predecessor": func(b *BodyV3) { b.PredecessorHash = fill(1) },
		"tuple":       func(b *BodyV3) { b.Config.Genesis = arr32(8) },
	} {
		require.NotEqual(t, id, other(mutate), name)
	}
}

func TestDecodeBody(t *testing.T) {
	b := vectorBody(t)
	raw := b.Encode()
	got, err := DecodeBody(raw)
	require.NoError(t, err)
	require.Equal(t, raw, got.Encode())
	require.Equal(t, b.Identity(), got.Identity())

	t.Run("noncanonical", func(t *testing.T) {
		// the epoch 2 as the two-byte form 0x1802
		i := bytes.Index(raw, []byte{0x05, 0x02, 0x14})
		require.Positive(t, i)
		long := append(append(append([]byte{}, raw[:i+1]...), 0x18, 0x02), raw[i+2:]...)
		_, err := DecodeBody(long)
		require.ErrorIs(t, err, ErrFormat)
	})
	t.Run("trailing byte and truncation", func(t *testing.T) {
		_, err := DecodeBody(append(append([]byte{}, raw...), 0))
		require.ErrorIs(t, err, ErrFormat)
		for _, n := range []int{0, 1, len(raw) / 2, len(raw) - 1} {
			_, err := DecodeBody(raw[:n])
			require.ErrorIs(t, err, ErrFormat, "%d bytes", n)
		}
	})
	t.Run("oversize is refused before decoding", func(t *testing.T) {
		_, err := DecodeBody(make([]byte, maxBodyLen+1))
		require.ErrorIs(t, err, ErrTooLarge)
	})
	t.Run("unknown domain and version", func(t *testing.T) {
		_, err := DecodeBody(enc("UNICITY_TRUSTBASE_V4", b.fields()))
		require.ErrorIs(t, err, ErrVersion)
		f := b.fields()
		f[0] = uint64(4)
		_, err = DecodeBody(enc(bodyDomain, f))
		require.ErrorIs(t, err, ErrVersion)
	})
	t.Run("empty optional is not null", func(t *testing.T) {
		f := b.fields()
		f[6] = []byte{}
		_, err := DecodeBody(enc(bodyDomain, f))
		require.ErrorIs(t, err, ErrFormat)
	})
	t.Run("unordered members", func(t *testing.T) {
		f := b.fields()
		m := f[4].([]any)
		m[0], m[1] = m[1], m[0]
		_, err := DecodeBody(enc(bodyDomain, f))
		require.ErrorIs(t, err, ErrFormat)
	})
	t.Run("too many members", func(t *testing.T) {
		f := b.fields()
		f[4] = make([]any, MaxMembers+1)
		_, err := DecodeBody(enc(bodyDomain, f))
		require.ErrorIs(t, err, ErrTooLarge)
	})
	t.Run("wrong field kind and arity", func(t *testing.T) {
		f := b.fields()
		f[1] = "5"
		_, err := DecodeBody(enc(bodyDomain, f))
		require.ErrorIs(t, err, ErrFormat)
		_, err = DecodeBody(enc(bodyDomain, f[:9]))
		require.ErrorIs(t, err, ErrFormat)
		_, err = DecodeBody(enc(bodyDomain, b.fields(), uint64(1)))
		require.ErrorIs(t, err, ErrFormat)
	})
}

func TestBodyValidation(t *testing.T) {
	b := vectorBody(t)
	require.NoError(t, b.Validate(), "acceptance control")
	mutate := func(f func(*BodyV3)) BodyV3 {
		c := b
		c.Members = append(evmroot.WeightSet(nil), b.Members...)
		f(&c)
		return c
	}
	for name, tc := range map[string]struct {
		body BodyV3
		want error
	}{
		"epoch 1":                             {mutate(func(c *BodyV3) { c.Epoch = 1 }), ErrBody},
		"no A_min":                            {mutate(func(c *BodyV3) { c.EarliestActivation = 0 }), ErrBody},
		"short predecessor":                   {mutate(func(c *BodyV3) { c.PredecessorHash = fill(1)[:31] }), ErrBody},
		"tuple network":                       {mutate(func(c *BodyV3) { c.Config = Q3Config(6, arr32(7)) }), ErrBody},
		"tuple value":                         {mutate(func(c *BodyV3) { c.Config.SigningScheme = 1 }), ErrConfig},
		"threshold low":                       {mutate(func(c *BodyV3) { c.RootThreshold = 6 }), ErrBody},
		"threshold high":                      {mutate(func(c *BodyV3) { c.RootThreshold = 8 }), ErrBody},
		"zero weight":                         {mutate(func(c *BodyV3) { c.Members[1].Weight = 0; c.RootThreshold = 6 }), ErrBody},
		"weight above cap":                    {mutate(func(c *BodyV3) { c.Members[0].Weight = evmroot.MaxMemberWeight + 1 }), ErrBody},
		"total above B, each member in range": {mutate(func(c *BodyV3) { c.Members[0].Weight = evmroot.MaxTotalWeight }), ErrBody},
		"duplicate key":                       {mutate(func(c *BodyV3) { c.Members[1].ConsensusKey = c.Members[2].ConsensusKey }), ErrBody},
		"key off the curve":                   {mutate(func(c *BodyV3) { c.Members[1].ConsensusKey = append([]byte{2}, fill(0xff)...) }), ErrBody},
		"empty members":                       {mutate(func(c *BodyV3) { c.Members = nil }), ErrBody},
		"too many members":                    {mutate(func(c *BodyV3) { c.Members = make(evmroot.WeightSet, MaxMembers+1) }), ErrTooLarge},
		"duplicate node id":                   {mutate(func(c *BodyV3) { c.Members[1].NodeID = c.Members[0].NodeID }), ErrBody},
		"duplicate staking id":                {mutate(func(c *BodyV3) { c.Members[1].StakingID = c.Members[0].StakingID }), ErrBody},
	} {
		require.ErrorIs(t, tc.body.Validate(), tc.want, name)
	}
}

func TestBodyKeyMustBeOnTheCurve(t *testing.T) {
	b := vectorBody(t)
	b.Members = append(evmroot.WeightSet(nil), b.Members...)
	b.Members[1].ConsensusKey = append([]byte{2}, fill(0xff)...) // 33 bytes, x is not a field element
	err := b.Validate()
	require.ErrorIs(t, err, ErrBody)
	require.ErrorContains(t, err, "signing key is invalid", "refused by the go-base key check behind weightvalidation")
}

func TestDecodeBodyValidatesWhatItDecodes(t *testing.T) {
	b := vectorBody(t)
	b.RootThreshold = 8
	_, err := DecodeBody(b.Encode()) // canonical, but not a valid body
	require.ErrorIs(t, err, ErrBody)
	b = vectorBody(t)
	b.Config.SigningScheme = 1
	_, err = DecodeBody(b.Encode())
	require.ErrorIs(t, err, ErrConfig)
	b = vectorBody(t)
	b.ChangeRecordHash = nil // a null optional field decodes and re-encodes to the same bytes
	got, err := DecodeBody(b.Encode())
	require.NoError(t, err)
	require.Empty(t, got.ChangeRecordHash)
	f := vectorBody(t).fields()
	tuple := f[9].([]any)
	for _, bad := range [][]any{tuple[:7], append(append([]any{}, tuple...), uint64(0))} { // seven and nine fields
		f[9] = bad
		_, err = DecodeBody(enc(bodyDomain, f))
		require.ErrorIs(t, err, ErrFormat)
	}
}

func TestPredecessorCodec(t *testing.T) {
	id := fill(0x11)
	v1, err := Prior{Network: 5, Epoch: 1, BodyVersion: 1, Identity: id}.Hash()
	require.NoError(t, err)
	v3, err := Prior{Network: 5, Epoch: 2, BodyVersion: 3, Identity: id}.Hash()
	require.NoError(t, err)
	require.Equal(t, id, v3, "a V3 prior is named directly")
	require.NotEqual(t, id, v1)
	require.Equal(t, v1, func() []byte {
		h := sha256.Sum256(enc("UNICITY_TRUSTBASE_TO_V3", uint64(5), uint64(1), uint64(1), id))
		return h[:]
	}())
	other, err := Prior{Network: 6, Epoch: 1, BodyVersion: 1, Identity: id}.Hash()
	require.NoError(t, err)
	require.NotEqual(t, v1, other)
	for name, p := range map[string]Prior{
		"network 0": {0, 1, 1, id}, "epoch 0": {5, 0, 1, id}, "version 0": {5, 1, 0, id}, "version 2": {5, 1, 2, id}, "version 4": {5, 1, 4, id},
		"short identity": {5, 1, 1, id[:31]}, "long identity": {5, 1, 3, append(id, 0)},
	} {
		_, err := p.Hash()
		require.ErrorIs(t, err, ErrPrior, name)
	}
}

func TestVersionCodec(t *testing.T) {
	b := vectorBody(t)
	v, err := Version(b.Encode())
	require.NoError(t, err)
	require.Equal(t, uint64(3), v)
	v2 := evmroot.TrustBaseBodyV2{Version: 2, NetworkID: 5, Epoch: 2, EarliestActivation: 20, Members: b.Members, RootThreshold: 7, PredecessorHash: fill(1)}
	_, err = Version(v2.Encode())
	require.ErrorIs(t, err, ErrVersion, "a V2 field array is not a body of this deployment")
	_, err = Version(enc("UNICITY_TRUSTBASE_V4", b.fields()))
	require.ErrorIs(t, err, ErrVersion)
	_, err = Version(enc(uint64(1), uint64(2)))
	require.ErrorIs(t, err, ErrVersion)
	_, err = Version([]byte{0xff, 0x00})
	require.ErrorIs(t, err, ErrFormat)
	_, err = DecodeBody(v2.Encode())
	require.ErrorIs(t, err, ErrVersion, "a V2 body is not a V3 body")
}

func receiptsFor(t *testing.T, ctx ReceiptContext, signers map[string]abcrypto.Signer, ids ...string) []Receipt {
	t.Helper()
	var out []Receipt
	for _, id := range ids {
		r, err := SignReceipt(ctx, id, signers[id])
		require.NoError(t, err)
		out = append(out, r)
	}
	return out
}

func TestReceipts(t *testing.T) {
	b, signers := signedBody(t, 6, 1, 1, 1)
	ctx := ContextFor(b, 3, arr32(0x44))
	all := receiptsFor(t, ctx, signers, "n1", "n2", "n3", "n4")
	require.NoError(t, VerifyReceipts(b, ctx, all), "acceptance control")

	t.Run("omitted", func(t *testing.T) {
		require.ErrorIs(t, VerifyReceipts(b, ctx, all[:3]), ErrReceiptMissing)
		require.ErrorIs(t, VerifyReceipts(b, ctx, nil), ErrReceiptMissing)
	})
	t.Run("duplicate", func(t *testing.T) {
		require.ErrorIs(t, VerifyReceipts(b, ctx, append(append([]Receipt{}, all...), all[0])), ErrReceiptDuplicate)
	})
	t.Run("unknown signer", func(t *testing.T) {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		extra, err := SignReceipt(ctx, "zz", s)
		require.NoError(t, err)
		require.ErrorIs(t, VerifyReceipts(b, ctx, append(append([]Receipt{}, all...), extra)), ErrReceiptUnknown)
	})
	t.Run("another member's key", func(t *testing.T) {
		forged, err := SignReceipt(ctx, "n2", signers["n3"])
		require.NoError(t, err)
		require.ErrorIs(t, VerifyReceipts(b, ctx, []Receipt{all[0], forged, all[2], all[3]}), ErrReceiptSignature)
		bad := append([]Receipt{}, all...)
		bad[1].Signature = nil
		require.ErrorIs(t, VerifyReceipts(b, ctx, bad), ErrReceiptSignature)
	})
	// a receipt signed for another chain, handoff or tuple never counts, one substituted field at a time
	for name, mutate := range map[string]func(*ReceiptContext){
		"network":     func(c *ReceiptContext) { c.Network++ },
		"genesis":     func(c *ReceiptContext) { c.Genesis = arr32(9) },
		"predecessor": func(c *ReceiptContext) { c.Predecessor = arr32(9) },
		"body":        func(c *ReceiptContext) { c.BodyID = arr32(9) },
		"tuple":       func(c *ReceiptContext) { c.Config = arr32(9) },
	} {
		t.Run("context "+name, func(t *testing.T) {
			other := ctx
			mutate(&other)
			require.ErrorIs(t, VerifyReceipts(b, other, receiptsFor(t, other, signers, "n1", "n2", "n3", "n4")), ErrReceiptContext)
		})
	}
	for name, mutate := range map[string]func(*ReceiptContext){
		"attempt":   func(c *ReceiptContext) { c.Attempt++ },
		"candidate": func(c *ReceiptContext) { c.CandidateDigest = arr32(9) },
	} {
		t.Run("replay "+name, func(t *testing.T) {
			other := ctx
			mutate(&other)
			require.NoError(t, VerifyReceipts(b, other, receiptsFor(t, other, signers, "n1", "n2", "n3", "n4")), "its own receipts verify")
			require.ErrorIs(t, VerifyReceipts(b, other, all), ErrReceiptSignature, "the other handoff's do not")
		})
	}
	t.Run("invalid body", func(t *testing.T) {
		bad := b
		bad.RootThreshold++
		require.ErrorIs(t, VerifyReceipts(bad, ContextFor(bad, 3, arr32(0x44)), all), ErrBody)
	})
	t.Run("named for the member", func(t *testing.T) {
		require.NotEqual(t, ctx.Message("n1"), ctx.Message("n2"))
		moved := Receipt{NodeID: "n2", Signature: all[0].Signature}
		require.ErrorIs(t, VerifyReceipts(b, ctx, []Receipt{all[0], moved, all[2], all[3]}), ErrReceiptSignature)
	})
}

func TestReceiptCodec(t *testing.T) {
	b, signers := signedBody(t, 6, 1, 1, 1)
	ctx := ContextFor(b, 3, arr32(0x44))
	all := receiptsFor(t, ctx, signers, "n1", "n2", "n3", "n4")
	r, err := newReader([]any{receiptItems(all)}, 1)
	require.NoError(t, err)
	got, err := readReceipts(r)
	require.NoError(t, err)
	require.Equal(t, all, got)
	unordered := []any{receiptItems([]Receipt{all[1], all[0]})}
	r, _ = newReader(unordered, 1)
	_, err = readReceipts(r)
	require.ErrorIs(t, err, ErrFormat)
	r, _ = newReader([]any{make([]any, MaxMembers+1)}, 1)
	_, err = readReceipts(r)
	require.ErrorIs(t, err, ErrTooLarge)
	for _, entry := range []any{[]any{"n1"}, []any{"n1", []byte{1}, []byte{2}}} {
		r, _ = newReader([]any{[]any{entry}}, 1)
		_, err = readReceipts(r)
		require.ErrorIs(t, err, ErrFormat)
	}
	r, _ = newReader([]any{[]any{[]any{"n1", make([]byte, maxSignature+1)}}}, 1)
	_, err = readReceipts(r)
	require.ErrorIs(t, err, ErrTooLarge)
}

func TestStrictDecoding(t *testing.T) {
	_, err := parse(enc(uint64(1)), 64)
	require.NoError(t, err, "acceptance control")
	for name, raw := range map[string][]byte{
		"tag":                {0xc1, 0x81, 0x01},
		"indefinite array":   {0x9f, 0x01, 0xff},
		"map":                {0xa1, 0x01, 0x02},
		"not an array":       {0x01},
		"empty":              nil,
		"truncated":          {0x82, 0x01},
		"trailing":           {0x81, 0x01, 0x00},
		"long head":          {0x81, 0x18, 0x01},
		"deep nesting":       append(bytes.Repeat([]byte{0x81}, 40), 0x01),
		"nested tag":         {0x81, 0xd8, 0x64, 0x01},
		"undefined as value": {0x81, 0xf7},
	} {
		_, err := parse(raw, 64)
		require.ErrorIs(t, err, ErrFormat, name)
	}
	_, err = parse(enc(make([]byte, 100)), 64)
	require.ErrorIs(t, err, ErrTooLarge)

	for name, tc := range map[string]struct {
		items []any
		read  func(*reader)
	}{
		"negative integer": {[]any{int64(-1)}, func(r *reader) { r.uint() }},
		"float":            {[]any{1.5}, func(r *reader) { r.uint() }},
		"bytes as text":    {[]any{[]byte{1}}, func(r *reader) { r.text(8) }},
		"text as bytes":    {[]any{"a"}, func(r *reader) { r.bytes(-1, 8) }},
		"short fixed":      {[]any{[]byte{1}}, func(r *reader) { r.bytes(2, 0) }},
		"null as bytes":    {[]any{nil}, func(r *reader) { r.bytes(-1, 8) }},
		"non-array nested": {[]any{uint64(1)}, func(r *reader) { r.array(8) }},
		"wrong arity":      {[]any{[]any{uint64(1)}}, func(r *reader) { r.sub(2) }},
		"nothing left":     {nil, func(r *reader) { r.uint() }},
	} {
		r, err := newReader(tc.items, -1)
		require.NoError(t, err)
		tc.read(r)
		require.ErrorIs(t, r.done(), ErrFormat, name)
	}
	r, _ := newReader([]any{"x"}, -1)
	r.expect("y")
	require.ErrorIs(t, r.done(), ErrVersion)
	r, _ = newReader([]any{"abcdef"}, -1)
	r.text(3)
	require.ErrorIs(t, r.done(), ErrTooLarge)
	r, _ = newReader([]any{[]byte{1, 2, 3}}, -1)
	r.optBytes(2)
	require.ErrorIs(t, r.done(), ErrTooLarge)
	r, _ = newReader([]any{nil, uint64(1)}, -1)
	require.Nil(t, r.optBytes(2))
	require.ErrorIs(t, r.done(), ErrFormat, "a trailing item is refused")
	_, err = newReader(uint64(1), -1)
	require.ErrorIs(t, err, ErrFormat)
	_, err = newReader([]any{uint64(1)}, 2)
	require.ErrorIs(t, err, ErrFormat)
}

func TestValidSignature(t *testing.T) {
	b, signers := signedBody(t, 1, 1)
	msg := []byte("m")
	sig, err := signers["n1"].SignBytes(msg)
	require.NoError(t, err)
	require.True(t, validSignature(b.Members[0].ConsensusKey, msg, sig))
	require.False(t, validSignature(b.Members[1].ConsensusKey, msg, sig))
	require.False(t, validSignature([]byte{1}, msg, sig), "a malformed key verifies nothing")
}
