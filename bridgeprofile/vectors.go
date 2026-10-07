package bridgeprofile

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// FormatVersion identifies the manifest layout.
const FormatVersion = "bridge-pr1/1"

// Pins are the immutable sources the profile was written against
// (briefs/bridge-b2b4-design-v2.md, source alias table).
var Pins = map[string]string{
	"B": "43be1c56b5d98984161108855eef6d693aa84e7b (bft-core)",
	"J": "ca0361bfc12deb7240d41d183e027f0603b3692b (state-transition-sdk-js)",
	"R": "7ed017effd4bd0a201ab2a9ef36793cb9924a048 (state-transition-sdk-rust)",
	"Y": "8627d4d98835b6ddf35f8b4e72f0cfc131131257 (unicity-yellowpaper-tex)",
}

// Notes qualify every number in the manifest.
var Notes = []string{
	"Every fixture value is a DEV fixture input, not a production parameter.",
	"Signatures are RFC 6979 deterministic with low-s; J, R and this oracle must reproduce them byte for byte.",
	"No gas price is frozen by this manifest.",
}

// Expect is the outcome every implementation must reproduce.
type Expect struct {
	Status string `json:"status"`           // "ok" or "error"
	Family string `json:"family,omitempty"` // malformed | invalid | budget
	Reason string `json:"reason,omitempty"` // sentinel name
	Result *RJSON `json:"result,omitempty"`
}

// RJSON is a Result rendered for the manifest.
type RJSON struct {
	Cfg                string   `json:"cfg"`
	Nonce              uint64   `json:"nonce"`
	Amount             string   `json:"amount"`
	TokenID            string   `json:"tokenId"`
	Salt               string   `json:"salt"`
	FirstPredicateHash string   `json:"firstPredicateHash"`
	LockDigest         string   `json:"lockDigest"`
	ReleaseTo          string   `json:"releaseTo"`
	Nullifier          string   `json:"nullifier"`
	Leaves             []string `json:"leaves"` // sid||txHash
}

// Vector is one input with its expected outcome.
type Vector struct {
	ID          string `json:"id"`
	Family      string `json:"family"`
	Op          string `json:"op"`
	Description string `json:"description"`
	Cfg         string `json:"cfg,omitempty"` // fixture name
	Input       string `json:"input"`
	Extra       string `json:"extra,omitempty"` // op-specific second input
	Expected    Expect `json:"expected"`
}

// FixtureJSON publishes the instantiated deployment fixture.
type FixtureJSON struct {
	Name                 string `json:"name"`
	ChainID              uint64 `json:"chainId"`
	AggregatorPartition  uint32 `json:"aggregatorPartition"`
	AggregatorShardConf  string `json:"aggregatorShardConfHash"`
	EVMPartition         uint32 `json:"evmPartition"`
	EVMShard             string `json:"evmShard"`
	Cfg                  string `json:"cfg"`
	CfgHash              string `json:"cfgHash"`
	PolicyBody           string `json:"policyBody"`
	PolicyHash           string `json:"policyHash"`
	Vault                string `json:"vault"`
	Ty                   string `json:"ty"`
	Aid                  string `json:"aid"`
	SemanticProfileHash  string `json:"semanticProfileHash"`
	B1ProfileHash        string `json:"b1ProfileHash"`
	TokenVerifierAddress string `json:"tokenVerifierAddress"`
}

// Manifest is the JSON document exchanged between implementations.
type Manifest struct {
	Format   string            `json:"format"`
	Seed     string            `json:"seed"`
	Pins     map[string]string `json:"pins"`
	Notes    []string          `json:"notes"`
	Fixtures []FixtureJSON     `json:"fixtures"`
	Vectors  []Vector          `json:"vectors"`
}

// JSON renders the manifest deterministically.
func (m *Manifest) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func hx(b []byte) string    { return hex.EncodeToString(b) }
func h32(b [32]byte) string { return hex.EncodeToString(b[:]) }

// reasons lists every leaf sentinel by name, in the order Reason searches.
var reasons = []struct {
	name string
	err  error
}{
	{"ErrTruncated", ErrTruncated}, {"ErrTrailing", ErrTrailing}, {"ErrNonCanonical", ErrNonCanonical},
	{"ErrForbiddenCBOR", ErrForbiddenCBOR}, {"ErrShape", ErrShape}, {"ErrTag", ErrTag}, {"ErrVersion", ErrVersion},
	{"ErrLength", ErrLength}, {"ErrIntRange", ErrIntRange}, {"ErrABIFraming", ErrABIFraming}, {"ErrBadOperation", ErrBadOperation},
	{"ErrInputTooLarge", ErrInputTooLarge}, {"ErrTooManyTx", ErrTooManyTx}, {"ErrTooManyItems", ErrTooManyItems},
	{"ErrTooDeep", ErrTooDeep}, {"ErrTooManyPaths", ErrTooManyPaths},
	{"ErrCfgMismatch", ErrCfgMismatch}, {"ErrPolicyHash", ErrPolicyHash}, {"ErrPolicyTuple", ErrPolicyTuple},
	{"ErrPolicyAnchors", ErrPolicyAnchors}, {"ErrPolicyLeafIndex", ErrPolicyLeafIndex},
	{"ErrPolicyLeafCount", ErrPolicyLeafCount}, {"ErrPolicyPartition", ErrPolicyPartition},
	{"ErrPredicate", ErrPredicate}, {"ErrMintShape", ErrMintShape}, {"ErrMintJustif", ErrMintJustif},
	{"ErrMintSalt", ErrMintSalt}, {"ErrMintType", ErrMintType}, {"ErrMintData", ErrMintData},
	{"ErrTransferData", ErrTransferData}, {"ErrCDMismatch", ErrCDMismatch}, {"ErrUnlock", ErrUnlock},
	{"ErrUnlockLength", ErrUnlockLength}, {"ErrUnlockScalars", ErrUnlockScalars}, {"ErrUnlockRecovery", ErrUnlockRecovery},
	{"ErrUnlockKey", ErrUnlockKey}, {"ErrMinterKey", ErrMinterKey}, {"ErrRepeatedSID", ErrRepeatedSID},
	{"ErrNoTransfers", ErrNoTransfers}, {"ErrHasTransfers", ErrHasTransfers}, {"ErrBurnNotFinal", ErrBurnNotFinal},
	{"ErrNotBurn", ErrNotBurn}, {"ErrBurnReason", ErrBurnReason}, {"ErrReturnData", ErrReturnData},
	{"ErrReturnAmount", ErrReturnAmount}, {"ErrReturnRecip", ErrReturnRecip}, {"ErrLockInput", ErrLockInput},
	{"ErrZeroDigest", ErrZeroDigest},
}

// Reason names the leaf sentinel err wraps and its family.
func Reason(err error) (name, family string) {
	for _, r := range reasons {
		if errors.Is(err, r.err) {
			name = r.name
			break
		}
	}
	switch {
	case errors.Is(err, ErrMalformed):
		family = "malformed"
	case errors.Is(err, ErrBudget):
		family = "budget"
	case errors.Is(err, ErrInvalid):
		family = "invalid"
	}
	return
}

func expectFor(res *Result, err error) Expect {
	if err != nil {
		name, fam := Reason(err)
		return Expect{Status: "error", Family: fam, Reason: name}
	}
	return Expect{Status: "ok", Result: renderResult(res)}
}

func renderResult(r *Result) *RJSON {
	out := &RJSON{Cfg: h32(r.Cfg), Nonce: r.Nonce, Amount: hx(AmountBytes(r.Amount)), TokenID: h32(r.TokenID),
		Salt: h32(r.Salt), FirstPredicateHash: h32(r.FirstPredicateHash), LockDigest: h32(r.LockDigest),
		ReleaseTo: hx(r.ReleaseTo[:]), Nullifier: h32(r.Nullifier), Leaves: []string{}}
	for _, l := range r.Leaves {
		out.Leaves = append(out.Leaves, h32(l.SID)+h32(l.TxHash))
	}
	return out
}

func fixtureJSON(name string, f *Fixture) FixtureJSON {
	c := f.Cfg
	return FixtureJSON{Name: name, ChainID: c.ChainID, AggregatorPartition: f.Policy.Partition,
		AggregatorShardConf: h32(f.Policy.ShardConf), EVMPartition: c.EVMPartition, EVMShard: hx(c.EVMShard),
		Cfg: hx(c.Bytes()), CfgHash: h32(c.Hash()), PolicyBody: hx(f.Policy.Bytes()), PolicyHash: h32(f.Policy.Hash()),
		Vault: hx(c.Vault[:]), Ty: h32(c.Ty), Aid: h32(c.Aid), SemanticProfileHash: h32(c.SemanticProfileHash),
		B1ProfileHash: h32(c.B1ProfileHash), TokenVerifierAddress: hx(c.TokenVerifierAddress[:])}
}

// Seed identifies the fixture generation; changing it changes every vector.
const Seed = "bridge-pr1-v1"

// BuildManifest constructs the golden manifest from the oracle.
func BuildManifest() (*Manifest, error) {
	f := NewFixture(31337, 11, H([]byte("fixture-agg-conf")))
	m := &Manifest{Format: FormatVersion, Seed: Seed, Pins: Pins, Notes: Notes,
		Fixtures: []FixtureJSON{fixtureJSON("dev", f)}}
	add := func(v Vector) { m.Vectors = append(m.Vectors, v) }
	amount := big.NewInt(1_000_000_007)

	// ---- derivations -------------------------------------------------------
	ch := f.Cfg.Hash()
	nonces := []uint64{1, 2, 1<<64 - 1}
	for n := uint64(3); len(nonces) < 4; n++ {
		id := DeriveTokenID(DeriveSalt(ch, n), f.Cfg.Network)
		rc := H([]byte{byte(n)})
		d := LockDigest(ch, n, LockRecord(f.Cfg.ZeroAddress, f.Cfg.Ty, f.Cfg.Aid, amount, id, rc))
		if d[0] == 0 {
			nonces = append(nonces, n)
		}
	}
	for _, n := range nonces {
		salt := DeriveSalt(ch, n)
		id := DeriveTokenID(salt, f.Cfg.Network)
		rc := H([]byte{byte(n)})
		k := LockRecord(f.Cfg.ZeroAddress, f.Cfg.Ty, f.Cfg.Aid, amount, id, rc)
		d := LockDigest(ch, n, k)
		slot := LockDigestSlot(n)
		spent := SpentSlot(n)
		add(Vector{ID: fmt.Sprintf("derive-n%d", n), Family: "derivation", Op: "derive", Cfg: "dev",
			Description: "salt, token ID, lock record, cfg-bound digest, vault slots and RLP storage value for nonce n",
			Input:       fmt.Sprintf("%d", n), Extra: hx(rc[:]),
			Expected: Expect{Status: "ok", Result: &RJSON{Cfg: h32(ch), Nonce: n, Amount: hx(AmountBytes(amount)),
				TokenID: h32(id), Salt: h32(salt), FirstPredicateHash: h32(rc), LockDigest: h32(d),
				ReleaseTo: hx(k), // lock record K bytes
				Nullifier: h32(slot) + h32(StorageTrieKey(slot)) + h32(spent) + h32(StorageTrieKey(spent)) + hx(StorageValueRLP(d)),
				Leaves:    []string{}}}})
	}

	// ---- unlock ------------------------------------------------------------
	uk := KeyFromSeed("unlock-vector")
	sh, th := H([]byte("source-hash")), H([]byte("tx-hash"))
	u := SignUnlock(uk, sh, th)
	addUnlock := func(id, desc string, key []byte, ub []byte) {
		pk, perr := ParseKey(key)
		var err error
		if perr != nil {
			err = perr
		} else {
			err = VerifyUnlock(pk, sh, th, ub)
		}
		input := h32(sh) + h32(th) + hx(ub)
		e := Expect{Status: "ok"}
		if err != nil {
			e = expectFor(nil, err)
		}
		add(Vector{ID: id, Family: "unlock", Op: "unlock", Description: desc, Input: input, Extra: hx(key), Expected: e})
	}
	ukey := uk.PubKey().SerializeCompressed()
	addUnlock("unlock-valid", "valid unlock: recovery equals key, compact signature verifies", ukey, u)
	mut := func(f func([]byte)) []byte { b := append([]byte{}, u...); f(b); return b }
	addUnlock("unlock-flipped-parity", "recovery ID parity flipped, r and s unchanged and low-s", ukey, mut(func(b []byte) { b[64] ^= 1 }))
	addUnlock("unlock-id2", "recovery ID 2 against a signature whose ID is 0 or 1", ukey, mut(func(b []byte) { b[64] = 2 | b[64]&1 }))
	addUnlock("unlock-id3", "recovery ID 3", ukey, mut(func(b []byte) { b[64] = 3 }))
	addUnlock("unlock-id4", "recovery ID 4 is out of range", ukey, mut(func(b []byte) { b[64] = 4 }))
	addUnlock("unlock-id255", "recovery ID 255 is out of range", ukey, mut(func(b []byte) { b[64] = 255 }))
	addUnlock("unlock-short", "64 bytes", ukey, u[:64])
	addUnlock("unlock-high-s", "high-s twin of a valid signature, never normalised", ukey, mut(func(b []byte) {
		s := new(big.Int).Sub(secpN, new(big.Int).SetBytes(b[32:64]))
		copy(b[32:64], s.FillBytes(make([]byte, 32)))
		b[64] ^= 1
	}))
	addUnlock("unlock-r-zero", "r = 0", ukey, mut(func(b []byte) { copy(b[:32], make([]byte, 32)) }))
	addUnlock("unlock-s-zero", "s = 0", ukey, mut(func(b []byte) { copy(b[32:64], make([]byte, 32)) }))
	addUnlock("unlock-r-n", "r = n", ukey, mut(func(b []byte) { copy(b[:32], secpN.FillBytes(make([]byte, 32))) }))
	addUnlock("unlock-other-key", "valid signature against another expected key", KeyFromSeed("other").PubKey().SerializeCompressed(), u)
	hk, hu := HighRecoveryUnlock(sh, th)
	addUnlock("unlock-high-recovery-match", "recovery ID 2 or 3 where recovery succeeds and equals the expected key", hk, hu)
	addUnlock("unlock-high-recovery-flipped", "the same signature with the other of IDs 2 and 3", hk, func() []byte { b := append([]byte{}, hu...); b[64] = 5 - b[64]; return b }())
	addUnlock("unlock-high-recovery-id0", "the same signature with ID 0", hk, func() []byte { b := append([]byte{}, hu...); b[64] = 0; return b }())
	// The review's regression vector: key G, digest-preimage 0x01*32/0x02*32.
	gkey := hexMust("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	rs := hexMust("7303acb5b7bab8529f540716e3bb91c02edfd535950b0a81efc558dc39589e4c" +
		"615c4a64d26e3f07cbbcc8cce562e26319aa91ec6e9a59167e05b8da3eb15c7f")
	for _, id := range []byte{0, 1} {
		var s1, t1 [32]byte
		for i := range s1 {
			s1[i], t1[i] = 1, 2
		}
		var err error
		pk, _ := ParseKey(gkey)
		ub := append(append([]byte{}, rs...), id)
		err = VerifyUnlock(pk, s1, t1, ub)
		e := Expect{Status: "ok"}
		if err != nil {
			e = expectFor(nil, err)
		}
		add(Vector{ID: fmt.Sprintf("unlock-regression-%02x", id), Family: "unlock", Op: "unlock",
			Description: "review regression vector over G: r||s||01 accepts and r||s||00 rejects",
			Input:       h32(s1) + h32(t1) + hx(ub), Extra: hx(gkey), Expected: e})
	}

	// ---- policy and envelope ----------------------------------------------
	pb := f.Policy.Bytes()
	addPolicy := func(id, desc string, body []byte) {
		_, err := DecodePolicy(body)
		e := Expect{Status: "ok"}
		if err != nil {
			e = expectFor(nil, err)
		}
		add(Vector{ID: id, Family: "policy", Op: "policy-decode", Description: desc, Input: hx(body), Expected: e})
	}
	addPolicy("policy-valid", "the canonical policy body", pb)
	addPolicy("policy-trailing", "one trailing byte", append(append([]byte{}, pb...), 0))
	addPolicy("policy-empty-bstr-shard", "empty byte string instead of native 0x80", replaceOnce(pb, []byte{0x41, 0x80}, []byte{0x40}))
	addPolicy("policy-nonminimal-partition", "partition 11 as 0x180b", replaceOnce(pb, []byte{0x0b, 0x41}, []byte{0x18, 0x0b, 0x41}))
	addPolicy("policy-oversized", "over 128 bytes", append(append([]byte{}, pb...), make([]byte, MaxPolicyBytes)...))

	envFor := func(mutate func(e *Envelope)) *Envelope {
		e := &Envelope{PolicyBody: pb, History: []byte{1, 2, 3},
			Anchors: []Anchor{{Partition: f.Policy.Partition, Shard: EmptyPrefixShard, ShardConfHash: f.Policy.ShardConf,
				ExpectedStateRoot: H([]byte("root")), ExpectedIRHash: H([]byte("ir")), UC: []byte{9, 9}}},
			LeafProofs: []LeafProof{
				{Bitmap: H([]byte{0}), Siblings: [][32]byte{H([]byte{1}), H([]byte{2})}},
				{Bitmap: H([]byte{1}), Siblings: [][32]byte{H([]byte{3})}},
			}}
		if mutate != nil {
			mutate(e)
		}
		return e
	}
	addEnv := func(id, desc string, e *Envelope, leaves int) {
		b, _ := e.Encode()
		var err error
		if d, derr := DecodeEnvelope(b); derr != nil {
			err = derr
		} else {
			_, err = CheckPolicy(f.Cfg, d, leaves)
		}
		ex := Expect{Status: "ok"}
		if err != nil {
			ex = expectFor(nil, err)
		}
		add(Vector{ID: id, Family: "envelope", Op: "envelope-policy", Cfg: "dev", Description: desc,
			Input: hx(b), Extra: fmt.Sprintf("%d", leaves), Expected: ex})
	}
	addEnv("envelope-valid", "one anchor equal to the authenticated tuple, two leaves at index 0", envFor(nil), 2)
	addEnv("envelope-missing-policy", "empty policy body", envFor(func(e *Envelope) { e.PolicyBody = nil }), 2)
	addEnv("envelope-other-partition-policy", "a well formed policy for another partition", envFor(func(e *Envelope) {
		e.PolicyBody = Policy{Partition: 12, ShardConf: f.Policy.ShardConf}.Bytes()
	}), 2)
	addEnv("envelope-trailing-policy", "policy body with a trailing byte", envFor(func(e *Envelope) { e.PolicyBody = append(append([]byte{}, pb...), 0) }), 2)
	addEnv("envelope-partition", "anchor partition changed", envFor(func(e *Envelope) { e.Anchors[0].Partition++ }), 2)
	addEnv("envelope-shard", "anchor shard changed", envFor(func(e *Envelope) { e.Anchors[0].Shard = []byte{0x81} }), 2)
	addEnv("envelope-conf", "anchor configuration changed", envFor(func(e *Envelope) { e.Anchors[0].ShardConfHash[0] ^= 1 }), 2)
	addEnv("envelope-two-anchors", "two identical anchors", envFor(func(e *Envelope) { e.Anchors = append(e.Anchors, e.Anchors[0]) }), 2)
	addEnv("envelope-no-anchors", "no anchors", envFor(func(e *Envelope) { e.Anchors = nil }), 2)
	addEnv("envelope-leaf-index", "second leaf names anchor 1", envFor(func(e *Envelope) { e.LeafProofs[1].AnchorIndex = 1 }), 2)
	addEnv("envelope-too-few-leaves", "obligation count above the supplied leaf proofs", envFor(nil), 3)
	addEnv("envelope-too-many-leaves", "obligation count below the supplied leaf proofs", envFor(nil), 1)
	bad, _ := envFor(nil).Encode()
	add(Vector{ID: "envelope-trailing-word", Family: "envelope", Op: "envelope-policy", Cfg: "dev",
		Description: "a canonical envelope followed by one zero word", Input: hx(append(append([]byte{}, bad...), make([]byte, 32)...)), Extra: "2",
		Expected: Expect{Status: "error", Family: "malformed", Reason: "ErrABIFraming"}})
	alias := append([]byte{}, bad...)
	copy(alias[64:96], alias[96:128])
	add(Vector{ID: "envelope-anchor-alias", Family: "envelope", Op: "envelope-policy", Cfg: "dev",
		Description: "anchors offset aliases the leaf proof array", Input: hx(alias), Extra: "2",
		Expected: Expect{Status: "error", Family: "malformed", Reason: "ErrABIFraming"}})

	// Cumulative path budget, exact caps and nested-offset overflow.
	addEncoded := func(id, desc string, b []byte, leaves int) {
		var err error
		if d, derr := DecodeEnvelope(b); derr != nil {
			err = derr
		} else {
			_, err = CheckPolicy(f.Cfg, d, leaves)
		}
		ex := Expect{Status: "ok"}
		if err != nil {
			ex = expectFor(nil, err)
		}
		add(Vector{ID: id, Family: "envelope", Op: "envelope-policy", Cfg: "dev", Description: desc,
			Input: hx(b), Extra: fmt.Sprintf("%d", leaves), Expected: ex})
	}
	sibs := func(n int) [][32]byte {
		out := make([][32]byte, n)
		for i := range out {
			out[i] = H([]byte{byte(i), byte(i >> 8)})
		}
		return out
	}
	withLeaves := func(counts ...int) *Envelope {
		return envFor(func(e *Envelope) {
			e.LeafProofs = nil
			for _, c := range counts {
				e.LeafProofs = append(e.LeafProofs, LeafProof{Bitmap: H([]byte{byte(c)}), Siblings: sibs(c)})
			}
		})
	}
	rep := func(n, c int) []int {
		out := make([]int, n)
		for i := range out {
			out[i] = c
		}
		return out
	}
	addEnv("envelope-paths-2048-eight-leaves", "eight leaves of 256 siblings: exactly MaxPathSteps", withLeaves(rep(8, 256)...), 8)
	addEnv("envelope-paths-2049-nine-leaves", "nine leaves with sibling counts 256 x8 and 1: one step over MaxPathSteps", withLeaves(append(rep(8, 256), 1)...), 9)
	addEnv("envelope-paths-2048-one-leaf", "one leaf with 2048 siblings", withLeaves(2048), 1)
	addEnv("envelope-paths-2049-one-leaf", "one leaf with 2049 siblings", withLeaves(2049), 1)
	addEnv("envelope-paths-2049-split", "two leaves of 1024 and 1025 siblings", withLeaves(1024, 1025), 2)
	// Hand-patched layouts.
	base, _ := envFor(nil).Encode()
	putWord := func(b []byte, off int, v *big.Int) []byte {
		out := append([]byte{}, b...)
		w := v.FillBytes(make([]byte, 32))
		copy(out[off:off+32], w)
		return out
	}
	u64max := new(big.Int).SetUint64(1<<64 - 1)
	word := func(b []byte, off int) int { return int(new(big.Int).SetBytes(b[off : off+32]).Uint64()) }
	offL := word(base, 96)
	leafT := func(i int) int { return offL + 32 + word(base, offL+32+32*i) }
	offA := word(base, 64)
	anchT := offA + 32 + word(base, offA+32)
	addEncoded("envelope-sibling-count-u64max", "first leaf sibling count is 2^64-1", putWord(base, leafT(0)+word(base, leafT(0)+64), u64max), 2)
	addEncoded("envelope-sibling-count-2pow64", "first leaf sibling count word exceeds 64 bits",
		putWord(base, leafT(0)+word(base, leafT(0)+64), new(big.Int).Lsh(big.NewInt(1), 64)), 2)
	addEncoded("envelope-offset-sibling-u64max", "first leaf sibling offset is 2^64-1", putWord(base, leafT(0)+64, u64max), 2)
	addEncoded("envelope-offset-leaf-head-u64max", "first leaf head offset is 2^64-1", putWord(base, offL+32, u64max), 2)
	addEncoded("envelope-offset-anchor-head-u64max", "first anchor head offset is 2^64-1", putWord(base, offA+32, u64max), 2)
	addEncoded("envelope-offset-shard-u64max", "anchor shard offset is 2^64-1", putWord(base, anchT+32, u64max), 2)
	addEncoded("envelope-offset-uc-u64max", "anchor uc offset is 2^64-1", putWord(base, anchT+5*32, u64max), 2)
	addEncoded("envelope-offset-sibling-near-max", "first leaf sibling offset is 2^64-32", putWord(base, leafT(0)+64, new(big.Int).SetUint64(1<<64-32)), 2)
	// Exact caps.
	anchors := func(n int) *Envelope {
		return envFor(func(e *Envelope) {
			for len(e.Anchors) < n {
				e.Anchors = append(e.Anchors, e.Anchors[0])
			}
		})
	}
	addEnv("envelope-anchors-8", "eight anchors pass the count bound and fail the one-anchor policy", anchors(8), 2)
	addEnv("envelope-anchors-9", "nine anchors exceed MaxAnchors", anchors(9), 2)
	leaves := func(n int) *Envelope {
		return envFor(func(e *Envelope) {
			e.LeafProofs = nil
			for i := 0; i < n; i++ {
				e.LeafProofs = append(e.LeafProofs, LeafProof{Bitmap: H([]byte{byte(i)})})
			}
		})
	}
	addEnv("envelope-leaves-65", "sixty-five leaves, the maximum history", leaves(65), 65)
	addEnv("envelope-leaves-66", "sixty-six leaves exceed MaxLeaves", leaves(66), 66)
	sized := func(extra int) []byte {
		e0 := envFor(func(e *Envelope) { e.History = nil })
		b0, _ := e0.Encode()
		e0.History = make([]byte, MaxEnvelopeBytes-len(b0)+extra)
		b, _ := e0.Encode()
		return b
	}
	addEncoded("envelope-size-262144", "envelope of exactly MaxEnvelopeBytes", sized(0), 2)
	addEncoded("envelope-size-262176", "envelope one word over MaxEnvelopeBytes", sized(32), 2)

	for _, nv := range []struct{ id, desc, in string }{
		{"return-negative-integer", "CBOR major type 1 (-1) as the whole return input", "20"},
		{"return-negative-integer-nonminimal", "major type 1 with a non-shortest head", "3800"},
	} {
		in, _ := hex.DecodeString(nv.in)
		res, err := VerifyReturn(f.Cfg, in)
		add(Vector{ID: nv.id, Family: "wire", Op: "return", Cfg: "dev", Description: nv.desc, Input: nv.in, Expected: expectFor(res, err)})
	}

	// ---- prepareLock -------------------------------------------------------
	okKeys := []*secp256k1.PrivateKey{KeyFromSeed("v-a"), KeyFromSeed("v-b"), KeyFromSeed("v-c")}
	p0 := sigPred(okKeys[0]).Bytes()
	addPrep := func(id, desc string, n uint64, amt *big.Int, p []byte) {
		res, err := PrepareLock(f.Cfg, n, amt, p)
		add(Vector{ID: id, Family: "prepare", Op: "prepareLock", Cfg: "dev", Description: desc,
			Input: hx(p), Extra: fmt.Sprintf("%d:%s", n, hx(AmountBytes(amt))), Expected: expectFor(res, err)})
	}
	addPrep("prepare-valid", "n=5, whole UCT amount, signature P0", 5, amount, p0)
	addPrep("prepare-max-nonce", "n = u64 max", 1<<64-1, amount, p0)
	addPrep("prepare-zero-nonce", "n = 0", 0, amount, p0)
	addPrep("prepare-zero-amount", "amount 0", 5, big.NewInt(0), p0)
	addPrep("prepare-burn-p0", "burn predicate as P0", 5, amount, BurnPredicate([32]byte{1}).Bytes())

	// ---- histories --------------------------------------------------------
	build := func(n uint64, transfers int, burn bool) (*History, []*secp256k1.PrivateKey) {
		keys := make([]*secp256k1.PrivateKey, transfers+1)
		for i := range keys {
			keys[i] = KeyFromSeed(fmt.Sprintf("vh-%d", i))
		}
		h, _ := f.BuildToken(n, amount, keys)
		if burn {
			var rcpt [20]byte
			rcpt[0], rcpt[19] = 0xAA, 0x01
			f.AppendBurn(h, keys[len(keys)-1], rcpt, amount)
		}
		return h, keys
	}
	addHist := func(id, desc, op string, h *History) {
		b := h.Bytes()
		var res *Result
		var err error
		if op == "mint" {
			res, err = VerifyMint(f.Cfg, b)
		} else {
			res, err = VerifyReturn(f.Cfg, b)
		}
		add(Vector{ID: id, Family: "history", Op: op, Cfg: "dev", Description: desc, Input: hx(b), Expected: expectFor(res, err)})
	}
	h, _ := build(5, 0, false)
	addHist("mint-valid", "fresh mint, zero transfers", "mint", h)
	for _, tr := range []int{0, 1, 2, 16} {
		h, _ := build(5, tr, true)
		addHist(fmt.Sprintf("return-valid-%d", tr), fmt.Sprintf("mint, %d ordinary transfers, final burn", tr), "return", h)
	}
	h, _ = build(7, 0, false)
	addHist("mint-for-return-op", "a mint-only history under the return operation", "return", h)
	h, _ = build(7, 2, true)
	addHist("return-for-mint-op", "a returned history under the mint operation", "mint", h)

	type hm struct {
		id, desc string
		mut      func(h *History)
		keysOf   func(keys []*secp256k1.PrivateKey) []*secp256k1.PrivateKey
		noResign bool
	}
	same := func(k []*secp256k1.PrivateKey) []*secp256k1.PrivateKey { return k }
	muts := []hm{
		{id: "mint-wrong-network", desc: "mint network differs from Cfg", mut: func(h *History) { h.Mint.Network++ }},
		{id: "mint-burn-recipient", desc: "burn predicate as first recipient", mut: func(h *History) { h.Mint.Recipient = BurnPredicate([32]byte{1}) }},
		{id: "mint-wrong-type", desc: "type is not the bridge type", mut: func(h *History) { h.Mint.Type[0] ^= 1 }},
		{id: "mint-null-justification", desc: "null justification", mut: func(h *History) { h.Mint.Justification = nil }},
		{id: "mint-external-backing", desc: "external backing tag 39047", mut: func(h *History) {
			c := f.Cfg
			h.Mint.Justification = CTag(TagExternalMint, CArr(CUint(1), CUint(c.ChainID), CBytes(c.Vault[:]), CBytes(c.ZeroAddress[:]), CUint(7)))
		}},
		{id: "mint-wrong-chain", desc: "justification chain ID differs", mut: func(h *History) {
			c := f.Cfg
			h.Mint.Justification = MintJustification(c.ChainID+1, c.Vault, c.ZeroAddress, 7)
		}},
		{id: "mint-zero-nonce", desc: "justification nonce 0", mut: func(h *History) {
			c := f.Cfg
			h.Mint.Justification = MintJustification(c.ChainID, c.Vault, c.ZeroAddress, 0)
		}},
		{id: "mint-other-nonce", desc: "same salt offered for another nonce", mut: func(h *History) {
			c := f.Cfg
			h.Mint.Justification = MintJustification(c.ChainID, c.Vault, c.ZeroAddress, 8)
		}},
		{id: "mint-salt-changed", desc: "salt is not the derived salt", mut: func(h *History) { h.Mint.Salt[0] ^= 1 }},
		{id: "mint-null-data", desc: "null mint data", mut: func(h *History) { h.Mint.Data = nil }},
		{id: "mint-wrong-asset", desc: "mint data names another asset", mut: func(h *History) {
			a := f.Cfg.Aid
			a[0] ^= 1
			h.Mint.Data = MintData(a, amount)
		}},
		{id: "mint-leading-zero-amount", desc: "amount with a leading zero byte", mut: func(h *History) {
			h.Mint.Data = CArr(CBytes(f.Cfg.Aid[:]), CBytes(append([]byte{0}, AmountBytes(amount)...)))
		}},
		{id: "transfer-data", desc: "intermediate transfer carries data", mut: func(h *History) { h.Transfers[0].Data = []byte{1} }},
		{id: "transfer-empty-data", desc: "intermediate empty data string is not null", mut: func(h *History) { h.Transfers[1].Data = []byte{} }},
		{id: "burn-before-final", desc: "burn predicate before the final transfer", mut: func(h *History) { h.Transfers[0].Recipient = BurnPredicate([32]byte{9}) }},
		{id: "final-not-burn", desc: "final transfer locks a signature predicate", mut: func(h *History) {
			h.Transfers[len(h.Transfers)-1].Recipient = sigPred(KeyFromSeed("x"))
		}},
		{id: "burn-reason-mismatch", desc: "burn parameters differ from H(R)", mut: func(h *History) {
			h.Transfers[len(h.Transfers)-1].Recipient = BurnPredicate([32]byte{7})
		}},
		{id: "return-null-data", desc: "final transfer without return data", mut: func(h *History) { h.Transfers[len(h.Transfers)-1].Data = nil }},
		{id: "cd-source-owner", desc: "CD names another source owner", noResign: true, mut: func(h *History) { h.CDs[1].Source = sigPred(KeyFromSeed("evil")) }},
		{id: "cd-source-hash", desc: "CD source hash substituted", noResign: true, mut: func(h *History) { h.CDs[1].SourceHash[0] ^= 1 }},
		{id: "cd-tx-hash", desc: "CD tx hash substituted", noResign: true, mut: func(h *History) { h.CDs[1].TxHash[0] ^= 1 }},
		{id: "history-removed-predecessor", desc: "first transfer removed", noResign: true, mut: func(h *History) {
			h.Transfers = append(h.Transfers[:0:0], h.Transfers[1:]...)
			h.CDs = append(h.CDs[:0:0], h.CDs[1:]...)
		}},
		{id: "history-reordered", desc: "two transfers swapped", noResign: true, mut: func(h *History) {
			h.Transfers[0], h.Transfers[1] = h.Transfers[1], h.Transfers[0]
			h.CDs[0], h.CDs[1] = h.CDs[1], h.CDs[0]
		}},
		{id: "unlock-wrong-signer", desc: "transfer unlocked by a stranger", noResign: true, mut: func(h *History) {
			h.CDs[0].Unlock = SignUnlock(KeyFromSeed("evil"), h.CDs[0].SourceHash, h.CDs[0].TxHash)
		}},
		{id: "unlock-minter-public-key", desc: "mint unlocked by a non-minter key", noResign: true, mut: func(h *History) {
			h.MintCD.Unlock = SignUnlock(KeyFromSeed("evil"), h.MintCD.SourceHash, h.MintCD.TxHash)
		}},
		{id: "hist-unlock-flipped-parity", desc: "transfer unlock with recovery parity flipped", noResign: true, mut: func(h *History) { h.CDs[2].Unlock[64] ^= 1 }},
		{id: "hist-unlock-id4", desc: "transfer unlock with recovery ID 4", noResign: true, mut: func(h *History) { h.CDs[2].Unlock[64] = 4 }},
		{id: "hist-unlock-short", desc: "transfer unlock of 64 bytes", noResign: true, mut: func(h *History) { h.CDs[2].Unlock = h.CDs[2].Unlock[:64] }},
	}
	_ = same
	for _, mm := range muts {
		h, keys := build(7, 3, true)
		mm.mut(h)
		if !mm.noResign {
			if err := h.Resign(keys); err != nil {
				return nil, err
			}
		}
		addHist(mm.id, mm.desc, "return", h)
	}

	// Terminal return rejections built from the exact reason layout.
	retMut := func(id, desc string, mk func(parts [][]byte, rcpt *[20]byte, a **big.Int) []byte) {
		h, keys := build(7, 2, true)
		var rcpt [20]byte
		rcpt[0], rcpt[19] = 0xAA, 0x01
		c := f.Cfg
		ok := ReturnReason(c.ChainID, c.Vault, c.ZeroAddress, c.Ty, c.Aid, rcpt, amount)
		root, _ := scanOne(ok)
		var parts [][]byte
		for _, k := range root.kids[0].kids {
			parts = append(parts, ok[k.start:k.end])
		}
		a := new(big.Int).Set(amount)
		r := mk(parts, &rcpt, &a)
		if r == nil {
			r = ReturnReason(c.ChainID, c.Vault, c.ZeroAddress, c.Ty, c.Aid, rcpt, a)
		}
		n := len(h.Transfers) - 1
		h.Transfers[n].Data = r
		h.Transfers[n].Recipient = BurnPredicate(H(r))
		_ = h.Resign(keys)
		addHist(id, desc, "return", h)
	}
	retMut("return-partial-amount", "return amount below the genesis amount", func(p [][]byte, r *[20]byte, a **big.Int) []byte {
		*a = big.NewInt(1)
		return nil
	})
	retMut("return-zero-recipient", "zero recipient", func(p [][]byte, r *[20]byte, a **big.Int) []byte { *r = [20]byte{}; return nil })
	retMut("return-vault-recipient", "vault as recipient", func(p [][]byte, r *[20]byte, a **big.Int) []byte { *r = f.Cfg.Vault; return nil })
	retMut("return-fee-token", "fee token slot set", func(p [][]byte, r *[20]byte, a **big.Int) []byte {
		p[8] = CBytes(make([]byte, 20))
		p[8][len(p[8])-1] = 1
		return CTag(TagReturnReason, CArr(p...))
	})
	retMut("return-fee-amount", "fee amount slot set", func(p [][]byte, r *[20]byte, a **big.Int) []byte {
		p[9] = CBytes([]byte{1})
		return CTag(TagReturnReason, CArr(p...))
	})
	retMut("return-deadline", "deadline slot set", func(p [][]byte, r *[20]byte, a **big.Int) []byte {
		p[10] = CUint(1)
		return CTag(TagReturnReason, CArr(p...))
	})
	retMut("return-wrong-asset", "reason names another asset", func(p [][]byte, r *[20]byte, a **big.Int) []byte {
		p[5] = CBytes(make([]byte, 32))
		return CTag(TagReturnReason, CArr(p...))
	})

	// Wire-level decode rejections.
	h, _ = build(7, 2, true)
	good := h.Bytes()
	add(Vector{ID: "wire-trailing", Family: "wire", Op: "return", Cfg: "dev", Description: "history with a trailing byte",
		Input: hx(append(append([]byte{}, good...), 0)), Expected: expectFor(nil, ErrTrailing)})
	add(Vector{ID: "wire-truncated", Family: "wire", Op: "return", Cfg: "dev", Description: "history truncated by one byte",
		Input: hx(good[:len(good)-1]), Expected: expectFor(nil, ErrTruncated)})
	add(Vector{ID: "wire-indefinite", Family: "wire", Op: "return", Cfg: "dev", Description: "indefinite-length array",
		Input: "9fff", Expected: expectFor(nil, ErrForbiddenCBOR)})
	add(Vector{ID: "wire-nonminimal-head", Family: "wire", Op: "return", Cfg: "dev", Description: "array head 0x9802 instead of 0x82",
		Input: "9802", Expected: expectFor(nil, ErrNonCanonical)})
	t0 := h.Transfers[0].Bytes()
	badver := CTag(TagTransfer, CArr(CUint(2), h.Transfers[0].Recipient.Bytes(), CBytes(h.Transfers[0].Mask[:]), CNull))
	add(Vector{ID: "wire-transfer-version", Family: "wire", Op: "return", Cfg: "dev", Description: "transfer version literal 2",
		Input: hx(replaceOnce(good, t0, badver)), Expected: expectFor(nil, ErrVersion)})
	extra := CTag(TagTransfer, CArr(CUint(1), h.Transfers[0].Recipient.Bytes(), CBytes(h.Transfers[0].Mask[:]), CNull, CNull))
	add(Vector{ID: "wire-transfer-extra-field", Family: "wire", Op: "return", Cfg: "dev", Description: "transfer with a fifth field",
		Input: hx(replaceOnce(good, t0, extra)), Expected: expectFor(nil, ErrShape)})
	badtag := CTag(TagTransfer+1, CArr(CUint(1), h.Transfers[0].Recipient.Bytes(), CBytes(h.Transfers[0].Mask[:]), CNull))
	add(Vector{ID: "wire-transfer-tag", Family: "wire", Op: "return", Cfg: "dev", Description: "transfer with tag 39046",
		Input: hx(replaceOnce(good, t0, badtag)), Expected: expectFor(nil, ErrTag)})
	short := CTag(TagTransfer, CArr(CUint(1), h.Transfers[0].Recipient.Bytes(), CBytes(h.Transfers[0].Mask[:31]), CNull))
	add(Vector{ID: "wire-transfer-short-mask", Family: "wire", Op: "return", Cfg: "dev", Description: "31 byte state mask",
		Input: hx(replaceOnce(good, t0, short)), Expected: expectFor(nil, ErrLength)})
	pt := h.Transfers[0].Recipient.Bytes()
	for _, pv := range []struct {
		id, desc string
		p        []byte
	}{
		{"wire-predicate-engine", "predicate engine 2", CTag(TagPredicate, CArr(CUint(2), CBytes([]byte{1}), CBytes(okKeys[1].PubKey().SerializeCompressed())))},
		{"wire-predicate-text-code", "predicate code is the text name", CTag(TagPredicate, CArr(CUint(1), CBytes([]byte("signature")), CBytes(okKeys[1].PubKey().SerializeCompressed())))},
		{"wire-predicate-nonminimal-code", "code bytes 1801", CTag(TagPredicate, CArr(CUint(1), CBytes([]byte{0x18, 1}), CBytes(okKeys[1].PubKey().SerializeCompressed())))},
		{"wire-predicate-uncompressed", "uncompressed key", CTag(TagPredicate, CArr(CUint(1), CBytes([]byte{1}), CBytes(append([]byte{4}, make([]byte, 64)...))))},
	} {
		_, err := DecodeHistory(replaceOnce(good, pt, pv.p))
		add(Vector{ID: pv.id, Family: "wire", Op: "return", Cfg: "dev", Description: pv.desc,
			Input: hx(replaceOnce(good, pt, pv.p)), Expected: expectFor(nil, err)})
	}

	// Cfg binding: the same bytes under another Cfg.
	h, _ = build(7, 1, true)
	other := fixtureJSON("dev", f)
	_ = other
	return m, nil
}

func replaceOnce(b, old, repl []byte) []byte {
	i := indexOf(b, old)
	if i < 0 {
		panic("vector construction: pattern not found")
	}
	return append(append(append([]byte{}, b[:i]...), repl...), b[i+len(old):]...)
}

func indexOf(b, sub []byte) int {
	for i := 0; i+len(sub) <= len(b); i++ {
		if string(b[i:i+len(sub)]) == string(sub) {
			return i
		}
	}
	return -1
}

func hexMust(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
