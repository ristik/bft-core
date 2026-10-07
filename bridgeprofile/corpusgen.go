package bridgeprofile

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/unicitynetwork/bft-go-base/types"
)

// semanticProfile is the canonical native-bridge profile artifact, byte for
// byte native-bridge-plugins protocol/profile-v2.json at the revision this
// generator was written against.
//
//go:embed testdata/semantic-profile.json
var semanticProfile []byte

// Notes qualify every number in the corpus.
var Notes = []string{
	"Every fixture value is a DEV fixture input, not a production parameter.",
	"Signatures are RFC 6979 deterministic with low-s; every implementation must reproduce them byte for byte.",
	"No gas price is frozen by this corpus. Bounds are provisional DEV ceilings.",
	"Supported authority is one fixed SDK trust base, unit weights, count quorum N-(N-1)/3. DEFERRED (common SDK trust-base work, bft-core#421): weighted acceptance such as (98,1,1), mixed historical/current committees, trust-base append/fetch, interval closure, old-J validity through rotation, full B1/SDK seal parity; they have no cases.",
	"The trust-base documents in fixtures.json are the exact bytes the pinned JS SDK 3.0.1 emits; native-bridge-plugins checks each against the SDK, and config/sdk-root-trust-base.json is the pinned B.",
	"B1 in compose cases is the claim set in aux.claims plus the real RSMT_MEMBER_V1; UC verification behind 0x0100 is B1's own conformance.",
	"referenceTime and nonce are decimal strings; amounts are minimal big-endian hex.",
}

var families = []string{"config", "wire", "unlock", "policy", "lock", "history", "proof", "return", "vault"}

// Corpus is the generated vector tree: path -> bytes.
type Corpus struct {
	Files map[string][]byte
	Set   *FixtureSet
	Cases map[string][]Case
}

type gen struct {
	d      *Deployment
	fs     *FixtureSet
	cases  map[string][]Case
	failed error
}

func (g *gen) add(c Case) {
	if c.Expected.Status == "" {
		c.Expected = Replay(g.fs, c)
	}
	g.cases[c.Family] = append(g.cases[c.Family], c)
}

func (g *gen) must(err error) {
	if err != nil && g.failed == nil {
		g.failed = err
	}
}

func trustBaseHex(tb types.RootTrustBase) (string, string) {
	raw, _ := types.Cbor.Marshal(tb)
	id := sha256.Sum256(raw)
	return hx(raw), hex.EncodeToString(id[:])
}

// BuildCorpus generates the whole candidate corpus deterministically.
func BuildCorpus() (*Corpus, error) {
	d, err := NewDeployment()
	if err != nil {
		return nil, err
	}
	g := &gen{d: d, cases: map[string][]Case{}}
	g0 := g
	f := d.F
	fs := &FixtureSet{Format: CorpusFormat, Proto: NativeBridgeProtoVersion, Notes: Notes,
		Cfgs: map[string]FixtureJSON{"dev": fixtureJSON("dev", f)}, TrustBases: map[string]string{}, Pins: map[string]PinJSON{},
		Aggregat: map[string]string{}}
	tb2, err := d.Auth.TrustBase(DevNetwork, 2)
	if err != nil {
		return nil, err
	}
	rogue, err := NewAuthority("rogue")
	if err != nil {
		return nil, err
	}
	rtb, err := rogue.TrustBase(DevNetwork, 1)
	if err != nil {
		return nil, err
	}
	jsonHex := func(tb *types.RootTrustBaseV1) string { b, err := RenderTrustBaseJSON(tb); g0.must(err); return hx(b) }
	fs.TrustBases["pinned"] = hx(d.Trust.JSON)
	fs.TrustBases["next-epoch-same-keys"] = jsonHex(tb2)
	fs.TrustBases["rogue-authority"] = jsonHex(rtb)
	futureStart, err := d.Auth.TrustBaseWith(DevNetwork, 1, DevRootRound+1)
	g0.must(err)
	fs.TrustBases["epoch-start-after-certificate"] = jsonHex(futureStart)
	otherNet, err := d.Auth.TrustBase(DevNetwork+1, 1)
	g0.must(err)
	fs.TrustBases["other-network"] = jsonHex(otherNet)
	// Four validators with threshold 2: a valid SDK document whose threshold is
	// not the supported count quorum N-(N-1)/3 = 3.
	quad, err := NewCommittee("quorum-4", 4)
	g0.must(err)
	wrongThr, err := quad.TrustBase(DevNetwork, 1)
	g0.must(err)
	wrongThr.QuorumThreshold = 2
	fs.TrustBases["threshold-not-n-minus-third"] = jsonHex(wrongThr)
	// Unit-weight committees for the count-quorum boundaries.
	for _, n := range []int{3, 4, 7} {
		com, err := NewCommittee(fmt.Sprintf("quorum-%d", n), n)
		g0.must(err)
		ctb, err := com.TrustBase(DevNetwork, 1)
		g0.must(err)
		fs.TrustBases[fmt.Sprintf("committee-%d", n)] = jsonHex(ctb)
	}
	heavy := *d.TB
	heavy.RootNodes = []*types.NodeInfo{{NodeID: d.TB.RootNodes[0].NodeID, SigKey: d.TB.RootNodes[0].SigKey, Stake: 2}}
	fs.TrustBases["non-unit-weight"] = jsonHex(&heavy)
	pdrHex := func(p *types.PartitionDescriptionRecord) string { b, _ := types.Cbor.Marshal(p); return hx(b) }
	fs.Pins["dev"] = PinJSON{GenesisPDR: pdrHex(d.EVMPDR), VaultCodeHash: h32(d.Pin.VaultCodeHash)}
	other := *d.Pin
	other.VaultCodeHash[0] ^= 1
	fs.Pins["other-runtime"] = PinJSON{GenesisPDR: pdrHex(d.EVMPDR), VaultCodeHash: h32(other.VaultCodeHash)}
	gp := *d.EVMPDR
	gp.T2Timeout++
	fs.Pins["other-genesis"] = PinJSON{GenesisPDR: pdrHex(&gp), VaultCodeHash: h32(d.Pin.VaultCodeHash)}
	h0, _ := trustBaseHex(d.TB)
	fs.Aggregat["dev"] = h0
	// A replacement vault: same asset identifiers, another cfg.
	dev2 := *f
	c2 := *f.Cfg
	c2.Vault[0] ^= 0x5a
	dev2.Cfg = &c2
	fs.Cfgs["dev-replacement-vault"] = fixtureJSON("dev-replacement-vault", &dev2)
	g.fs = fs

	for _, network := range []uint64{0, 65536} {
		var doc map[string]any
		g.must(json.Unmarshal(d.Trust.JSON, &doc))
		doc["networkId"] = network
		raw, err := json.Marshal(doc)
		g.must(err)
		g.add(Case{ID: fmt.Sprintf("trust-network-%d", network), Family: "config", Op: "trust-input", Description: "network rejected before narrowing", Input: hx(raw)})
	}
	g.networkBoundaries()
	g.config()
	g.vault()
	g.unlock()
	g.policy()
	g.histories()
	g.wire()
	g.lock()
	g.proof()
	if g.failed != nil {
		return nil, g.failed
	}
	return g.pack()
}

// networkBoundaries reconstructs the identities, cfg-bound proof, salt, ID and
// genesis signature; a zero-network failure cannot be a stale-identity failure.
func (g *gen) networkBoundaries() {
	owner := KeyFromSeed("network-boundary-owner")
	for _, network := range []uint16{0, 1, 65535} {
		f := *g.d.F
		c := *f.Cfg
		c.Network = network
		c.Ty = DeriveType(network, c.RootGenesis, c.ExecutionGenesis, c.ChainID)
		c.Aid = DeriveAsset(network, c.RootGenesis, c.ExecutionGenesis, c.ChainID)
		f.Cfg = &c
		h, err := f.BuildToken(7, big.NewInt(12345), []*secp256k1.PrivateKey{owner})
		g.must(err)
		cfg := c.Bytes()
		add := func(id, op string, input []byte) {
			g.add(Case{ID: fmt.Sprintf("network-%d-%s", network, id), Family: "config", Op: op,
				Description: "SDK NetworkId boundary with reconstructed signed genesis", Input: hx(input)})
		}
		add("cfg", "cfg-decode", cfg)
		mint, err := EncodeKernelInput(1, cfg, h.Bytes())
		g.must(err)
		add("mint", "kernel", mint)
		prepare, err := EncodeKernelInput(0, cfg, PreparePayload(7, big.NewInt(12345), h.Mint.Recipient.Bytes()))
		g.must(err)
		add("prepare", "kernel", prepare)
	}
	// uint16 cannot represent 65536; replace the encoded field for overflow cases.
	c := g.d.F.Cfg
	cfg := bytes.Replace(c.Bytes(), append(CBytes([]byte(cfgDomain)), CUint(uint64(c.Network))...), append(CBytes([]byte(cfgDomain)), CUint(65536)...), 1)
	g.add(Case{ID: "network-65536-cfg", Family: "config", Op: "cfg-decode", Input: hx(cfg), Description: "network above SDK uint16 maximum"})
	for _, op := range []uint8{0, 1} {
		input, err := EncodeKernelInput(op, cfg, CNull)
		g.must(err)
		g.add(Case{ID: fmt.Sprintf("network-65536-kernel-%d", op), Family: "config", Op: "kernel", Input: hx(input), Description: "overflow Cfg before payload decoding"})
	}
	// Independently exercise the mint wire decoder under a valid Cfg.
	for _, network := range []uint64{0, 65536} {
		h, err := g.d.F.BuildToken(7, big.NewInt(12345), []*secp256k1.PrivateKey{owner})
		g.must(err)
		// Preserve the tagged eight-field mint header and replace only its network.
		prefix := append(CTag(TagMint, nil), 0x88, byte(TxVersion))
		old := append(append([]byte{}, prefix...), CUint(uint64(c.Network))...)
		next := append(append([]byte{}, prefix...), CUint(network)...)
		mint := bytes.Replace(h.Mint.Bytes(), old, next, 1)
		history := CArr(CArr(mint, h.MintCD.Bytes(), CUint(h.MintTime)), CArr())
		input, err := EncodeKernelInput(1, c.Bytes(), history)
		g.must(err)
		g.add(Case{ID: fmt.Sprintf("network-%d-mint-wire", network), Family: "config", Op: "kernel", Input: hx(input), Description: "mint wire NetworkId range independent of valid Cfg"})
	}
}

func (g *gen) config() {
	f := g.d.F
	c := f.Cfg
	ids := func(id, desc string, nw uint16, r, x [32]byte, ch uint64) {
		g.add(Case{ID: id, Family: "config", Op: "identifiers", Description: desc,
			Input: fmt.Sprintf("%d:%s:%s:%d", nw, h32(r), h32(x), ch)})
	}
	ids("ids-dev", "type and asset of the dev deployment under family unicity-native", c.Network, c.RootGenesis, c.ExecutionGenesis, c.ChainID)
	ids("ids-network", "another network", c.Network+1, c.RootGenesis, c.ExecutionGenesis, c.ChainID)
	r := c.RootGenesis
	r[0] ^= 1
	ids("ids-root-genesis", "another root genesis", c.Network, r, c.ExecutionGenesis, c.ChainID)
	x := c.ExecutionGenesis
	x[0] ^= 1
	ids("ids-execution-genesis", "another execution genesis", c.Network, c.RootGenesis, x, c.ChainID)
	ids("ids-chain", "another chain id", c.Network, c.RootGenesis, c.ExecutionGenesis, c.ChainID+1)
	ids("ids-small-chain", "chain id 7: no leading zeros", c.Network, c.RootGenesis, c.ExecutionGenesis, 7)
	ids("ids-max-chain", "chain id u64 maximum", c.Network, c.RootGenesis, c.ExecutionGenesis, 1<<64-1)
	for _, a := range []string{"1", "258", "1000000007", new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)).String()} {
		g.add(Case{ID: "value-data-" + a[:min(len(a), 12)], Family: "config", Op: "value-data",
			Description: "the common wallet value envelope tag 39050 for one asset", Input: h32(c.Aid) + ":" + a})
	}
	cb := c.Bytes()
	g.add(Case{ID: "cfg-valid", Family: "config", Op: "cfg-decode", Description: "the dev Cfg", Input: hx(cb)})
	g.add(Case{ID: "cfg-trailing", Family: "config", Op: "cfg-decode", Description: "one trailing byte", Input: hx(append(bytes.Clone(cb), 0))})
	g.add(Case{ID: "cfg-truncated", Family: "config", Op: "cfg-decode", Description: "one byte short", Input: hx(cb[:len(cb)-1])})
	bad := bytes.Clone(cb)
	bad[3] ^= 1
	g.add(Case{ID: "cfg-domain", Family: "config", Op: "cfg-decode", Description: "domain tampered", Input: hx(bad)})
	nm := bytes.Replace(cb, []byte{0x03, 0x58, 0x20}, []byte{0x18, 0x03, 0x58, 0x20}, 1)
	nm = append([]byte{0x90}, nm[1:]...)
	g.add(Case{ID: "cfg-nonminimal-network", Family: "config", Op: "cfg-decode", Description: "network 3 as 0x1803", Input: hx(nm)})
	t := *c
	t.Ty[0] ^= 1
	g.add(Case{ID: "cfg-type-not-derived", Family: "config", Op: "cfg-decode", Description: "well formed Cfg whose type is not derived from its inputs", Input: hx(t.Bytes())})
	z := *c
	z.ZeroAddress[19] = 1
	g.add(Case{ID: "cfg-zero-address", Family: "config", Op: "cfg-decode", Description: "nonzero native-asset address", Input: hx(z.Bytes())})
	g.add(Case{ID: "cfg-replacement-vault", Family: "config", Op: "cfg-decode",
		Description: "a replacement vault keeps ty and aid, with its own cfg", Input: g.fs.Cfgs["dev-replacement-vault"].Cfg})
}

func (g *gen) vault() {
	f := g.d.F
	amount := big.NewInt(1_000_000_007)
	ch := f.Cfg.Hash()
	nonces := []uint64{1, 2, 1<<64 - 1}
	for n := uint64(3); len(nonces) < 4; n++ {
		id := DeriveTokenID(DeriveSalt(ch, n), f.Cfg.Network)
		rc := H([]byte{byte(n)})
		if LockDigest(ch, n, LockRecord(f.Cfg.ZeroAddress, f.Cfg.Ty, f.Cfg.Aid, amount, id, rc))[0] == 0 {
			nonces = append(nonces, n)
		}
	}
	for _, n := range nonces {
		rc := H([]byte{byte(n)})
		g.add(Case{ID: fmt.Sprintf("derive-n%d", n), Family: "vault", Op: "derive", Cfg: "dev",
			Description: "salt, token ID, lock record, cfg-bound digest, vault slots and RLP storage value for nonce n",
			Input:       strconv.FormatUint(n, 10), Aux: map[string]string{"amount": amount.String(), "firstPredicateHash": h32(rc)}})
	}
}

func (g *gen) unlock() {
	uk := KeyFromSeed("unlock-vector")
	sh, th := H([]byte("source-hash")), H([]byte("tx-hash"))
	u := SignUnlock(uk, sh, th)
	ukey := uk.PubKey().SerializeCompressed()
	add := func(id, desc string, key, ub []byte) {
		g.add(Case{ID: id, Family: "unlock", Op: "unlock", Description: desc, Input: h32(sh) + h32(th) + hx(ub), Aux: map[string]string{"key": hx(key)}})
	}
	mut := func(f func([]byte)) []byte { b := bytes.Clone(u); f(b); return b }
	add("unlock-valid", "valid unlock: recovery equals key, compact signature verifies", ukey, u)
	add("unlock-flipped-parity", "recovery ID parity flipped, r and s unchanged and low-s", ukey, mut(func(b []byte) { b[64] ^= 1 }))
	add("unlock-id2", "recovery ID 2 against a signature whose ID is 0 or 1", ukey, mut(func(b []byte) { b[64] = 2 | b[64]&1 }))
	add("unlock-id3", "recovery ID 3", ukey, mut(func(b []byte) { b[64] = 3 }))
	add("unlock-id4", "recovery ID 4 is out of range", ukey, mut(func(b []byte) { b[64] = 4 }))
	add("unlock-id255", "recovery ID 255 is out of range", ukey, mut(func(b []byte) { b[64] = 255 }))
	add("unlock-short", "64 bytes", ukey, u[:64])
	add("unlock-high-s", "high-s twin of a valid signature, never normalised", ukey, mut(func(b []byte) {
		s := new(big.Int).Sub(secpN, new(big.Int).SetBytes(b[32:64]))
		copy(b[32:64], s.FillBytes(make([]byte, 32)))
		b[64] ^= 1
	}))
	add("unlock-r-zero", "r = 0", ukey, mut(func(b []byte) { copy(b[:32], make([]byte, 32)) }))
	add("unlock-s-zero", "s = 0", ukey, mut(func(b []byte) { copy(b[32:64], make([]byte, 32)) }))
	add("unlock-r-n", "r = n", ukey, mut(func(b []byte) { copy(b[:32], secpN.FillBytes(make([]byte, 32))) }))
	add("unlock-other-key", "valid signature against another expected key", KeyFromSeed("other").PubKey().SerializeCompressed(), u)
	hk, hu := HighRecoveryUnlock(sh, th)
	add("unlock-high-recovery-match", "recovery ID 2 or 3 where recovery succeeds and equals the expected key", hk, hu)
	add("unlock-high-recovery-flipped", "the same signature with the other of IDs 2 and 3", hk, func() []byte { b := bytes.Clone(hu); b[64] = 5 - b[64]; return b }())
	add("unlock-high-recovery-id0", "the same signature with ID 0", hk, func() []byte { b := bytes.Clone(hu); b[64] = 0; return b }())
	gkey := hexMust("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	rs := hexMust("7303acb5b7bab8529f540716e3bb91c02edfd535950b0a81efc558dc39589e4c" + "615c4a64d26e3f07cbbcc8cce562e26319aa91ec6e9a59167e05b8da3eb15c7f")
	for _, id := range []byte{0, 1} {
		var s1, t1 [32]byte
		for i := range s1 {
			s1[i], t1[i] = 1, 2
		}
		g.add(Case{ID: fmt.Sprintf("unlock-regression-%02x", id), Family: "unlock", Op: "unlock",
			Description: "review regression vector over G: r||s||01 accepts and r||s||00 rejects",
			Input:       h32(s1) + h32(t1) + hx(append(bytes.Clone(rs), id)), Aux: map[string]string{"key": hx(gkey)}})
	}
}

func (g *gen) policy() {
	f := g.d.F
	pb := f.Policy.Bytes()
	ap := func(id, desc string, body []byte) {
		g.add(Case{ID: id, Family: "policy", Op: "policy-decode", Description: desc, Input: hx(body)})
	}
	ap("policy-valid", "the canonical policy body", pb)
	ap("policy-trailing", "one trailing byte", append(bytes.Clone(pb), 0))
	ap("policy-empty-bstr-shard", "empty byte string instead of native 0x80", replaceOnce(pb, []byte{0x41, 0x80}, []byte{0x40}))
	ap("policy-nonminimal-partition", "partition 11 as 0x180b", replaceOnce(pb, []byte{0x0b, 0x41}, []byte{0x18, 0x0b, 0x41}))
	ap("policy-oversized", "over 128 bytes", append(bytes.Clone(pb), make([]byte, MaxPolicyBytes)...))

	envFor := func(mutate func(e *Envelope)) *Envelope {
		e := &Envelope{PolicyBody: pb, History: []byte{1, 2, 3},
			Anchors: []Anchor{{Partition: f.Policy.Partition, Shard: EmptyPrefixShard, ShardConfHash: f.Policy.ShardConf,
				ExpectedStateRoot: H([]byte("root")), ExpectedIRHash: H([]byte("ir")), UC: []byte{9, 9}, InputRecord: []byte{7, 7}}},
			LeafProofs: []LeafProof{
				{Bitmap: H([]byte{0}), Siblings: [][32]byte{H([]byte{1}), H([]byte{2})}},
				{Bitmap: H([]byte{1}), Siblings: [][32]byte{H([]byte{3})}}}}
		if mutate != nil {
			mutate(e)
		}
		return e
	}
	addBytes := func(id, desc string, b []byte, leaves int) {
		g.add(Case{ID: id, Family: "policy", Op: "envelope-policy", Cfg: "dev", Description: desc, Input: hx(b), Aux: map[string]string{"leaves": strconv.Itoa(leaves)}})
	}
	addEnv := func(id, desc string, e *Envelope, leaves int) {
		b, err := e.Encode()
		g.must(err)
		addBytes(id, desc, b, leaves)
	}
	addEnv("envelope-valid", "one anchor equal to the authenticated tuple with its IR opening, two leaves at index 0", envFor(nil), 2)
	addEnv("envelope-missing-policy", "empty policy body", envFor(func(e *Envelope) { e.PolicyBody = nil }), 2)
	addEnv("envelope-other-partition-policy", "a well formed policy for another partition", envFor(func(e *Envelope) {
		e.PolicyBody = Policy{Partition: 12, ShardConf: f.Policy.ShardConf}.Bytes()
	}), 2)
	addEnv("envelope-trailing-policy", "policy body with a trailing byte", envFor(func(e *Envelope) { e.PolicyBody = append(bytes.Clone(pb), 0) }), 2)
	addEnv("envelope-partition", "anchor partition changed", envFor(func(e *Envelope) { e.Anchors[0].Partition++ }), 2)
	addEnv("envelope-shard", "anchor shard changed", envFor(func(e *Envelope) { e.Anchors[0].Shard = []byte{0x81} }), 2)
	addEnv("envelope-conf", "anchor configuration changed", envFor(func(e *Envelope) { e.Anchors[0].ShardConfHash[0] ^= 1 }), 2)
	addEnv("envelope-two-anchors", "two identical anchors", envFor(func(e *Envelope) { e.Anchors = append(e.Anchors, e.Anchors[0]) }), 2)
	addEnv("envelope-no-anchors", "no anchors", envFor(func(e *Envelope) { e.Anchors = nil }), 2)
	addEnv("envelope-leaf-index", "second leaf names anchor 1", envFor(func(e *Envelope) { e.LeafProofs[1].AnchorIndex = 1 }), 2)
	addEnv("envelope-too-few-leaves", "obligation count above the supplied leaf proofs", envFor(nil), 3)
	addEnv("envelope-too-many-leaves", "obligation count below the supplied leaf proofs", envFor(nil), 1)
	addEnv("envelope-empty-input-record", "anchor with an empty IR opening still frames; the composition rejects it", envFor(func(e *Envelope) { e.Anchors[0].InputRecord = nil }), 2)
	good, _ := envFor(nil).Encode()
	addBytes("envelope-trailing-word", "a canonical envelope followed by one zero word", append(bytes.Clone(good), make([]byte, 32)...), 2)
	alias := bytes.Clone(good)
	copy(alias[64:96], alias[96:128])
	addBytes("envelope-anchor-alias", "anchors offset aliases the leaf proof array", alias, 2)

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
	base, _ := envFor(nil).Encode()
	putWord := func(b []byte, off int, v *big.Int) []byte {
		out := bytes.Clone(b)
		copy(out[off:off+32], v.FillBytes(make([]byte, 32)))
		return out
	}
	u64max := new(big.Int).SetUint64(1<<64 - 1)
	word := func(b []byte, off int) int { return int(new(big.Int).SetBytes(b[off : off+32]).Uint64()) }
	offL := word(base, 96)
	leafT := func(i int) int { return offL + 32 + word(base, offL+32+32*i) }
	offA := word(base, 64)
	anchT := offA + 32 + word(base, offA+32)
	addBytes("envelope-sibling-count-u64max", "first leaf sibling count is 2^64-1", putWord(base, leafT(0)+word(base, leafT(0)+64), u64max), 2)
	addBytes("envelope-sibling-count-2pow64", "first leaf sibling count word exceeds 64 bits", putWord(base, leafT(0)+word(base, leafT(0)+64), new(big.Int).Lsh(big.NewInt(1), 64)), 2)
	addBytes("envelope-offset-sibling-u64max", "first leaf sibling offset is 2^64-1", putWord(base, leafT(0)+64, u64max), 2)
	addBytes("envelope-offset-leaf-head-u64max", "first leaf head offset is 2^64-1", putWord(base, offL+32, u64max), 2)
	addBytes("envelope-offset-anchor-head-u64max", "first anchor head offset is 2^64-1", putWord(base, offA+32, u64max), 2)
	addBytes("envelope-offset-shard-u64max", "anchor shard offset is 2^64-1", putWord(base, anchT+32, u64max), 2)
	addBytes("envelope-offset-uc-u64max", "anchor uc offset is 2^64-1", putWord(base, anchT+5*32, u64max), 2)
	addBytes("envelope-offset-input-record-u64max", "anchor inputRecord offset is 2^64-1", putWord(base, anchT+6*32, u64max), 2)
	addBytes("envelope-offset-sibling-near-max", "first leaf sibling offset is 2^64-32", putWord(base, leafT(0)+64, new(big.Int).SetUint64(1<<64-32)), 2)
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
	addBytes("envelope-size-262144", "envelope of exactly MaxEnvelopeBytes", sized(0), 2)
	addBytes("envelope-size-262176", "envelope one word over MaxEnvelopeBytes", sized(32), 2)
}

// histories: the relation cases (mint and return) and the return terminal.
func (g *gen) histories() {
	f := g.d.F
	amount := big.NewInt(1_000_000_007)
	build := func(n uint64, transfers int, burn bool) (*History, []*secp256k1.PrivateKey) {
		keys := make([]*secp256k1.PrivateKey, transfers+1)
		for i := range keys {
			keys[i] = KeyFromSeed(fmt.Sprintf("vh-%d", i))
		}
		h, err := f.BuildToken(n, amount, keys)
		g.must(err)
		if burn {
			var rcpt [20]byte
			rcpt[0], rcpt[19] = 0xAA, 0x01
			f.AppendBurn(h, keys[len(keys)-1], rcpt, amount)
		}
		return h, keys
	}
	add := func(id, fam, desc, op string, h *History) {
		g.add(Case{ID: id, Family: fam, Op: op, Cfg: "dev", Description: desc, Input: hx(h.Bytes())})
	}
	h, keys := build(5, 0, false)
	add("mint-valid", "history", "fresh mint, zero transfers, null deadline", "mint", h)
	p0 := sigPred(keys[0]).Bytes()
	for _, c := range []struct {
		id, desc string
		n        uint64
		a        *big.Int
		p        []byte
	}{
		{"prepare-valid", "n=5, whole amount, signature P0", 5, amount, p0},
		{"prepare-max-nonce", "n = u64 max", 1<<64 - 1, amount, p0},
		{"prepare-zero-nonce", "n = 0", 0, amount, p0},
		{"prepare-zero-amount", "amount 0", 5, big.NewInt(0), p0},
		{"prepare-burn-p0", "burn predicate as P0", 5, amount, BurnPredicate([32]byte{1}).Bytes()},
	} {
		g.add(Case{ID: c.id, Family: "history", Op: "prepareLock", Cfg: "dev", Description: c.desc, Input: hx(c.p),
			Aux: map[string]string{"n": strconv.FormatUint(c.n, 10), "amount": c.a.String()}})
	}
	for _, tr := range []int{0, 1, 2, 16} {
		h, _ := build(5, tr, true)
		add(fmt.Sprintf("return-valid-%d", tr), "history", fmt.Sprintf("mint, %d ordinary transfers, final burn", tr), "return", h)
	}
	h, _ = build(7, 0, false)
	add("mint-for-return-op", "history", "a mint-only history under the return operation", "return", h)
	h, _ = build(7, 2, true)
	add("return-for-mint-op", "history", "a returned history under the mint operation", "mint", h)

	type hm struct {
		id, desc string
		mut      func(h *History)
		noResign bool
	}
	c := f.Cfg
	just := func(chain uint64, v [20]byte, n uint64) []byte {
		return MintJustification(chain, v, c.ZeroAddress, n, f.StructuralProof(n))
	}
	rawV := func(amount []byte) []byte {
		return CTag(TagValue, CArr(CUint(1), CArr(CArr(CBytes(c.Aid[:]), amount)), CNull))
	}
	muts := []hm{
		{id: "mint-wrong-network", desc: "mint network differs from Cfg", mut: func(h *History) { h.Mint.Network++ }},
		{id: "mint-burn-recipient", desc: "burn predicate as first recipient", mut: func(h *History) { h.Mint.Recipient = BurnPredicate([32]byte{1}) }},
		{id: "mint-wrong-type", desc: "type is not the bridge type", mut: func(h *History) { h.Mint.Type[0] ^= 1 }},
		{id: "mint-null-justification", desc: "null justification", mut: func(h *History) { h.Mint.Justification = nil }},
		{id: "mint-external-backing", desc: "external backing tag 39047", mut: func(h *History) {
			h.Mint.Justification = CTag(TagExternalMint, CArr(CUint(2), CUint(c.ChainID), CBytes(c.Vault[:]), CBytes(c.ZeroAddress[:]), CUint(7), f.StructuralProof(7).Bytes()))
		}},
		{id: "mint-pre30-pointer-reason", desc: "the pre-3.0 pointer-only lock reason v1", mut: func(h *History) {
			h.Mint.Justification = CTag(TagMintLock, CArr(CUint(1), CUint(c.ChainID), CBytes(c.Vault[:]), CBytes(c.ZeroAddress[:]), CUint(7)))
		}},
		{id: "mint-wrong-chain", desc: "justification chain ID differs", mut: func(h *History) { h.Mint.Justification = just(c.ChainID+1, c.Vault, 7) }},
		{id: "mint-zero-nonce", desc: "justification nonce 0", mut: func(h *History) { h.Mint.Justification = just(c.ChainID, c.Vault, 0) }},
		{id: "mint-other-nonce", desc: "same salt offered for another nonce", mut: func(h *History) { h.Mint.Justification = just(c.ChainID, c.Vault, 8) }},
		{id: "mint-proof-other-cfg", desc: "embedded lock proof bound to another cfg", mut: func(h *History) {
			lp := f.StructuralProof(7)
			lp.Cfg[0] ^= 1
			h.Mint.Justification = MintJustification(c.ChainID, c.Vault, c.ZeroAddress, 7, lp)
		}},
		{id: "mint-salt-changed", desc: "salt is not the derived salt", mut: func(h *History) { h.Mint.Salt[0] ^= 1 }},
		{id: "mint-null-data", desc: "null mint data", mut: func(h *History) { h.Mint.Data = nil }},
		{id: "mint-pre30-bare-payload", desc: "the pre-3.0 bare [aid, amount] payload", mut: func(h *History) { h.Mint.Data = CArr(CBytes(c.Aid[:]), CAmount(amount)) }},
		{id: "mint-wrong-asset", desc: "mint data names another asset", mut: func(h *History) { a := c.Aid; a[0] ^= 1; h.Mint.Data = ValueData(a, amount) }},
		{id: "mint-leading-zero-amount", desc: "amount with a leading zero byte", mut: func(h *History) { h.Mint.Data = rawV(CBytes([]byte{0, 1})) }},
		{id: "mint-zero-amount", desc: "amount zero", mut: func(h *History) { h.Mint.Data = rawV(CBytes(nil)) }},
		{id: "mint-two-assets", desc: "two inline assets", mut: func(h *History) {
			e := CArr(CBytes(c.Aid[:]), CAmount(amount))
			h.Mint.Data = CTag(TagValue, CArr(CUint(1), CArr(e, e), CNull))
		}},
		{id: "mint-value-memo", desc: "non-null memo slot", mut: func(h *History) {
			h.Mint.Data = CTag(TagValue, CArr(CUint(1), CArr(CArr(CBytes(c.Aid[:]), CAmount(amount))), CBytes([]byte{1})))
		}},
		{id: "transfer-data", desc: "intermediate transfer carries data", mut: func(h *History) { h.Transfers[0].Data = []byte{1} }},
		{id: "transfer-empty-data", desc: "intermediate empty data string is not null", mut: func(h *History) { h.Transfers[1].Data = []byte{} }},
		{id: "burn-before-final", desc: "burn predicate before the final transfer", mut: func(h *History) { h.Transfers[0].Recipient = BurnPredicate([32]byte{9}) }},
		{id: "final-not-burn", desc: "final transfer locks a signature predicate", mut: func(h *History) {
			h.Transfers[len(h.Transfers)-1].Recipient = sigPred(KeyFromSeed("x"))
		}},
		{id: "burn-reason-mismatch", desc: "burn parameters differ from H(R)", mut: func(h *History) { h.Transfers[len(h.Transfers)-1].Recipient = BurnPredicate([32]byte{7}) }},
		{id: "return-null-data", desc: "final transfer without return data", mut: func(h *History) { h.Transfers[len(h.Transfers)-1].Data = nil }},
		{id: "cd-source-owner", desc: "CD names another source owner", noResign: true, mut: func(h *History) { h.CDs[1].Source = sigPred(KeyFromSeed("evil")) }},
		{id: "cd-source-hash", desc: "CD source hash substituted", noResign: true, mut: func(h *History) { h.CDs[1].SourceHash[0] ^= 1 }},
		{id: "cd-tx-hash", desc: "CD tx hash substituted", noResign: true, mut: func(h *History) { h.CDs[1].TxHash[0] ^= 1 }},
		{id: "history-removed-predecessor", desc: "first transfer removed", noResign: true, mut: func(h *History) {
			h.Transfers = append(h.Transfers[:0:0], h.Transfers[1:]...)
			h.CDs = append(h.CDs[:0:0], h.CDs[1:]...)
			h.Times = append(h.Times[:0:0], h.Times[1:]...)
		}},
		{id: "history-reordered", desc: "two transfers swapped", noResign: true, mut: func(h *History) {
			h.Transfers[0], h.Transfers[1] = h.Transfers[1], h.Transfers[0]
			h.CDs[0], h.CDs[1] = h.CDs[1], h.CDs[0]
			h.Times[0], h.Times[1] = h.Times[1], h.Times[0]
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

		// Deadlines and reference times.
		{id: "deadline-null-valid", desc: "null deadlines with a far-future reference time never expire", mut: func(h *History) { h.Times[1] = 1<<64 - 1 }},
		{id: "deadline-explicit-before", desc: "explicit e with t = e-1", mut: func(h *History) { h.Transfers[1].Deadline = DeadlineAt(BaseTime + 1000); h.Times[1] = BaseTime + 999 }},
		{id: "deadline-explicit-equal", desc: "explicit e with t = e: equality rejects", mut: func(h *History) { h.Transfers[1].Deadline = DeadlineAt(BaseTime + 1000); h.Times[1] = BaseTime + 1000 }},
		{id: "deadline-explicit-after", desc: "explicit e with t = e+1", mut: func(h *History) { h.Transfers[1].Deadline = DeadlineAt(BaseTime + 1000); h.Times[1] = BaseTime + 1001 }},
		{id: "deadline-mint-explicit-equal", desc: "explicit mint deadline equal to the mint's t", mut: func(h *History) { h.Mint.Deadline = DeadlineAt(BaseTime) }},
		{id: "deadline-max", desc: "e = 2^64-1 with a small t", mut: func(h *History) { h.Transfers[0].Deadline = DeadlineAt(1<<64 - 1) }},
		{id: "deadline-cd-null-tx-explicit", desc: "transaction deadline explicit, CD null", noResign: true, mut: func(h *History) {
			h.Transfers[0].Deadline = DeadlineAt(1 << 50)
			h.Refresh()
			h.CDs[0].TxHash = H(h.transfersRaw[0])
		}},
		{id: "deadline-cd-explicit-tx-null", desc: "CD deadline explicit, transaction null", noResign: true, mut: func(h *History) { h.CDs[0].Deadline = DeadlineAt(1 << 50) }},
		{id: "deadline-cd-differs", desc: "both explicit and different", noResign: true, mut: func(h *History) {
			h.Transfers[0].Deadline = DeadlineAt(1 << 50)
			h.Refresh()
			h.CDs[0].TxHash = H(h.transfersRaw[0])
			h.CDs[0].Deadline = DeadlineAt(1<<50 + 1)
		}},
		{id: "time-mutated-mint", desc: "the mint's t mutated: only its leaf value changes", noResign: true, mut: func(h *History) { h.MintTime++ }},
		{id: "time-mutated-transfer", desc: "a transfer's t mutated: only its leaf value changes", noResign: true, mut: func(h *History) { h.Times[1]++ }},
	}
	for _, mm := range muts {
		h, keys := build(7, 3, true)
		mm.mut(h)
		if !mm.noResign {
			g.must(h.Resign(keys))
		}
		fam := "history"
		add(mm.id, fam, mm.desc, "return", h)
	}

	retMut := func(id, desc string, mk func(parts [][]byte, rcpt *[20]byte, a **big.Int) []byte) {
		h, keys := build(7, 2, true)
		var rcpt [20]byte
		rcpt[0], rcpt[19] = 0xAA, 0x01
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
		g.must(h.Resign(keys))
		add(id, "return", desc, "return", h)
	}
	retMut("return-partial-amount", "return amount below the genesis amount", func(p [][]byte, r *[20]byte, a **big.Int) []byte { *a = big.NewInt(1); return nil })
	retMut("return-zero-recipient", "zero recipient", func(p [][]byte, r *[20]byte, a **big.Int) []byte { *r = [20]byte{}; return nil })
	retMut("return-vault-recipient", "vault as recipient", func(p [][]byte, r *[20]byte, a **big.Int) []byte { *r = c.Vault; return nil })
	retMut("return-fee-token", "fee token slot set", func(p [][]byte, r *[20]byte, a **big.Int) []byte {
		p[8] = CBytes(append(make([]byte, 19), 1))
		return CTag(TagReturnReason, CArr(p...))
	})
	retMut("return-fee-amount", "fee amount slot set", func(p [][]byte, r *[20]byte, a **big.Int) []byte {
		p[9] = CBytes([]byte{1})
		return CTag(TagReturnReason, CArr(p...))
	})
	retMut("return-deadline", "fixed return fee-deadline slot set", func(p [][]byte, r *[20]byte, a **big.Int) []byte {
		p[10] = CUint(1)
		return CTag(TagReturnReason, CArr(p...))
	})
	retMut("return-wrong-asset", "reason names another asset", func(p [][]byte, r *[20]byte, a **big.Int) []byte {
		p[5] = CBytes(make([]byte, 32))
		return CTag(TagReturnReason, CArr(p...))
	})
	h, _ = build(7, 2, true)
	add("return-valid-recheck", "return", "a returned history; the nullifier excludes referenceTime, paths and submitter", "return", h)
	// Nullifier independence from t: the same burn at another time has the same eta.
	h2, _ := build(7, 2, true)
	for i := range h2.Times {
		h2.Times[i] += 12345
	}
	add("return-same-burn-other-time", "return", "the same burn certified at other times: same nullifier, other leaf values", "return", h2)
	// Operation shape.
	g.add(Case{ID: "return-negative-integer", Family: "wire", Op: "return", Cfg: "dev", Description: "CBOR major type 1 (-1) as the whole return input", Input: "20"})
	g.add(Case{ID: "return-negative-integer-nonminimal", Family: "wire", Op: "return", Cfg: "dev", Description: "major type 1 with a non-shortest head", Input: "3800"})
}

func (g *gen) wire() {
	f := g.d.F
	amount := big.NewInt(1_000_000_007)
	keys := []*secp256k1.PrivateKey{KeyFromSeed("w-a"), KeyFromSeed("w-b"), KeyFromSeed("w-c")}
	h, err := f.BuildToken(7, amount, keys)
	g.must(err)
	var rcpt [20]byte
	rcpt[0], rcpt[19] = 0xAA, 0x01
	f.AppendBurn(h, keys[2], rcpt, amount)
	good := h.Bytes()
	add := func(id, desc string, b []byte) {
		g.add(Case{ID: id, Family: "wire", Op: "return", Cfg: "dev", Description: desc, Input: hx(b)})
	}
	add("wire-trailing", "history with a trailing byte", append(bytes.Clone(good), 0))
	add("wire-truncated", "history truncated by one byte", good[:len(good)-1])
	add("wire-indefinite", "indefinite-length array", []byte{0x9f, 0xff})
	add("wire-nonminimal-head", "array head 0x9802 instead of 0x82", []byte{0x98, 0x02})
	add("wire-text", "text string", []byte{0x61, 'a'})
	add("wire-map", "map", []byte{0xa0})
	add("wire-float", "half float", []byte{0xf9, 0, 0})
	add("wire-oversized", "history over the 128 KiB semantic bound", make([]byte, MaxSemanticBytes+1))
	add("wire-nesting-bomb", "CBOR nesting over the depth bound", bytes.Repeat([]byte{0x81}, MaxCBORDepth+2))
	add("wire-count-bomb", "array count above the remaining bytes", []byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	t0 := h.Transfers[0]
	tb := t0.Bytes()
	rep := func(id, desc string, repl []byte, orig []byte) { add(id, desc, replaceOnce(good, orig, repl)) }
	rep("wire-transfer-version", "transfer version literal 3", CTag(TagTransfer, CArr(CUint(3), t0.Recipient.Bytes(), CBytes(t0.Mask[:]), CNull, CNull)), tb)
	rep("wire-transfer-extra-field", "transfer with a sixth field", CTag(TagTransfer, CArr(CUint(2), t0.Recipient.Bytes(), CBytes(t0.Mask[:]), CNull, CNull, CNull)), tb)
	rep("wire-transfer-tag", "transfer with tag 39046", CTag(TagTransfer+1, CArr(CUint(2), t0.Recipient.Bytes(), CBytes(t0.Mask[:]), CNull, CNull)), tb)
	rep("wire-transfer-short-mask", "31 byte state mask", CTag(TagTransfer, CArr(CUint(2), t0.Recipient.Bytes(), CBytes(t0.Mask[:31]), CNull, CNull)), tb)
	rep("wire-pre30-transfer", "pre-3.0 transfer: version 1, arity 4", CTag(TagTransfer, CArr(CUint(1), t0.Recipient.Bytes(), CBytes(t0.Mask[:]), CNull)), tb)
	mb := h.Mint.Bytes()
	rep("wire-pre30-mint", "pre-3.0 mint: version 1, arity 7", CTag(TagMint, CArr(CUint(1), CUint(uint64(h.Mint.Network)), h.Mint.Recipient.Bytes(), CBytes(h.Mint.Salt[:]), CBytes(h.Mint.Type[:]), CNullOr(h.Mint.Justification), CNullOr(h.Mint.Data))), mb)
	rep("wire-v1-mint-new-arity", "mint with the new arity but version 1", CTag(TagMint, CArr(CUint(1), CUint(uint64(h.Mint.Network)), h.Mint.Recipient.Bytes(), CBytes(h.Mint.Salt[:]), CBytes(h.Mint.Type[:]), CNullOr(h.Mint.Justification), CNullOr(h.Mint.Data), CNull)), mb)
	cb := h.MintCD.Bytes()
	c := h.MintCD
	rep("wire-pre30-cd", "pre-3.0 CD: version 1, arity 5, no deadline", CTag(TagCertification, CArr(CUint(1), c.Source.Bytes(), CBytes(c.SourceHash[:]), CBytes(c.TxHash[:]), CBytes(c.Unlock))), cb)
	rep("wire-cd-deadline-after-unlock", "CD with the deadline after the unlock", CTag(TagCertification, CArr(CUint(2), c.Source.Bytes(), CBytes(c.SourceHash[:]), CBytes(c.TxHash[:]), CBytes(c.Unlock), CNull)), cb)
	rep("wire-cd-deadline-zero", "CD deadline 0", CTag(TagCertification, CArr(CUint(2), c.Source.Bytes(), CBytes(c.SourceHash[:]), CBytes(c.TxHash[:]), CUint(0), CBytes(c.Unlock))), cb)
	rep("wire-transfer-deadline-zero", "transfer deadline 0", CTag(TagTransfer, CArr(CUint(2), t0.Recipient.Bytes(), CBytes(t0.Mask[:]), CNull, CUint(0))), tb)
	rep("wire-transfer-deadline-bytes", "transfer deadline as a byte string", CTag(TagTransfer, CArr(CUint(2), t0.Recipient.Bytes(), CBytes(t0.Mask[:]), CNull, CBytes([]byte{1}))), tb)
	rep("wire-transfer-deadline-nonminimal", "transfer deadline 1 as 0x1801", CTag(TagTransfer, CArr(CUint(2), t0.Recipient.Bytes(), CBytes(t0.Mask[:]), CNull, []byte{0x18, 1})), tb)
	rep("wire-pre30-projection-pair", "pre-3.0 projection tuple without t", CArr(h.Transfers[0].Bytes(), h.CDs[0].Bytes()), tb)
	pt := t0.Recipient.Bytes()
	k1 := keys[1].PubKey().SerializeCompressed()
	for _, pv := range []struct {
		id, desc string
		p        []byte
	}{
		{"wire-predicate-engine", "predicate engine 2", CTag(TagPredicate, CArr(CUint(2), CBytes([]byte{1}), CBytes(k1)))},
		{"wire-predicate-text-code", "predicate code is the text name", CTag(TagPredicate, CArr(CUint(1), CBytes([]byte("signature")), CBytes(k1)))},
		{"wire-predicate-nonminimal-code", "code bytes 1801", CTag(TagPredicate, CArr(CUint(1), CBytes([]byte{0x18, 1}), CBytes(k1)))},
		{"wire-predicate-uncompressed", "uncompressed key", CTag(TagPredicate, CArr(CUint(1), CBytes([]byte{1}), CBytes(append([]byte{4}, make([]byte, 64)...))))},
	} {
		rep(pv.id, pv.desc, pv.p, pt)
	}

	// SDK tokens: strict decode and projection.
	cp, err := g.certified(3)
	g.must(err)
	tok := TokenFromHistory(cp.h, cp.cert.InclusionProofs())
	tbts := tok.Bytes()
	tadd := func(id, desc string, b []byte) {
		g.add(Case{ID: id, Family: "wire", Op: "token-project", Description: desc, Input: hx(b)})
	}
	tadd("token-valid", "a certified token projects to the kernel's history bytes", tbts)
	tadd("token-trailing", "token with a trailing byte", append(bytes.Clone(tbts), 0))
	root, _ := scanOneNative(tbts)
	k := root.kids[0].kids
	sl2 := func(i int) []byte { return tbts[k[i].start:k[i].end] }
	tk := func(items ...[]byte) []byte { return CTag(TagToken, CArr(items...)) }
	tadd("token-version-1", "token version 1", tk(CUint(1), sl2(1), sl2(2)))
	tadd("token-third-slot", "token with a separate third reference-time slot", tk(CUint(2), sl2(1), sl2(2), CUint(5)))
	tadd("token-wrong-tag", "token tag 39041", CTag(TagToken+1, CArr(CUint(2), sl2(1), sl2(2))))
	tadd("token-genesis-no-proof", "genesis without its proof", tk(CUint(2), CArr(sl2(1)), sl2(2)))
	p0 := tok.MintProof.Bytes()
	cd0 := tok.MintProof.CD.Bytes()
	path := append([]byte{}, tok.MintProof.Bitmap[:]...)
	for _, s := range tok.MintProof.Siblings {
		path = append(path, s[:]...)
	}
	pr := func(items ...[]byte) []byte { return CTag(TagInclusion, CArr(items...)) }
	uc0 := tok.MintProof.UC
	tadd("token-proof-pending", "a pending aggregator response in place of the proof", replaceOnce(tbts, p0, CNull))
	tadd("token-proof-pre30-no-time", "pre-3.0 proof arity 4 without t", replaceOnce(tbts, p0, pr(CUint(1), cd0, CBytes(path), uc0)))
	tadd("token-proof-version-2", "inclusion proof version 2", replaceOnce(tbts, p0, pr(CUint(2), cd0, CUint(tok.MintProof.T), CBytes(path), uc0)))
	tadd("token-proof-bad-path-length", "path one byte short", replaceOnce(tbts, p0, pr(CUint(1), cd0, CUint(tok.MintProof.T), CBytes(path[:len(path)-1]), uc0)))
	tadd("token-proof-extra-sibling", "a sibling beyond the bitmap", replaceOnce(tbts, p0, pr(CUint(1), cd0, CUint(tok.MintProof.T), CBytes(append(bytes.Clone(path), make([]byte, 32)...)), uc0)))
	tadd("token-proof-no-certificate", "null certificate", replaceOnce(tbts, p0, pr(CUint(1), cd0, CUint(tok.MintProof.T), CBytes(path), CNull)))
	tadd("token-proof-certificate-not-decodable", "a tagged item that is not an SDK-decodable certificate", replaceOnce(tbts, p0, pr(CUint(1), cd0, CUint(tok.MintProof.T), CBytes(path), CTag(1, CBytes([]byte{1})))))
	tadd("token-proof-signature-64-bytes", "certificate whose seal signatures are 64 bytes", replaceOnce(tbts, p0, pr(CUint(1), cd0, CUint(tok.MintProof.T), CBytes(path), g.shortSigUC(uc0))))
	for _, mutation := range certificateMutations() {
		uc, err := replaceCertificateItem(uc0, mutation.replacement, mutation.path...)
		g.must(err)
		tadd("token-certificate-"+mutation.name, "isolated certificate intersection: "+mutation.name, replaceOnce(tbts, p0, pr(CUint(1), cd0, CUint(tok.MintProof.T), CBytes(path), uc)))
	}
	for _, n := range []int{224, 225} {
		uc, err := certificateWithSteps(uc0, 32)
		g.must(err)
		keys := make([]*secp256k1.PrivateKey, 8)
		for i := range keys {
			keys[i] = KeyFromSeed(fmt.Sprintf("budget-owner-%d", i))
		}
		h, err := g.d.F.BuildToken(5, big.NewInt(123), keys)
		g.must(err)
		proofs := make([]InclusionProof, 8)
		for i := range proofs {
			proofs[i].UC = uc
			siblings := 224
			if i == 0 {
				siblings = n
			}
			for bit := 0; bit < siblings; bit++ {
				proofs[i].Bitmap[bit/8] |= 1 << (bit % 8)
			}
			proofs[i].Siblings = make([][32]byte, siblings)
		}
		tadd(fmt.Sprintf("token-combined-path-%d", 2048+n-224), "combined RSMT and Unicity path budget", TokenFromHistory(h, proofs).Bytes())
	}
	tadd("token-proof-oversized-certificate", "certificate over the proof bound", replaceOnce(tbts, p0, pr(CUint(1), cd0, CUint(tok.MintProof.T), CBytes(path), CTag(1, CBytes(make([]byte, MaxProofUCBytes))))))
	// Kernel ABI.
	cfgB := f.Cfg.Bytes()
	kin := func(op uint8, payload []byte) []byte {
		b, err := EncodeKernelInput(op, cfgB, payload)
		g.must(err)
		return b
	}
	kadd := func(id, desc string, b []byte) {
		g.add(Case{ID: id, Family: "wire", Op: "kernel", Cfg: "dev", Description: desc, Input: hx(b)})
	}
	kadd("kernel-return-valid", "the kernel output for a returned history: 448+128*m bytes", kin(OpReturn, cp.h.Bytes()))
	mt, err := f.BuildToken(5, amount, keys[:1])
	g.must(err)
	kadd("kernel-mint-valid", "the kernel output for a mint: 448+128 bytes", kin(OpMint, mt.Bytes()))
	kadd("kernel-prepare-valid", "prepareLock output: no leaves", kin(OpPrepareLock, PreparePayload(5, amount, sigPred(keys[0]).Bytes())))
	kadd("kernel-mint-with-transfers", "a relation that does not hold: the all-zero false output", kin(OpMint, cp.h.Bytes()))
	kadd("kernel-malformed-history", "a malformed history halts", kin(OpReturn, append(cp.h.Bytes(), 0)))
	kadd("kernel-bad-operation", "operation 9", kin(9, nil))
	kin1 := kin(OpReturn, cp.h.Bytes())
	kadd("kernel-input-trailing-word", "input with a trailing word", append(bytes.Clone(kin1), make([]byte, 32)...))
	kadd("kernel-input-unaligned", "input not a word multiple", kin1[:len(kin1)-1])
	bad := *f.Cfg
	bad.Ty[0] ^= 1
	b, _ := EncodeKernelInput(OpReturn, bad.Bytes(), cp.h.Bytes())
	kadd("kernel-cfg-identity-not-derived", "Cfg whose identifiers are not derived: the false output", b)
}

type certifiedHistory struct {
	h    *History
	res  *Result
	cert *CertifiedLeaves
	keys []*secp256k1.PrivateKey
}

// certified builds a return history with `transfers` ordinary transfers and
// the aggregator certificate over its leaves at an IR time after every t.
func (g *gen) certified(transfers int) (*certifiedHistory, error) {
	f := g.d.F
	keys := make([]*secp256k1.PrivateKey, transfers+1)
	for i := range keys {
		keys[i] = KeyFromSeed(fmt.Sprintf("cert-%d", i))
	}
	h, err := f.BuildToken(5, big.NewInt(1_000_000_007), keys)
	if err != nil {
		return nil, err
	}
	var rcpt [20]byte
	rcpt[0], rcpt[19] = 0xAA, 0x01
	f.AppendBurn(h, keys[len(keys)-1], rcpt, big.NewInt(1_000_000_007))
	res, err := VerifyReturn(f.Cfg, h.Bytes())
	if err != nil {
		return nil, err
	}
	extra := []Leaf{{SID: H([]byte("other-1")), Value: H([]byte("v1"))}, {SID: H([]byte("other-2")), Value: H([]byte("v2"))}}
	cert, err := g.d.Agg.Certify(res.Leaves, extra, BaseTime+1000, 100)
	if err != nil {
		return nil, err
	}
	return &certifiedHistory{h: h, res: res, cert: cert, keys: keys}, nil
}

func claimOf(a Anchor) string { return h32(a.ExpectedStateRoot) + ":" + h32(a.ExpectedIRHash) }

func (g *gen) lock() {
	d := g.d
	f := d.F
	amount := big.NewInt(1_000_000_007)
	keys := []*secp256k1.PrivateKey{KeyFromSeed("lock-a")}
	h, lp, err := d.Backed(5, amount, keys)
	g.must(err)
	if err != nil {
		return
	}
	// Justification structure and bounds.
	j := h.Mint.Justification
	g.add(Case{ID: "justification-valid", Family: "lock", Op: "justification", Cfg: "dev", Description: "tag 39049 version 2 with the embedded LockProof", Input: hx(j)})
	jf := func(mut func(lp *LockProof)) []byte {
		p := f.StructuralProof(5)
		mut(p)
		return MintJustification(f.Cfg.ChainID, f.Cfg.Vault, f.Cfg.ZeroAddress, 5, p)
	}
	fill := func(n int) []byte { return bytes.Repeat([]byte{7}, n) }
	nodes := func(n, size int) [][]byte {
		out := make([][]byte, n)
		for i := range out {
			out[i] = fill(size)
		}
		return out
	}
	bounds := []struct {
		name     string
		at, over func(lp *LockProof)
	}{
		{"pdr", func(lp *LockProof) { lp.PDR = fill(MaxLockPDRBytes) }, func(lp *LockProof) { lp.PDR = fill(MaxLockPDRBytes + 1) }},
		{"uc", func(lp *LockProof) { lp.UC = fill(MaxLockUCBytes) }, func(lp *LockProof) { lp.UC = fill(MaxLockUCBytes + 1) }},
		{"header", func(lp *LockProof) { lp.Header = fill(MaxLockHeaderBytes) }, func(lp *LockProof) { lp.Header = fill(MaxLockHeaderBytes + 1) }},
		{"node-size", func(lp *LockProof) { lp.AccountNodes = nodes(1, MaxMPTNodeBytes) }, func(lp *LockProof) { lp.AccountNodes = nodes(1, MaxMPTNodeBytes+1) }},
		{"node-count", func(lp *LockProof) { lp.AccountNodes = nodes(MaxMPTNodes, 8) }, func(lp *LockProof) { lp.AccountNodes = nodes(MaxMPTNodes+1, 8) }},
		{"mpt-combined", func(lp *LockProof) {
			lp.AccountNodes = nodes(12, MaxMPTNodeBytes)
			lp.StorageNodes = nodes(12, MaxMPTNodeBytes)
		}, func(lp *LockProof) {
			lp.AccountNodes = nodes(12, MaxMPTNodeBytes)
			lp.StorageNodes = append(nodes(12, MaxMPTNodeBytes), fill(1))
		}},
	}
	for _, b := range bounds {
		g.add(Case{ID: "justification-bound-" + b.name + "-at", Family: "lock", Op: "justification", Cfg: "dev", Description: b.name + " exactly at its bound", Input: hx(jf(b.at))})
		g.add(Case{ID: "justification-bound-" + b.name + "-over", Family: "lock", Op: "justification", Cfg: "dev", Description: b.name + " one over its bound", Input: hx(jf(b.over))})
	}
	g.add(Case{ID: "justification-over-64k", Family: "lock", Op: "justification", Cfg: "dev", Description: "J one byte over 64 KiB", Input: hx(make([]byte, MaxJustificationBytes+1))})
	g.add(Case{ID: "justification-empty-uc", Family: "lock", Op: "justification", Cfg: "dev", Description: "empty certificate", Input: hx(jf(func(lp *LockProof) { lp.UC = nil }))})
	g.add(Case{ID: "justification-empty-account-nodes", Family: "lock", Op: "justification", Cfg: "dev", Description: "empty account node list", Input: hx(jf(func(lp *LockProof) { lp.AccountNodes = nil }))})
	g.add(Case{ID: "justification-missing-proof", Family: "lock", Op: "justification", Cfg: "dev", Description: "null in place of the proof: a rejection, never a fetch",
		Input: hx(CTag(TagMintLock, CArr(CUint(2), CUint(f.Cfg.ChainID), CBytes(f.Cfg.Vault[:]), CBytes(f.Cfg.ZeroAddress[:]), CUint(5), CNull)))})
	sp := f.StructuralProof(5)
	g.add(Case{ID: "justification-receipt-alternative", Family: "lock", Op: "justification", Cfg: "dev", Description: "a receipt-style alternative in the storage slot",
		Input: hx(CTag(TagMintLock, CArr(CUint(2), CUint(f.Cfg.ChainID), CBytes(f.Cfg.Vault[:]), CBytes(f.Cfg.ZeroAddress[:]), CUint(5),
			CArr(CUint(1), CBytes(sp.Cfg[:]), CBytes(sp.TrustBaseID[:]), CBytes(sp.PDR), CBytes(sp.UC), CBytes(sp.Header), CArr(CBytes(sp.AccountNodes[0])), CBytes(sp.StorageNodes[0])))))})
	g.add(Case{ID: "justification-proof-version-2", Family: "lock", Op: "justification", Cfg: "dev", Description: "LockProof version 2",
		Input: hx(CTag(TagMintLock, CArr(CUint(2), CUint(f.Cfg.ChainID), CBytes(f.Cfg.Vault[:]), CBytes(f.Cfg.ZeroAddress[:]), CUint(5),
			CArr(CUint(2), CBytes(sp.Cfg[:]), CBytes(sp.TrustBaseID[:]), CBytes(sp.PDR), CBytes(sp.UC), CBytes(sp.Header), CArr(CBytes(sp.AccountNodes[0])), CArr(CBytes(sp.StorageNodes[0]))))))})

	back := func(id, desc string, hh *History, trustBase, pin string) {
		g.add(Case{ID: id, Family: "lock", Op: "lock-backing", Cfg: "dev", Description: desc, Input: hx(hh.Bytes()), Aux: map[string]string{"trustBase": trustBase, "pin": pin}})
	}
	back("backing-valid", "the real embedded certified lock proof verifies offline", h, "pinned", "dev")
	remint := func(mut func(lp *LockProof)) *History {
		c := *lp
		mut(&c)
		hh, err := f.BuildTokenWith(5, amount, keys, BuildOpts{Proof: &c})
		g.must(err)
		return hh
	}
	for _, mutation := range certificateMutations() {
		back("backing-certificate-"+mutation.name, "isolated certificate intersection: "+mutation.name, remint(func(p *LockProof) {
			var err error
			p.UC, err = replaceCertificateItem(p.UC, mutation.replacement, mutation.path...)
			g.must(err)
		}), "pinned", "dev")
	}
	flip := func(b []byte, i int) []byte { c := bytes.Clone(b); c[i] ^= 1; return c }
	reUC := func(fn func(uc *types.UnicityCertificate)) func(lp *LockProof) {
		return func(lp *LockProof) {
			var uc types.UnicityCertificate
			g.must(types.Cbor.Unmarshal(lp.UC, &uc))
			fn(&uc)
			b, err := types.Cbor.Marshal(&uc)
			g.must(err)
			lp.UC = b
		}
	}
	for _, c := range []struct {
		id, desc string
		mut      func(lp *LockProof)
	}{
		{"backing-trust-base-digest", "trustBaseId is not the digest of the installed document", func(lp *LockProof) { lp.TrustBaseID[0] ^= 1 }},
		{"backing-other-cfg", "proof bound to another cfg", func(lp *LockProof) { lp.Cfg[0] ^= 1 }},
		{"backing-uc-signature", "a seal signature byte flipped", reUC(func(uc *types.UnicityCertificate) {
			keysSorted := []string{}
			for k := range uc.UnicitySeal.Signatures {
				keysSorted = append(keysSorted, k)
			}
			sort.Strings(keysSorted)
			for _, k := range keysSorted {
				uc.UnicitySeal.Signatures[k] = flip(uc.UnicitySeal.Signatures[k], 3)
			}
		})},
		{"backing-uc-signature-64-bytes", "every seal signature cut to 64 bytes: inside native B1's accepted widths, outside the SDK codec", reUC(func(uc *types.UnicityCertificate) {
			for k, sig := range uc.UnicitySeal.Signatures {
				uc.UnicitySeal.Signatures[k] = sig[:64]
			}
		})},
		{"backing-uc-state-root", "certified state hash altered", reUC(func(uc *types.UnicityCertificate) { uc.InputRecord.Hash[0] ^= 1 })},
		{"backing-uc-network", "seal names another network", reUC(func(uc *types.UnicityCertificate) { uc.UnicitySeal.NetworkID++ })},
		{"backing-uc-noncanonical", "certificate with a trailing byte", func(lp *LockProof) { lp.UC = append(bytes.Clone(lp.UC), 0) }},
		{"backing-pdr-noncanonical", "partition description with a trailing byte", func(lp *LockProof) { lp.PDR = append(bytes.Clone(lp.PDR), 0) }},
		{"backing-pdr-flipped", "partition description byte flipped", func(lp *LockProof) { lp.PDR = flip(lp.PDR, len(lp.PDR)-2) }},
		{"backing-header-flipped", "header byte flipped", func(lp *LockProof) { lp.Header = flip(lp.Header, 40) }},
		{"backing-account-node-flipped", "account node corrupted", func(lp *LockProof) { lp.AccountNodes = cloneNodes(lp.AccountNodes); lp.AccountNodes[0][5] ^= 1 }},
		{"backing-account-extraneous", "an extraneous account node", func(lp *LockProof) { lp.AccountNodes = append(cloneNodes(lp.AccountNodes), lp.AccountNodes[0]) }},
		{"backing-account-dropped", "the last account node dropped", func(lp *LockProof) { lp.AccountNodes = lp.AccountNodes[:len(lp.AccountNodes)-1] }},
		{"backing-storage-node-flipped", "storage node corrupted", func(lp *LockProof) { lp.StorageNodes = cloneNodes(lp.StorageNodes); lp.StorageNodes[0][3] ^= 1 }},
		{"backing-storage-extraneous", "an extraneous storage node", func(lp *LockProof) { lp.StorageNodes = append(cloneNodes(lp.StorageNodes), lp.StorageNodes[0]) }},
		{"backing-storage-is-account-proof", "the account proof offered as the storage proof", func(lp *LockProof) { lp.StorageNodes = lp.AccountNodes }},
	} {
		back(c.id, c.desc, remint(c.mut), "pinned", "dev")
	}
	// A certificate over an unrelated state root: header not bound.
	w := &LockWorld{Vault: d.World.Vault, VaultCodeHash: d.World.VaultCodeHash, Locks: map[uint64][32]byte{5: d.World.Locks[5]}, Filler: 2}
	other, err := w.Certified(f, d.Auth, d.EVMPDR, d.Trust, DevRootRound, 5, 9)
	g.must(err)
	back("backing-header-not-bound", "a quorum-signed certificate over another state root and header hash", remint(func(lp *LockProof) { lp.UC = other.UC }), "pinned", "dev")
	isolated := func(id, desc string, mut func(ir *types.InputRecord)) {
		p, err := d.World.CertifiedWith(f, d.Auth, d.EVMPDR, d.Trust, DevRootRound, 5, 9, mut)
		g.must(err)
		if err == nil {
			back(id, desc, remint(func(lp *LockProof) { *lp = *p }), "pinned", "dev")
		}
	}
	isolated("backing-ir-state-root-differs", "certified state hash is not the header's state root; the block hash still matches", func(ir *types.InputRecord) { ir.Hash = sl(H([]byte("unrelated-state-root"))) })
	isolated("backing-ir-block-hash-differs", "certified block hash is not keccak256 of the header; the state root still matches", func(ir *types.InputRecord) { ir.BlockHash = sl(H([]byte("unrelated-block"))) })
	isolated("backing-ir-summary-over-native-sublimit", "certified input record with a 257-byte summary: over the native 256-byte sublimit", func(ir *types.InputRecord) { ir.SummaryValue = bytes.Repeat([]byte{1}, MaxSummaryBytes+1) })
	isolated("backing-ir-epoch-differs-from-pdr", "certified shard epoch differs from the carried configuration's epoch", func(ir *types.InputRecord) { ir.Epoch = 5 })
	back("backing-other-runtime-pin", "the vault runtime pin differs", h, "pinned", "other-runtime")
	back("backing-other-genesis-pin", "the pinned genesis configuration differs", h, "pinned", "other-genesis")
	back("backing-no-pin", "no deployment pin installed", h, "pinned", "none")
	// Binding to the actual mint.
	lpFor := func(n uint64) *LockProof { c := *lp; return &c }
	hb := func(n uint64, a *big.Int, k *secp256k1.PrivateKey) *History {
		hh, err := f.BuildTokenWith(n, a, []*secp256k1.PrivateKey{k}, BuildOpts{Proof: lpFor(n)})
		g.must(err)
		return hh
	}
	back("backing-amount-differs", "mint amount differs from the locked amount", hb(5, new(big.Int).Add(amount, big.NewInt(1)), keys[0]), "pinned", "dev")
	back("backing-recipient-differs", "mint recipient differs from the locked recipient", hb(5, amount, KeyFromSeed("thief")), "pinned", "dev")
	back("backing-nonce-differs", "proof of nonce 5 offered for nonce 6", hb(6, amount, keys[0]), "pinned", "dev")
	back("backing-next-epoch-trust-base", "a different document (another epoch, same keys) is installed: digest mismatch", h, "next-epoch-same-keys", "dev")
	back("backing-rogue-authority", "a document whose only authority is another key is installed", h, "rogue-authority", "dev")
	back("backing-non-unit-weight", "unsupported configuration: a validator of weight 2", h, "non-unit-weight", "dev")
	back("backing-threshold", "unsupported configuration: quorumThreshold is not N-(N-1)/3", h, "threshold-not-n-minus-third", "dev")
	// Unit-weight count-quorum boundaries: N-(N-1)/3 distinct valid signers accept, one fewer rejects.
	for _, c := range []struct{ n, q int }{{3, 3}, {4, 3}, {7, 5}} {
		name := fmt.Sprintf("committee-%d", c.n)
		raw, _ := hex.DecodeString(g.fs.TrustBases[name])
		ti, err := LoadTrustInput(raw)
		g.must(err)
		com, err := NewCommittee(fmt.Sprintf("quorum-%d", c.n), c.n)
		g.must(err)
		if ti == nil || com == nil {
			continue
		}
		for _, k := range []int{c.q, c.q - 1} {
			com.Signers = k
			p, err := d.World.Certified(f, com, d.EVMPDR, ti, DevRootRound, 5, 9)
			g.must(err)
			if p == nil {
				continue
			}
			id, desc := fmt.Sprintf("backing-quorum-n%d-signers%d", c.n, k), fmt.Sprintf("%d validators, threshold %d: %d distinct valid signers", c.n, c.q, k)
			back(id, desc, remint(func(lp *LockProof) { *lp = *p }), name, "dev")
		}
	}
	// A proof that names the installed document but whose certificate lies outside the one pinned base.
	for _, c := range []struct{ id, desc, base string }{
		{"backing-epoch-mismatch", "the proof names the installed document (epoch 2) but its certificate is sealed in root epoch 1", "next-epoch-same-keys"},
		{"backing-epoch-start-after", "certificate root round before the base's epochStartRound", "epoch-start-after-certificate"},
		{"backing-other-network", "the installed document is for another network", "other-network"},
	} {
		raw, _ := hex.DecodeString(g.fs.TrustBases[c.base])
		ti, err := LoadTrustInput(raw)
		g.must(err)
		if err != nil {
			continue
		}
		back(c.id, c.desc, remint(func(lp *LockProof) { lp.TrustBaseID = ti.ID() }), c.base, "dev")
	}
	// J mutation after certification.
	hm := *h
	hm.Mint.Justification = flip(h.Mint.Justification, len(h.Mint.Justification)-3)
	hm.Refresh()
	g.add(Case{ID: "mint-j-mutated-after-certification", Family: "lock", Op: "mint", Cfg: "dev", Description: "J changed after the mint was certified: the CD no longer matches", Input: hx(hm.Bytes())})
	// Raw MPT proofs from the real world.
	ev, err := d.World.Evidence(5, 9)
	g.must(err)
	if err == nil {
		sk := StorageTrieKey(LockDigestSlot(5))
		join := func(ns [][]byte) string {
			s := make([]string, len(ns))
			for i, n := range ns {
				s[i] = hx(n)
			}
			return strings.Join(s, ",")
		}
		mp := func(id, desc string, root, key [32]byte, ns [][]byte) {
			g.add(Case{ID: id, Family: "lock", Op: "mpt", Description: desc, Input: "", Aux: map[string]string{"root": h32(root), "key": h32(key), "nodes": join(ns)}})
		}
		mp("mpt-storage-valid", "the lock word under the vault's storage root", ev.StorageRoot, sk, ev.StorageNodes)
		mp("mpt-storage-extra-node", "an extraneous node after the leaf", ev.StorageRoot, sk, append(cloneNodes(ev.StorageNodes), ev.StorageNodes[0]))
		mp("mpt-storage-wrong-root", "wrong root", [32]byte{1}, sk, ev.StorageNodes)
		mp("mpt-storage-other-key", "another key under the same nodes", ev.StorageRoot, StorageTrieKey(LockDigestSlot(6)), ev.StorageNodes)
		ak := AccountTrieKey(f.Cfg.Vault)
		mp("mpt-account-valid", "the vault account under the state root", ev.StateRoot, ak, ev.AccountNodes)
		if len(ev.AccountNodes) > 1 {
			sw := cloneNodes(ev.AccountNodes)
			sw[0], sw[1] = sw[1], sw[0]
			mp("mpt-account-out-of-order", "account nodes out of order", ev.StateRoot, ak, sw)
			mp("mpt-account-missing-leaf", "the last account node dropped", ev.StateRoot, ak, ev.AccountNodes[:len(ev.AccountNodes)-1])
		}
	}
}

func (g *gen) proof() {
	d := g.d
	f := d.F
	cp, err := g.certified(3)
	g.must(err)
	if err != nil {
		return
	}
	claims := claimOf(cp.cert.Anchor)
	envFrom := func(mut func(e *Envelope)) []byte {
		e := &Envelope{PolicyBody: f.Policy.Bytes(), History: cp.h.Bytes(), Anchors: []Anchor{cp.cert.Anchor}, LeafProofs: append([]LeafProof{}, cp.cert.Proofs...)}
		if mut != nil {
			mut(e)
		}
		b, err := e.Encode()
		g.must(err)
		return b
	}
	add := func(id, desc string, env []byte, claims string, op string) {
		g.add(Case{ID: id, Family: "proof", Op: "compose", Cfg: "dev", Description: desc, Input: hx(env),
			Aux: map[string]string{"operation": op, "claims": claims}})
	}
	add("compose-valid-return", "an authenticated anchor, its IR opening, every leaf proven under it", envFrom(nil), claims, "return")
	add("compose-anchor-not-admitted", "B1 does not authenticate the anchor", envFrom(nil), "", "return")
	add("compose-expected-ir-hash", "expected IR hash not the authenticated one", envFrom(func(e *Envelope) { e.Anchors[0].ExpectedIRHash[0] ^= 1 }), claims, "return")
	// IR opening attacks.
	ir := cp.cert.Anchor.InputRecord
	lie := rewriteIRBytes(ir, func(r *types.InputRecord) { r.Timestamp = 1 << 60 })
	add("compose-false-opening", "an opening with a huge timestamp for the same expected hash", envFrom(func(e *Envelope) { e.Anchors[0].InputRecord = lie }), claims, "return")
	add("compose-empty-opening", "no opening", envFrom(func(e *Envelope) { e.Anchors[0].InputRecord = nil }), claims, "return")
	// Time bound: IR time at and just before the latest t.
	maxT := BaseTime + 10*uint64(4)
	for _, c := range []struct {
		id, desc string
		t        uint64
	}{{"compose-ir-time-equals-latest-t", "IR timestamp equals the latest t", maxT}, {"compose-ir-time-before-latest-t", "IR timestamp one second before the latest t", maxT - 1}} {
		extra := []Leaf{{SID: H([]byte("other-1")), Value: H([]byte("v1"))}}
		cert, err := d.Agg.Certify(cp.res.Leaves, extra, c.t, 100)
		g.must(err)
		e := &Envelope{PolicyBody: f.Policy.Bytes(), History: cp.h.Bytes(), Anchors: []Anchor{cert.Anchor}, LeafProofs: cert.Proofs}
		b, err := e.Encode()
		g.must(err)
		add(c.id, c.desc, b, claimOf(cert.Anchor), "return")
	}
	// Leaf confusion.
	confused := make([]Leaf, len(cp.res.Leaves))
	for i, l := range cp.res.Leaves {
		confused[i] = Leaf{SID: l.SID, Value: l.TxHash}
	}
	cc, err := d.Agg.Certify(confused, nil, BaseTime+1000, 100)
	g.must(err)
	eb, _ := (&Envelope{PolicyBody: f.Policy.Bytes(), History: cp.h.Bytes(), Anchors: []Anchor{cc.Anchor}, LeafProofs: cc.Proofs}).Encode()
	add("compose-txhash-as-leaf-value", "the tree commits txHash alone as the value", eb, claimOf(cc.Anchor), "return")
	add("compose-paths-swapped", "the first two paths swapped", envFrom(func(e *Envelope) { e.LeafProofs[0], e.LeafProofs[1] = e.LeafProofs[1], e.LeafProofs[0] }), claims, "return")
	add("compose-corrupt-path", "one sibling corrupted", envFrom(func(e *Envelope) {
		s := append([][32]byte{}, e.LeafProofs[1].Siblings...)
		s[0][0] ^= 1
		e.LeafProofs[1].Siblings = s
	}), claims, "return")
	add("compose-too-few-paths", "one path missing", envFrom(func(e *Envelope) { e.LeafProofs = e.LeafProofs[:2] }), claims, "return")
	// Refresh: same leaves under a later anchor keep their original t.
	later, err := d.Agg.Certify(cp.res.Leaves, []Leaf{{SID: H([]byte("newer")), Value: H([]byte("n"))}}, BaseTime+1000+3600, 900)
	g.must(err)
	eb, _ = (&Envelope{PolicyBody: f.Policy.Bytes(), History: cp.h.Bytes(), Anchors: []Anchor{later.Anchor}, LeafProofs: later.Proofs}).Encode()
	add("compose-refresh-later-anchor", "the same leaves proven under a later admitted root keep their original t", eb, claimOf(later.Anchor), "return")
	hs := *cp.h
	hs.Times = append([]uint64{}, cp.h.Times...)
	for i := range hs.Times {
		hs.Times[i] = BaseTime + 1000 + 3600
	}
	hs.MintTime = BaseTime + 1000 + 3600
	eb, _ = (&Envelope{PolicyBody: f.Policy.Bytes(), History: hs.Bytes(), Anchors: []Anchor{later.Anchor}, LeafProofs: later.Proofs}).Encode()
	add("compose-refresh-rewritten-t", "a refresh that substitutes the new certificate's timestamp for t", eb, claimOf(later.Anchor), "return")
	// Mint operation.
	mt, err := f.BuildToken(5, big.NewInt(1_000_000_007), cp.keys[:1])
	g.must(err)
	mres, err := VerifyMint(f.Cfg, mt.Bytes())
	g.must(err)
	mc, err := d.Agg.Certify(mres.Leaves, nil, BaseTime+1000, 100)
	g.must(err)
	eb, _ = (&Envelope{PolicyBody: f.Policy.Bytes(), History: mt.Bytes(), Anchors: []Anchor{mc.Anchor}, LeafProofs: mc.Proofs}).Encode()
	add("compose-valid-mint", "a mint composed against its certified leaf", eb, claimOf(mc.Anchor), "mint")
}

func rewriteIRBytes(raw []byte, mut func(r *types.InputRecord)) []byte {
	var ir types.InputRecord
	if err := ir.UnmarshalCBOR(raw); err != nil {
		panic(err)
	}
	mut(&ir)
	out, err := ir.Bytes()
	if err != nil {
		panic(err)
	}
	return out
}

// pack renders the family files, the fixture set, the semantic profile and the
// pinned SDK trust-base document with its provenance.
func (g *gen) pack() (*Corpus, error) {
	out := &Corpus{Files: map[string][]byte{}, Set: g.fs, Cases: g.cases}
	js := func(v any) ([]byte, error) {
		b, err := json.MarshalIndent(v, "", " ")
		return append(b, '\n'), err
	}
	fsb, err := js(g.fs)
	if err != nil {
		return nil, err
	}
	out.Files["config/fixtures.json"] = fsb
	fdig := sha256.Sum256(fsb)
	for _, fam := range families {
		cases := g.cases[fam]
		seen := map[string]bool{}
		for _, c := range cases {
			if seen[c.ID] {
				return nil, fmt.Errorf("duplicate case id %s", c.ID)
			}
			seen[c.ID] = true
		}
		b, err := js(CaseFile{Format: CorpusFormat, Proto: NativeBridgeProtoVersion, Family: fam, Fixture: hex.EncodeToString(fdig[:]), Cases: cases})
		if err != nil {
			return nil, err
		}
		out.Files[fam+"/cases.json"] = b
	}
	out.Files["config/semantic-profile.json"] = semanticProfile
	b, err := g.d.sdkTrustFixture()
	if err != nil {
		return nil, err
	}
	out.Files["config/sdk-root-trust-base.json"] = g.d.Trust.JSON
	out.Files["config/sdk-root-trust-base.provenance.json"] = b
	return out, nil
}

// sdkTrustFixture is the provenance record published beside the pinned B; it
// has the bytes native-bridge-plugins' tools/sdk_trust_fixture.mjs writes.
func (d *Deployment) sdkTrustFixture() ([]byte, error) {
	sum := sha256.Sum256(d.Trust.JSON)
	b, err := json.MarshalIndent(struct {
		Fixture       string `json:"fixture"`
		SDKVersion    string `json:"sdkVersion"`
		SDKCommit     string `json:"sdkCommit"`
		Serialization string `json:"serialization"`
		ByteLength    int    `json:"byteLength"`
		SHA256        string `json:"sha256"`
	}{"synthetic-fixed-base-not-authenticated", "3.0.1", "f5f0737306901215860aa920a6ab570b699efba8",
		"UTF8(JSON.stringify(RootTrustBase.fromJSON(source).toJSON()))", len(d.Trust.JSON), hex.EncodeToString(sum[:])}, "", "  ")
	return append(b, '\n'), err
}

// Digest is the SHA-256 of the sorted "sha256  path" listing of every
// generated file: the content address of the unsealed tree. The sealed corpus
// digest of native-bridge-plugins (tools/vectors.py seal) additionally covers
// VERSION and the provenance record, which name this generator's commit.
func (c *Corpus) Digest() string {
	var names []string
	for p := range c.Files {
		names = append(names, p)
	}
	sort.Strings(names)
	var man bytes.Buffer
	for _, p := range names {
		fmt.Fprintf(&man, "%x  %s\n", sha256.Sum256(c.Files[p]), p)
	}
	d := sha256.Sum256(man.Bytes())
	return hex.EncodeToString(d[:])
}

// shortSigUC re-encodes a certificate with every seal signature cut to 64 bytes.
func (g *gen) shortSigUC(uc []byte) []byte {
	var c types.UnicityCertificate
	g.must(types.Cbor.Unmarshal(uc, &c))
	for k, sig := range c.UnicitySeal.Signatures {
		c.UnicitySeal.Signatures[k] = sig[:64]
	}
	b, err := types.Cbor.Marshal(&c)
	g.must(err)
	return b
}
