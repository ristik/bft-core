package b1gen

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// Native CBOR tags (unicity-ids cbor-tags.json).
const (
	tagUC    = 39001
	tagIR    = 39002
	tagShard = 39003
	tagUTC   = 39004
	tagSeal  = 39005
)

const genesisTime = 1681971084 // minimum seal timestamp

func sum(parts ...[]byte) [32]byte { return sha256.Sum256(cat(parts...)) }

// ---- deterministic randomness -------------------------------------------

// drbg is a counter-mode SHA-256 stream keyed by the seed and a label.
type drbg struct {
	key []byte
	n   uint64
}

func newDRBG(seed string, label string) *drbg {
	h := sha256.Sum256([]byte("b1gen/v1|" + seed + "|" + label))
	return &drbg{key: h[:]}
}

func (d *drbg) hash() [32]byte {
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], d.n)
	d.n++
	return sum(d.key, c[:])
}

func (d *drbg) bytes32() []byte { h := d.hash(); return h[:] }

// ---- validators and signing ----------------------------------------------

type validator struct {
	id  string
	key *secp256k1.PrivateKey
	pub []byte // compressed, 33 bytes
}

func makeValidator(seed string, id string) validator {
	h := sha256.Sum256([]byte("b1gen/v1|" + seed + "|key|" + id))
	k := secp256k1.PrivKeyFromBytes(h[:])
	return validator{id: id, key: k, pub: k.PubKey().SerializeCompressed()}
}

var curveN = secp256k1.S256().N

// signature is r||s (64 bytes) or r||s||v (65 bytes), low-s RFC 6979 over the
// SHA-256 digest of msg.
func (v validator) sign(msg []byte, withV bool) []byte {
	digest := sha256.Sum256(msg)
	compact := ecdsa.SignCompact(v.key, digest[:], true) // header | r | s
	out := append([]byte{}, compact[1:65]...)
	if withV {
		out = append(out, compact[0]-27-4) // recovery id 0..3 (0/1 in practice)
	}
	return out
}

// highS returns r || (n-s) [|| v] for the signature sig.
func highS(sig []byte) []byte {
	s := new(big.Int).SetBytes(sig[32:64])
	s.Sub(curveN, s)
	out := append([]byte{}, sig...)
	copy(out[32:64], pad32(s))
	return out
}

func pad32(x *big.Int) []byte {
	b := x.Bytes()
	return append(make([]byte, 32-len(b)), b...)
}

// ---- registry authority -----------------------------------------------------------

type authorityMember struct {
	id     string
	pub    []byte
	weight uint64
}

type authoritySpec struct {
	network    uint16
	epoch      uint64
	sourceKind uint64
	bodyID     [32]byte
	members    []authorityMember // wire order
}

func authorityOf(network uint16, epoch uint64, kind uint64, body [32]byte, vals []validator) authoritySpec {
	sorted := append([]validator{}, vals...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].id < sorted[j].id })
	v := authoritySpec{network: network, epoch: epoch, sourceKind: kind, bodyID: body}
	for _, x := range sorted {
		v.members = append(v.members, authorityMember{id: x.id, pub: x.pub, weight: 1})
	}
	return v
}

// ---- input records, shards, certificates ---------------------------------

type irSpec struct {
	round, epoch uint64
	prev         []byte // nil encodes null
	state        []byte
	summary      []byte // nil encodes null
	timestamp    uint64
	block        []byte // nil encodes null
	fees         uint64
	et           []byte // nil encodes null
}

func (ir irSpec) cbor() []byte {
	return cTag(tagIR, cArr(cUint(1), cUint(ir.round), cUint(ir.epoch), cNullOr(ir.prev), cBytes(ir.state),
		cNullOr(ir.summary), cUint(ir.timestamp), cNullOr(ir.block), cUint(ir.fees), cNullOr(ir.et)))
}

// shardBits packs a '0'/'1' string into the self-delimiting bit string: bits
// MSB-first, then a single 1 end marker, zero padded.
func shardBits(s string) []byte {
	out := make([]byte, len(s)/8+1)
	for i := 0; i < len(s); i++ {
		if s[i] == '1' {
			out[i/8] |= 0x80 >> uint(i%8)
		}
	}
	out[len(s)/8] |= 0x80 >> uint(len(s)%8)
	return out
}

// shardLeaf is the shard tree leaf hash: SHA256 of the CBOR operands
// IR, TRHash, ShardConfHash (each operand encoded, not raw-concatenated).
func shardLeaf(ir irSpec, tr, conf [32]byte) [32]byte {
	return sum(ir.cbor(), cBytes(tr[:]), cBytes(conf[:]))
}

func shardNode(l, r [32]byte) [32]byte { return sum(cBytes(l[:]), cBytes(r[:])) }

// shardFold folds a leaf up the given siblings; the last shard bit is the
// leaf's own side.
func shardFold(leaf [32]byte, shard string, sibs [][32]byte, raw bool) [32]byte {
	h := leaf
	for i, sib := range sibs {
		bit := byte('0')
		if idx := len(shard) - 1 - i; idx >= 0 { // more siblings than bits: out-of-profile input
			bit = shard[idx]
		}
		l, r := h, sib
		if bit == '1' {
			l, r = sib, h
		}
		if raw {
			h = sum(l[:], r[:])
		} else {
			h = shardNode(l, r)
		}
	}
	return h
}

// shardTree is the full tree of one partition over its shard scheme.
type shardTree struct {
	leaves map[string][32]byte
}

func (t shardTree) node(prefix string) [32]byte {
	if h, ok := t.leaves[prefix]; ok {
		return h
	}
	return shardNode(t.node(prefix+"0"), t.node(prefix+"1"))
}

func (t shardTree) root() [32]byte { return t.node("") }

func (t shardTree) siblings(shard string) [][32]byte {
	var out [][32]byte
	for i := len(shard) - 1; i >= 0; i-- {
		flip := shard[:i]
		if shard[i] == '0' {
			flip += "1"
		} else {
			flip += "0"
		}
		out = append(out, t.node(flip))
	}
	return out
}

// ---- unicity (indexed Merkle) tree ----------------------------------------

type imtLeaf struct {
	key  [4]byte
	data [32]byte // hash of the CBOR-encoded shard tree root
}

func imtLeafHash(l imtLeaf) [32]byte {
	return sum(cBytes([]byte{1}), cBytes(l.key[:]), cBytes(l.data[:]))
}

type imtNode struct {
	hash        [32]byte
	key         []byte
	data        [32]byte
	left, right *imtNode
}

func imtBuild(ls []imtLeaf) *imtNode {
	if len(ls) == 1 {
		return &imtNode{hash: imtLeafHash(ls[0]), key: ls[0].key[:], data: ls[0].data}
	}
	m := (len(ls) + 1) / 2
	l, r := imtBuild(ls[:m]), imtBuild(ls[m:])
	key := ls[m-1].key[:]
	return &imtNode{hash: sum(cBytes([]byte{0}), cBytes(key), cBytes(l.hash[:]), cBytes(r.hash[:])), key: key, left: l, right: r}
}

type pathStep struct {
	key  uint32
	hash [32]byte
}

// path returns the hash steps from the leaf's parent to the root, the leaf
// item itself excluded.
func (n *imtNode) path(key [4]byte) []pathStep {
	var z []pathStep
	cur := n
	for cur.left != nil {
		if string(key[:]) > string(cur.key) {
			z = append([]pathStep{{binary.BigEndian.Uint32(cur.key), cur.left.hash}}, z...)
			cur = cur.right
		} else {
			z = append([]pathStep{{binary.BigEndian.Uint32(cur.key), cur.right.hash}}, z...)
			cur = cur.left
		}
	}
	return z
}

// ---- seals ---------------------------------------------------------------

type sealSpec struct {
	network   uint16
	round     uint64
	epoch     uint64
	timestamp uint64
	prev      [32]byte
	root      [32]byte
	sigs      []entry // signer ID -> signature, any order (sorted when encoded)
}

func (s sealSpec) fields(sigs []byte) []byte {
	return cTag(tagSeal, cArr(cUint(1), cUint(uint64(s.network)), cUint(s.round), cUint(s.epoch), cUint(s.timestamp),
		cBytes(s.prev[:]), cBytes(s.root[:]), sigs))
}

// sigBytes is the signing preimage: the tagged seal with signatures = null.
func (s sealSpec) sigBytes() []byte { return s.fields(cNull) }

func (s sealSpec) cbor() []byte {
	es := make([]entry, len(s.sigs))
	for i, e := range s.sigs {
		es[i] = entry{e.key, cBytes(e.val)}
	}
	return s.fields(cTextMap(es))
}

// signWith signs the seal with the given validators (compact r||s or r||s||v).
func (s *sealSpec) signWith(vals []validator, withV bool) {
	msg := s.sigBytes()
	s.sigs = nil
	for _, v := range vals {
		s.sigs = append(s.sigs, entry{v.id, v.sign(msg, withV)})
	}
}

// ---- unicity certificate ---------------------------------------------------

type ucSpec struct {
	part      uint32
	shard     string
	ir        irSpec
	tr, conf  [32]byte
	shardSibs [][32]byte
	steps     []pathStep
	seal      sealSpec
	// sealBytes, when non-nil, replaces the encoded seal (malformed tests).
	sealBytes []byte
}

func (u ucSpec) cbor() []byte {
	sibs := make([][]byte, len(u.shardSibs))
	for i, s := range u.shardSibs {
		sibs[i] = cBytes(s[:])
	}
	steps := make([][]byte, len(u.steps))
	for i, s := range u.steps {
		steps[i] = cArr(cUint(uint64(s.key)), cBytes(s.hash[:]))
	}
	seal := u.sealBytes
	if seal == nil {
		seal = u.seal.cbor()
	}
	return cTag(tagUC, cArr(cUint(1), u.ir.cbor(), cBytes(u.tr[:]), cBytes(u.conf[:]),
		cTag(tagShard, cArr(cUint(1), cBytes(shardBits(u.shard)), cArr(sibs...))),
		cTag(tagUTC, cArr(cUint(1), cUint(uint64(u.part)), cArr(steps...))),
		seal))
}

// claim is one wire claim; fields are raw so negatives can corrupt any of them.
type claimSpec struct {
	part      uint32
	shardWire []byte
	conf      [32]byte
	stateRoot [32]byte
	irHash    [32]byte
	uc        []byte
	// overrides for length fields (nil = real length)
	shardLen *uint16
	ucLen    *uint32
}

func (c claimSpec) wire() []byte {
	sl := uint16(len(c.shardWire))
	if c.shardLen != nil {
		sl = *c.shardLen
	}
	ul := uint32(len(c.uc))
	if c.ucLen != nil {
		ul = *c.ucLen
	}
	var b [10]byte
	binary.BigEndian.PutUint32(b[0:], c.part)
	binary.BigEndian.PutUint16(b[4:], sl)
	var u [4]byte
	binary.BigEndian.PutUint32(u[:], ul)
	return cat(b[:6], c.shardWire, c.conf[:], c.stateRoot[:], c.irHash[:], u[:], c.uc)
}

func claimOf(u ucSpec) claimSpec {
	irHash := sha256.Sum256(u.ir.cbor())
	var state [32]byte
	copy(state[:], u.ir.state)
	return claimSpec{part: u.part, shardWire: shardBits(u.shard), conf: u.conf, stateRoot: state, irHash: irHash, uc: u.cbor()}
}

type requestSpec struct {
	version, flags byte
	count          *uint16 // nil = len(claims)
	claims         []claimSpec
	trailing       []byte
}

func (r requestSpec) wire() []byte {
	n := uint16(len(r.claims))
	if r.count != nil {
		n = *r.count
	}
	out := []byte{r.version, r.flags, byte(n >> 8), byte(n)}
	for _, c := range r.claims {
		out = append(out, c.wire()...)
	}
	return append(out, r.trailing...)
}

func newRequest(claims ...claimSpec) requestSpec {
	return requestSpec{version: 1, claims: claims}
}

func hex32(b [32]byte) string { return fmt.Sprintf("%x", b[:]) }

// TestValidator is an exported handle on a seed-derived validator, for tests
// that need a signature outside any vector.
type TestValidator struct {
	Pub []byte
	v   validator
}

// ValidatorForTest derives the validator with the given ID from a seed.
func ValidatorForTest(seed, id string) TestValidator {
	v := makeValidator(seed, id)
	return TestValidator{Pub: v.pub, v: v}
}

// Sign returns the compact signature over SHA-256(msg), with the recovery byte
// appended when withV.
func (t TestValidator) Sign(msg []byte, withV bool) []byte { return t.v.sign(msg, withV) }
