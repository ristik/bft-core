package bridgeprofile

import (
	"bytes"
	"math/big"
	"math/bits"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

const policyDomain = "UNICITY_BR_AGG_PARTITION"

// PolicyVersion is the literal version field of the partition policy body.
const PolicyVersion = 2

// EmptyPrefixShard is the one-byte native encoding of the empty shard prefix
// (depth 0). It is 0x80, not the empty byte string.
var EmptyPrefixShard = []byte{0x80}

// Policy is the sole admitted body C(b("UNICITY_BR_AGG_PARTITION"),2,aggregatorPartition) (briefs/b1-any-age-contract.md section 6,
// AGG_PARTITION_V2): one fixed aggregation partition whose certified shard configurations are authorized by the root quorum. It
// names no depth, shard list or configuration: each anchor's UC authenticates its own historical shard and configuration hash, and
// its depth comes from its own canonical shard ID. Its hash is Cfg.aggregatorPolicyHash.
type Policy struct {
	Partition uint32
}

// NewPolicy is the policy of an aggregation partition.
func NewPolicy(partition uint32) Policy { return Policy{Partition: partition} }

// Bytes is the exact canonical policy body.
func (p Policy) Bytes() []byte {
	return CArr(CBytes([]byte(policyDomain)), CUint(PolicyVersion), CUint(uint64(p.Partition)))
}

// Hash is aggregatorPolicyHash = H(exact policy bytes).
func (p Policy) Hash() [32]byte { return H(p.Bytes()) }

// DecodePolicy strictly decodes a policy body of at most MaxPolicyBytes bytes.
func DecodePolicy(b []byte) (Policy, error) {
	if len(b) > MaxPolicyBytes {
		return Policy{}, ErrInputTooLarge
	}
	root, err := scanOne(b)
	if err != nil {
		return Policy{}, err
	}
	if !root.isArray(3) {
		return Policy{}, ErrShape
	}
	k := root.kids
	if !k[0].isBytes() || string(k[0].data) != policyDomain {
		return Policy{}, ErrShape
	}
	if err := k[1].version(PolicyVersion); err != nil {
		return Policy{}, err
	}
	part, err := k[2].uintMax(0xffffffff)
	if err != nil {
		return Policy{}, err
	}
	if part == 0 {
		return Policy{}, ErrIntRange
	}
	// Canonical form follows from the strict scanner (shortest heads, definite
	// lengths) plus the exact field shapes above, so no re-encode is needed.
	return Policy{Partition: uint32(part)}, nil
}

// ShardDepth is the depth d of a canonical native shard ID: 8*len - trailingZeroBits(last byte) - 1, the bits before the
// terminator. ok is false for a noncanonical ID (empty, zero last byte, over 33 bytes or deeper than 256).
func ShardDepth(shard []byte) (d int, ok bool) {
	if len(shard) == 0 || len(shard) > 33 || shard[len(shard)-1] == 0 {
		return 0, false
	}
	d = 8*len(shard) - bits.TrailingZeros8(shard[len(shard)-1]) - 1
	return d, d <= 256
}

// InShard reports whether the first d bits of a 32-byte state ID are the shard's prefix bits (contract section 6).
func InShard(shard []byte, sid [32]byte) bool {
	d, ok := ShardDepth(shard)
	if !ok {
		return false
	}
	for i := 0; i < d; i++ {
		if (shard[i/8]>>(7-uint(i%8)))&1 != (sid[i/8]>>(7-uint(i%8)))&1 {
			return false
		}
	}
	return true
}

// Anchor is the ABI tuple
// (uint32 partition, bytes shard, bytes32 shardConfHash, bytes32 expectedStateRoot,
// bytes32 expectedIRHash, bytes uc, bytes inputRecord). inputRecord is the exact
// canonical native InputRecord opening committed by expectedIRHash; it is the
// only source of the anchor timestamp.
type Anchor struct {
	Partition         uint32
	Shard             []byte
	ShardConfHash     [32]byte
	ExpectedStateRoot [32]byte
	ExpectedIRHash    [32]byte
	UC                []byte
	InputRecord       []byte
}

// LeafProof is the ABI tuple (uint16 anchorIndex, bytes32 bitmap, bytes32[] siblings).
type LeafProof struct {
	AnchorIndex uint16
	Bitmap      [32]byte
	Siblings    [][32]byte
}

// Envelope is the proof envelope abi.encode(bytes policyBody, bytes history,
// Anchor[] anchors, LeafProof[] leafProofs).
type Envelope struct {
	PolicyBody []byte
	History    []byte
	Anchors    []Anchor
	LeafProofs []LeafProof
}

var envelopeArgs = mustEnvelopeArgs()

func mustEnvelopeArgs() abi.Arguments {
	anchor, err := abi.NewType("tuple[]", "", []abi.ArgumentMarshaling{
		{Name: "partition", Type: "uint32"},
		{Name: "shard", Type: "bytes"},
		{Name: "shardConfHash", Type: "bytes32"},
		{Name: "expectedStateRoot", Type: "bytes32"},
		{Name: "expectedIRHash", Type: "bytes32"},
		{Name: "uc", Type: "bytes"},
		{Name: "inputRecord", Type: "bytes"},
	})
	if err != nil {
		panic(err)
	}
	leaf, err := abi.NewType("tuple[]", "", []abi.ArgumentMarshaling{
		{Name: "anchorIndex", Type: "uint16"},
		{Name: "bitmap", Type: "bytes32"},
		{Name: "siblings", Type: "bytes32[]"},
	})
	if err != nil {
		panic(err)
	}
	bt, _ := abi.NewType("bytes", "", nil)
	return abi.Arguments{{Type: bt}, {Type: bt}, {Type: anchor}, {Type: leaf}}
}

type abiAnchor struct {
	Partition         uint32
	Shard             []byte
	ShardConfHash     [32]byte
	ExpectedStateRoot [32]byte
	ExpectedIRHash    [32]byte
	Uc                []byte
	InputRecord       []byte
}

type abiLeaf struct {
	AnchorIndex uint16
	Bitmap      [32]byte
	Siblings    [][32]byte
}

// Encode is the canonical ABI encoding of the envelope.
func (e *Envelope) Encode() ([]byte, error) {
	as := make([]abiAnchor, len(e.Anchors))
	for i, a := range e.Anchors {
		as[i] = abiAnchor{a.Partition, nonNil(a.Shard), a.ShardConfHash, a.ExpectedStateRoot, a.ExpectedIRHash, nonNil(a.UC), nonNil(a.InputRecord)}
	}
	ls := make([]abiLeaf, len(e.LeafProofs))
	for i, l := range e.LeafProofs {
		ls[i] = abiLeaf{l.AnchorIndex, l.Bitmap, l.Siblings}
		if ls[i].Siblings == nil {
			ls[i].Siblings = [][32]byte{}
		}
	}
	return envelopeArgs.Pack(nonNil(e.PolicyBody), nonNil(e.History), as, ls)
}

func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// DecodeEnvelope decodes an envelope and rejects noncanonical offsets, padding,
// aliases and trailing data by requiring that re-encoding reproduces the input
// exactly. Total, anchor, leaf and path counts are bounded before the ABI
// decoder runs.
func DecodeEnvelope(b []byte) (*Envelope, error) {
	if len(b) > MaxEnvelopeBytes {
		return nil, ErrInputTooLarge
	}
	if len(b)%32 != 0 || len(b) < 4*32 {
		return nil, ErrABIFraming
	}
	if err := boundEnvelopeCounts(b); err != nil {
		return nil, err
	}
	vals, err := envelopeArgs.Unpack(b)
	if err != nil || len(vals) != 4 {
		return nil, ErrABIFraming
	}
	e := &Envelope{PolicyBody: vals[0].([]byte), History: vals[1].([]byte)}
	for _, a := range vals[2].([]struct {
		Partition         uint32   `json:"partition"`
		Shard             []byte   `json:"shard"`
		ShardConfHash     [32]byte `json:"shardConfHash"`
		ExpectedStateRoot [32]byte `json:"expectedStateRoot"`
		ExpectedIRHash    [32]byte `json:"expectedIRHash"`
		Uc                []byte   `json:"uc"`
		InputRecord       []byte   `json:"inputRecord"`
	}) {
		e.Anchors = append(e.Anchors, Anchor{a.Partition, a.Shard, a.ShardConfHash, a.ExpectedStateRoot, a.ExpectedIRHash, a.Uc, a.InputRecord})
	}
	for _, l := range vals[3].([]struct {
		AnchorIndex uint16     `json:"anchorIndex"`
		Bitmap      [32]byte   `json:"bitmap"`
		Siblings    [][32]byte `json:"siblings"`
	}) {
		e.LeafProofs = append(e.LeafProofs, LeafProof{l.AnchorIndex, l.Bitmap, l.Siblings})
	}
	re, err := e.Encode()
	if err != nil || !bytes.Equal(re, b) {
		return nil, ErrABIFraming
	}
	return e, nil
}

// boundEnvelopeCounts reads the declared array lengths straight from the head
// words, so an over-budget count is rejected before any allocation. It walks
// the leaf proofs in order with overflow-safe offset arithmetic and rejects a
// cumulative sibling count above MaxPathSteps; a layout it cannot follow is
// ErrABIFraming.
func boundEnvelopeCounts(b []byte) error {
	n := uint64(len(b))
	// word reads the 32-byte word at off; a value above 2^64-1 or a read past
	// the end is a framing error.
	word := func(off uint64) (uint64, bool) {
		end := off + 32
		if end < off || end > n {
			return 0, false
		}
		v := new(big.Int).SetBytes(b[off:end])
		if !v.IsUint64() {
			return 0, false
		}
		return v.Uint64(), true
	}
	// add is a checked sum.
	add := func(a, c uint64) (uint64, bool) {
		s := a + c
		return s, s >= a
	}
	offAnchors, ok1 := word(64)
	offLeaves, ok2 := word(96)
	if !ok1 || !ok2 || offAnchors > n || offLeaves > n {
		return ErrABIFraming
	}
	na, ok := word(offAnchors)
	if !ok || na > n {
		return ErrABIFraming
	}
	if na > MaxAnchors {
		return ErrTooManyPaths
	}
	nl, ok := word(offLeaves)
	if !ok || nl > n {
		return ErrABIFraming
	}
	if nl > MaxLeaves {
		return ErrTooManyPaths
	}
	var steps uint64
	for i := uint64(0); i < nl; i++ {
		headAt, ok := add(offLeaves, 32+32*i)
		if !ok {
			return ErrABIFraming
		}
		rel, ok := word(headAt)
		if !ok {
			return ErrABIFraming
		}
		t, ok := add(offLeaves+32, rel)
		if !ok {
			return ErrABIFraming
		}
		sRel, ok := wordAt(word, add, t, 64)
		if !ok {
			return ErrABIFraming
		}
		sOff, ok := add(t, sRel)
		if !ok {
			return ErrABIFraming
		}
		ns, ok := word(sOff)
		if !ok {
			return ErrABIFraming
		}
		if ns > MaxPathSteps-steps {
			return ErrTooManyPaths
		}
		steps += ns
	}
	return nil
}

// wordAt reads the word at base+delta with a checked sum.
func wordAt(word func(uint64) (uint64, bool), add func(a, c uint64) (uint64, bool), base, delta uint64) (uint64, bool) {
	o, ok := add(base, delta)
	if !ok {
		return 0, false
	}
	return word(o)
}

// AnchorPlan is the anchor table the exported leaves require: one anchor per
// distinct complete UC in first-use leaf order, and each leaf's own anchor.
type AnchorPlan struct {
	LeafAnchor []int // anchor index of each leaf
}

// CheckPolicyBody is the composing verifier's opening, run before the kernel
// and before any B1 call: hash the supplied body against
// Cfg.aggregatorPolicyHash before interpreting it, decode it, require the
// aggregator partition to differ from the EVM partition and the anchor count
// to be within the anchor bound. A submitted anchor table never chooses its own
// admission.
func CheckPolicyBody(cfg *Cfg, env *Envelope) (Policy, error) {
	if len(env.PolicyBody) > MaxPolicyBytes {
		return Policy{}, ErrInputTooLarge
	}
	if H(env.PolicyBody) != cfg.AggregatorPolicyHash {
		return Policy{}, ErrPolicyHash
	}
	pol, err := DecodePolicy(env.PolicyBody)
	if err != nil {
		return Policy{}, err
	}
	if pol.Partition == cfg.EVMPartition {
		return Policy{}, ErrPolicyPartition
	}
	if len(env.Anchors) > MaxAnchors {
		return Policy{}, ErrTooManyPaths
	}
	if len(env.Anchors) == 0 {
		return Policy{}, ErrPolicyAnchors
	}
	return pol, nil
}

// PlanAnchors requires the envelope's anchor table to be exactly the function of the exported leaves the profile defines: one leaf
// proof per leaf in kernel order; every anchor of the policy's partition with a canonical shard ID; anchors pairwise distinct by
// complete UC bytes (byte-identical UCs are one anchor, never two); anchors numbered by first use in leaf order with none unused;
// and each leaf's anchorIndex naming an anchor whose shard prefix the leaf's state ID carries. Anchors of one history may come
// from different topologies: a parent shard before a split and its child after it are both admitted, each bound by its own UC.
// The configuration hash is not checked here: the UC authenticates it (B1). The number of anchors is not tied to the number of
// shards.
func PlanAnchors(pol Policy, env *Envelope, sids [][32]byte) (*AnchorPlan, error) {
	if len(env.LeafProofs) != len(sids) {
		return nil, ErrPolicyLeafCount
	}
	if len(env.Anchors) > MaxAnchors {
		return nil, ErrTooManyPaths
	}
	if len(env.Anchors) == 0 || len(env.Anchors) > len(sids) {
		return nil, ErrPolicyAnchors
	}
	seen := make(map[[32]byte]struct{}, len(env.Anchors))
	for j := range env.Anchors {
		a := &env.Anchors[j]
		if _, ok := ShardDepth(a.Shard); !ok || a.Partition != pol.Partition {
			return nil, ErrPolicyTuple
		}
		h := H(a.UC)
		if _, dup := seen[h]; dup {
			return nil, ErrPolicyAnchors
		}
		seen[h] = struct{}{}
	}
	plan := &AnchorPlan{LeafAnchor: make([]int, len(sids))}
	next := 0
	for i, sid := range sids {
		idx := int(env.LeafProofs[i].AnchorIndex)
		if idx >= len(env.Anchors) || idx > next || !InShard(env.Anchors[idx].Shard, sid) {
			return nil, ErrPolicyLeafIndex
		}
		if idx == next {
			next++
		}
		plan.LeafAnchor[i] = idx
	}
	if next != len(env.Anchors) {
		return nil, ErrPolicyAnchors
	}
	return plan, nil
}

// CheckPolicy is CheckPolicyBody followed by PlanAnchors for the given leaf
// state IDs.
func CheckPolicy(cfg *Cfg, env *Envelope, sids [][32]byte) (Policy, *AnchorPlan, error) {
	pol, err := CheckPolicyBody(cfg, env)
	if err != nil {
		return Policy{}, nil, err
	}
	plan, err := PlanAnchors(pol, env, sids)
	if err != nil {
		return Policy{}, nil, err
	}
	return pol, plan, nil
}

// InputRecordView is the opened native InputRecord:
// tag(39002,[1,round,epoch,previousHash,stateHash,summary,timestamp,blockHash,fees,executedTransactionsHash]).
type InputRecordView struct {
	Round, Epoch, Timestamp, Fees uint64
	PreviousHash                  []byte // nil when null
	StateHash                     [32]byte
	Summary                       []byte // nil when null
	BlockHash                     []byte // nil when null
	ExecutedTransactionsHash      []byte // nil when null
}

// OpenAnchor is the anchor's IR opening. The exact canonical native bytes must
// hash to the anchor's expectedIRHash and decode under B1's field, null, width
// and canonical rules, and the opened state hash must equal the anchor's
// expectedStateRoot. The opening carries no trust by itself: it is meaningful
// only after B1 0x0100 has authenticated (expectedStateRoot, expectedIRHash).
func OpenAnchor(a *Anchor) (*InputRecordView, error) {
	if len(a.InputRecord) == 0 || len(a.InputRecord) > MaxInputRecordBytes {
		return nil, ErrIRShape
	}
	if H(a.InputRecord) != a.ExpectedIRHash {
		return nil, ErrIROpening
	}
	root, err := scanOne(a.InputRecord)
	if err != nil {
		return nil, ErrIRShape
	}
	c, err := root.tagContent(TagInputRecord)
	if err != nil || !c.isArray(10) {
		return nil, ErrIRShape
	}
	k := c.kids
	if k[0].version(InputRecordVersion) != nil {
		return nil, ErrIRShape
	}
	hashOrNull := func(it *item) ([]byte, bool) {
		if it.null {
			return nil, true
		}
		if it.isBytes() && len(it.data) == 32 {
			return it.data, true
		}
		return nil, false
	}
	v := &InputRecordView{}
	var ok [7]bool
	v.Round, ok[0] = k[1].arg, k[1].isUint()
	v.Epoch, ok[1] = k[2].arg, k[2].isUint()
	v.Timestamp, ok[2] = k[6].arg, k[6].isUint()
	v.Fees, ok[3] = k[8].arg, k[8].isUint()
	v.PreviousHash, ok[4] = hashOrNull(&k[3])
	v.BlockHash, ok[5] = hashOrNull(&k[7])
	v.ExecutedTransactionsHash, ok[6] = hashOrNull(&k[9])
	for _, b := range ok {
		if !b {
			return nil, ErrIRShape
		}
	}
	if !k[4].isBytes() || len(k[4].data) != 32 {
		return nil, ErrIRShape
	}
	copy(v.StateHash[:], k[4].data)
	switch {
	case k[5].null:
	case k[5].isBytes() && len(k[5].data) <= MaxSummaryBytes:
		v.Summary = k[5].data
	default:
		return nil, ErrIRShape
	}
	if v.StateHash != a.ExpectedStateRoot {
		return nil, ErrIRState
	}
	return v, nil
}

// SemanticProfileJSON is the exact bytes of the development semantic-profile artifact; a deployment's semanticProfileHash is its SHA-256.
func SemanticProfileJSON() []byte { return append([]byte(nil), semanticProfile...) }
