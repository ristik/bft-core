package bridgeprofile

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

const policyDomain = "UNICITY_BR_AGG_ONE"

// EmptyPrefixShard is the one-byte native encoding of the empty shard prefix.
// It is 0x80, not the empty byte string.
var EmptyPrefixShard = []byte{0x80}

// Policy is the sole admitted body C("UNICITY_BR_AGG_ONE",
// aggregatorPartition, b(0x80), b(aggregatorShardConfHash)). Its hash is
// Cfg.aggregatorPolicyHash.
type Policy struct {
	Partition uint32
	ShardConf [32]byte
}

// Bytes is the exact canonical policy body.
func (p Policy) Bytes() []byte {
	return CArr(CBytes([]byte(policyDomain)), CUint(uint64(p.Partition)),
		CBytes(EmptyPrefixShard), CBytes(p.ShardConf[:]))
}

// Hash is aggregatorPolicyHash = H(exact policy bytes).
func (p Policy) Hash() [32]byte { return H(p.Bytes()) }

// DecodePolicy strictly decodes a policy body of at most 128 bytes.
func DecodePolicy(b []byte) (Policy, error) {
	if len(b) > MaxPolicyBytes {
		return Policy{}, ErrInputTooLarge
	}
	root, err := scanOne(b)
	if err != nil {
		return Policy{}, err
	}
	if !root.isArray(4) {
		return Policy{}, ErrShape
	}
	k := root.kids
	if !k[0].isBytes() || string(k[0].data) != policyDomain {
		return Policy{}, ErrShape
	}
	part, err := k[1].uintMax(0xffffffff)
	if err != nil {
		return Policy{}, err
	}
	if !k[2].isBytes() || !bytes.Equal(k[2].data, EmptyPrefixShard) {
		return Policy{}, ErrShape
	}
	var p Policy
	p.Partition = uint32(part)
	if err := fixed(&k[3], p.ShardConf[:]); err != nil {
		return Policy{}, err
	}
	// Canonical form follows from the strict scanner (shortest heads, definite
	// lengths) plus the exact field shapes above, so no re-encode is needed.
	return p, nil
}

// Anchor is the ABI tuple
// (uint32 partition, bytes shard, bytes32 shardConfHash, bytes32 expectedStateRoot,
// bytes32 expectedIRHash, bytes uc).
type Anchor struct {
	Partition         uint32
	Shard             []byte
	ShardConfHash     [32]byte
	ExpectedStateRoot [32]byte
	ExpectedIRHash    [32]byte
	UC                []byte
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
		as[i] = abiAnchor{a.Partition, nonNil(a.Shard), a.ShardConfHash, a.ExpectedStateRoot, a.ExpectedIRHash, nonNil(a.UC)}
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
	}) {
		e.Anchors = append(e.Anchors, Anchor{a.Partition, a.Shard, a.ShardConfHash, a.ExpectedStateRoot, a.ExpectedIRHash, a.Uc})
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
// words, so an over-budget count is rejected before any allocation.
func boundEnvelopeCounts(b []byte) error {
	word := func(off uint64) (uint64, bool) {
		if off+32 > uint64(len(b)) {
			return 0, false
		}
		v := new(big.Int).SetBytes(b[off : off+32])
		if !v.IsUint64() || v.Uint64() > uint64(len(b)) {
			return 0, false
		}
		return v.Uint64(), true
	}
	offAnchors, ok1 := word(64)
	offLeaves, ok2 := word(96)
	if !ok1 || !ok2 {
		return ErrABIFraming
	}
	na, ok := word(offAnchors)
	if !ok {
		return ErrABIFraming
	}
	if na > MaxAnchors {
		return ErrTooManyPaths
	}
	nl, ok := word(offLeaves)
	if !ok {
		return ErrABIFraming
	}
	if nl > MaxLeaves {
		return ErrTooManyPaths
	}
	return nil
}

// CheckPolicy is the composing verifier's opening and tuple check, run before
// any B1 call: hash the supplied body against Cfg.aggregatorPolicyHash before
// interpreting it, decode it, require exactly one anchor whose tuple equals the
// authenticated tuple, and require every leaf's anchorIndex to be 0 with
// exactly leafCount leaf proofs. The EVM partition may not equal the aggregator
// partition.
func CheckPolicy(cfg *Cfg, env *Envelope, leafCount int) (Policy, error) {
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
	if len(env.Anchors) != 1 {
		return Policy{}, ErrPolicyAnchors
	}
	a := env.Anchors[0]
	if a.Partition != pol.Partition || !bytes.Equal(a.Shard, EmptyPrefixShard) || a.ShardConfHash != pol.ShardConf {
		return Policy{}, ErrPolicyTuple
	}
	if len(env.LeafProofs) != leafCount {
		return Policy{}, ErrPolicyLeafCount
	}
	for _, l := range env.LeafProofs {
		if l.AnchorIndex != 0 {
			return Policy{}, ErrPolicyLeafIndex
		}
	}
	return pol, nil
}
