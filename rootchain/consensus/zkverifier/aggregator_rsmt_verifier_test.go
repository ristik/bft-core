package zkverifier

import (
	"bytes"
	"errors"
	"testing"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier/rsmt"
	"github.com/unicitynetwork/bft-go-base/types"
)

// tau is the reference time the tests build their rounds under; the tree stores rsmt.LeafValue(declared, tau).
const tau = 1_755_000_000

func newLeafHash(k [32]byte, declared []byte) [32]byte {
	stored := rsmt.LeafValue(declared, tau)
	return rsmt.HashLeaf(k, stored[:])
}

func TestAggregatorRSMTVerifier_SingleLeafIntoEmptyTree(t *testing.T) {
	var k [32]byte
	k[0] = 0x05
	v := []byte("hello")
	leafHash := newLeafHash(k, v)

	env, err := rsmt.EncodeEnvelope(
		[]rsmt.Leaf{{Key: k, Value: v}},
		[]byte{0x01}, // L
	)
	if err != nil {
		t.Fatal(err)
	}

	ver := NewAggregatorRSMTVerifier()
	if !ver.IsEnabled() {
		t.Fatal("expected IsEnabled()")
	}
	if ver.ProofType() != ProofTypeAggregatorRSMTv1 {
		t.Fatalf("unexpected ProofType %q", ver.ProofType())
	}

	// Genesis-to-first-leaf: prev nil, new = hashLeaf.
	if err := ver.VerifyProofAt(env, nil, leafHash[:], nil, tau); err != nil {
		t.Fatalf("VerifyProof: %v", err)
	}

	// The reference time is part of the statement: any other one is refused, and so is a call that supplies none.
	if err := ver.VerifyProofAt(env, nil, leafHash[:], nil, tau+1); !errors.Is(err, ErrProofVerificationFailed) {
		t.Fatalf("another reference time: got %v, want ErrProofVerificationFailed", err)
	}
	if err := ver.VerifyProof(env, nil, leafHash[:], nil); !errors.Is(err, ErrReferenceTimeRequired) {
		t.Fatalf("no reference time: got %v, want ErrReferenceTimeRequired", err)
	}
	var _ ReferenceTimeVerifier = ver

	// Wrong new root.
	bad := make([]byte, 32)
	if err := ver.VerifyProofAt(env, nil, bad, nil, tau); !errors.Is(err, ErrProofVerificationFailed) {
		t.Fatalf("wrong root: got %v, want ErrProofVerificationFailed", err)
	}

	// Malformed envelope.
	if err := ver.VerifyProofAt([]byte{0x00}, nil, leafHash[:], nil, tau); !errors.Is(err, ErrInvalidProofFormat) {
		t.Fatalf("malformed envelope: got %v, want ErrInvalidProofFormat", err)
	}

	// Wrong-length previous root.
	if err := ver.VerifyProofAt(env, []byte{1, 2, 3}, leafHash[:], nil, tau); !errors.Is(err, ErrInvalidProofFormat) {
		t.Fatalf("bad prev root length: got %v, want ErrInvalidProofFormat", err)
	}
}

func TestAggregatorRSMTVerifier_TwoLeaves(t *testing.T) {
	var k0, k1 [32]byte
	k0[0] = 0x00 // bit 0 (MSB) = 0 → left under depth-0 split
	k1[0] = 0x80 // bit 0 (MSB) = 1 → right
	v0 := []byte("v0")
	v1 := []byte("v1")

	h0 := newLeafHash(k0, v0)
	h1 := newLeafHash(k1, v1)
	region := rsmt.PrefixRegion(k0, 0)
	newRoot := rsmt.HashNode(h0, h1, 0, region)

	var proof bytes.Buffer
	proof.WriteByte(0x01) // L (k0)
	proof.WriteByte(0x01) // L (k1)
	proof.WriteByte(0x02) // N
	proof.WriteByte(0x00) //   depth=0

	env, err := rsmt.EncodeEnvelope(
		[]rsmt.Leaf{{Key: k0, Value: v0}, {Key: k1, Value: v1}},
		proof.Bytes(),
	)
	if err != nil {
		t.Fatal(err)
	}

	ver := NewAggregatorRSMTVerifier()
	if err := ver.VerifyProofAt(env, nil, newRoot[:], nil, tau); err != nil {
		t.Fatalf("VerifyProof: %v", err)
	}
}

func TestRegistry_AggregatorRSMT(t *testing.T) {
	reg := NewRegistry()
	params := map[string]string{ParamProofType: string(ProofTypeAggregatorRSMTv1)}
	v, err := reg.GetVerifier(types.PartitionID(42), types.ShardID{}, 0, params)
	if err != nil {
		t.Fatalf("GetVerifier: %v", err)
	}
	if _, ok := v.(*AggregatorRSMTVerifier); !ok {
		t.Fatalf("registry returned %T, want *AggregatorRSMTVerifier", v)
	}
	if !v.IsEnabled() {
		t.Fatalf("verifier not enabled")
	}
	if v.ProofType() != ProofTypeAggregatorRSMTv1 {
		t.Fatalf("wrong proof type %q", v.ProofType())
	}

	// Cached on repeat call.
	v2, err := reg.GetVerifier(types.PartitionID(42), types.ShardID{}, 0, params)
	if err != nil {
		t.Fatal(err)
	}
	if v != v2 {
		t.Fatalf("registry did not cache verifier")
	}
}
