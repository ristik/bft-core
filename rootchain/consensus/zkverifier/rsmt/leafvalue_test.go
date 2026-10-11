package rsmt

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// The rugregator commit these derivations and fixtures are checked against.
const pinnedRugregator = "dd5b1406a17fdeb415799045c5e81609619a870a"

// TestLeafValueMatchesTheSharedVector is the vector `matches_the_shared_test_vector` in rugregator's crates/rsmt-verify/src/leaf_value.rs
// (pinnedRugregator), shared by the Go, Java and TypeScript implementations: tx hash 0x00..0x1f, reference time 1755000000.
func TestLeafValueMatchesTheSharedVector(t *testing.T) {
	txHash := make([]byte, 32)
	for i := range txHash {
		txHash[i] = byte(i)
	}
	want := [32]byte{
		0x02, 0x35, 0xbd, 0x52, 0xcf, 0xa1, 0x0c, 0x97, 0x85, 0xdf, 0xa0, 0x19, 0x42, 0xbc, 0x39, 0x6f,
		0x20, 0x1f, 0xe7, 0x15, 0xdb, 0xc3, 0x89, 0x6e, 0xe1, 0x17, 0xa9, 0x7e, 0x89, 0x5e, 0x1e, 0x36,
	}
	if got := LeafValue(txHash, 1_755_000_000); got != want {
		t.Fatalf("LeafValue = %x, want %x (rugregator %s)", got, want, pinnedRugregator)
	}
}

// TestLeafValueIsTheShortestFormCBOROfTheTwoElementArray checks the hand-written heads against an independent encoder at every head-size
// boundary of the byte-string length and of the reference time.
func TestLeafValueIsTheShortestFormCBOROfTheTwoElementArray(t *testing.T) {
	for _, n := range []int{0, 1, 23, 24, 32, 255, 256} {
		for _, tau := range []uint64{0, 1, 23, 24, 255, 256, 65535, 65536, 1<<32 - 1, 1 << 32, 1_755_000_000, 1<<64 - 1} {
			tx := bytes.Repeat([]byte{0x5a}, n)
			enc, err := cbor.CoreDetEncOptions().EncMode()
			if err != nil {
				t.Fatal(err)
			}
			raw, err := enc.Marshal([]any{tx, tau})
			if err != nil {
				t.Fatal(err)
			}
			if got, want := LeafValue(tx, tau), sha256.Sum256(raw); got != want {
				t.Fatalf("len %d tau %d: LeafValue = %x, want %x", n, tau, got, want)
			}
		}
	}
}

func TestLeafValueBindsTheReferenceTimeAndTheHash(t *testing.T) {
	tx := bytes.Repeat([]byte{0x11}, 32)
	if LeafValue(tx, 1) == LeafValue(tx, 2) {
		t.Fatal("the reference time is not part of the leaf value")
	}
	other := bytes.Repeat([]byte{0x12}, 32)
	if LeafValue(tx, 1) == LeafValue(other, 1) {
		t.Fatal("the transaction hash is not part of the leaf value")
	}
}

// TestVerifyDerivesNewLeavesAndKeepsOpenedLeavesVerbatim isolates the two halves of the rule on one envelope: a two-leaf insertion into a
// one-leaf tree. The new leaf (L) is hashed with LeafValue(declared, tau); the preserved leaf (O_L) with the value the envelope carries.
func TestVerifyDerivesNewLeavesAndKeepsOpenedLeavesVerbatim(t *testing.T) {
	kOld, kNew := key(0x00), key(0x80)
	vOld, declared := []byte("stored value of the earlier round"), bytes.Repeat([]byte{0x77}, 32)
	hOld := HashLeaf(kOld, vOld)
	hNew := newLeafHash(kNew, declared)
	oldRoot := Root{Hash: hOld, Set: true}
	newRoot := Root{Hash: HashNode(hOld, hNew, 0, PrefixRegion(kOld, 0)), Set: true}
	var proof bytes.Buffer
	proof.Write(opOL(kOld, vOld))
	proof.Write(opL())
	proof.Write(opN(0))
	env := &Envelope{Leaves: []Leaf{{Key: kNew, Value: declared}}, Proof: proof.Bytes()}

	if err := Verify(env, oldRoot, newRoot, testTau); err != nil {
		t.Fatalf("control: %v", err)
	}
	// another reference time: only the new leaf's derivation changes
	if err := Verify(env, oldRoot, newRoot, testTau+1); !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("another reference time: got %v, want ErrRootMismatch", err)
	}
	// the declared value taken as the stored one (the behaviour before this change) is not the tree's root
	verbatim := Root{Hash: HashNode(hOld, HashLeaf(kNew, declared), 0, PrefixRegion(kOld, 0)), Set: true}
	if err := Verify(env, oldRoot, verbatim, testTau); !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("declared value used verbatim: got %v, want ErrRootMismatch", err)
	}
	// an opened preserved leaf is not re-derived: deriving it would change the pre-state root
	derivedOld := Root{Hash: newLeafHash(kOld, vOld), Set: true}
	if err := Verify(env, derivedOld, newRoot, testTau); !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("O_L re-derived: got %v, want ErrRootMismatch", err)
	}
}
