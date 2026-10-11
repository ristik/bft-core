package q3format

import (
	"encoding/hex"
	"testing"
)

// receiptWireVector is the encoding scripts/h6/prepare-handoff.py reproduces byte for byte (its test holds the same hex): the Python helper
// plans a V3 handoff over the operator API and must send exactly the canonical receipt set, which the root refuses otherwise.
const receiptWireVector = "828267726f6f742d3031582031323334353637383930313233343536373839303132333435363738393031328267726f6f742d3032410a"

func TestReceiptSetWireVectorIsTheOneTheOperatorHelperEncodes(t *testing.T) {
	// listed out of order on purpose: the canonical set is ordered by node id
	got, err := EncodeReceipts([]Receipt{{NodeID: "root-02", Signature: []byte{0x0a}}, {NodeID: "root-01", Signature: []byte("12345678901234567890123456789012")}})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != receiptWireVector {
		t.Fatalf("receipt set encoding changed (update scripts/h6/prepare-handoff.py and its test with it): %x", got)
	}
}
