package nb2ref

import (
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func mustWorld(t testing.TB, k, b uint64, shards int) *World {
	t.Helper()
	w, err := NewWorld(k, b, shards)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestDirectReturnVerifies(t *testing.T) {
	for _, shards := range []int{1, 2} {
		w := mustWorld(t, 64, 16, shards)
		owner, k2 := Key("a"), Key("b")
		dep, err := w.MakeDeposit(big.NewInt(100), owner, ReceiptOpts{Type: 2, TxIndex: 3, FillerLogs: 1})
		if err != nil {
			t.Fatal(err)
		}
		d := w.RootDraft(dep, []*secp256k1.PrivateKey{owner, k2})
		d.Return(w.ReturnTo(dep.Value, Recipient20("r"), 0))
		tok, err := w.Finalize(d)
		if err != nil {
			t.Fatal(err)
		}
		v, err := VerifyReturn(w.Gamma, Evidence(tok.Bytes()), w.Trust, CandidateParams)
		if err != nil {
			t.Fatalf("shards %d: %v", shards, err)
		}
		if v.Amount.Cmp(big.NewInt(100)) != 0 || v.Recipient != Recipient20("r") || v.MinSegment != 0 || v.Domain != w.Cfg.Domain() {
			t.Fatalf("verdict %+v", v)
		}
	}
}
