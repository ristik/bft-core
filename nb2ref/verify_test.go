package nb2ref

import (
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

func TestLegacyReturnUsesFixedUCTAsset(t *testing.T) {
	for _, useConfigAsset := range []bool{false, true} {
		w := mustWorld(t, 64, 16, 2)
		w.Cfg.Asset = HU([]byte("not the UCT asset"))
		w.Gamma = w.Cfg.Bytes()
		owner := Key("legacy-uct-return")
		dep, err := w.MakeDeposit(big.NewInt(100), owner, ReceiptOpts{})
		require.NoError(t, err)
		draft := w.RootDraft(dep, []*secp256k1.PrivateKey{owner})
		ret := w.ReturnTo(dep.Value, Recipient20("legacy-uct-recipient"), 0)
		if useConfigAsset {
			ret.Asset = w.Cfg.Asset
		}
		draft.Return(ret)
		token, err := w.Finalize(draft)
		require.NoError(t, err)
		verdict, err := VerifyReturn(w.Gamma, Evidence(token.Bytes()), w.Trust, CandidateParams)
		if useConfigAsset {
			require.ErrorIs(t, err, ErrReturnAsset)
		} else {
			require.NoError(t, err)
			require.Equal(t, AssetUCT, verdict.Asset)
		}
	}
}

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
