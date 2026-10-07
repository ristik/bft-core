package bridgeprofile

import (
	"fmt"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

// Feasibility workloads of design "Gas and finite development limits": real
// signed histories at 0/1/16/64/256/1024 transfers. Histories above the 64
// transfer direct cap are offline feasibility workloads, so they run the
// relation on the in-memory history without the decode caps.

// benchHistory builds a returned token with `transfers` transfers including the
// final burn (transfers >= 1): the mint, transfers-1 ordinary transfers, burn.
func benchHistory(b *testing.B, f *Fixture, transfers int) *History {
	b.Helper()
	keys := make([]*secp256k1.PrivateKey, transfers)
	for i := range keys {
		keys[i] = KeyFromSeed(fmt.Sprintf("bench-%d", i))
	}
	h, err := f.BuildToken(1, amt, keys)
	require.NoError(b, err)
	var rcpt [20]byte
	rcpt[0] = 1
	f.AppendBurn(h, keys[transfers-1], rcpt, amt)
	return h
}

// BenchmarkReturn measures the full relation on a returned token; the sub-test
// name carries the transfer count including the burn and the history bytes.
// BenchmarkMint is the zero-transfer case.
func BenchmarkReturn(b *testing.B) {
	f := fix()
	for _, n := range []int{1, 16, 64, 256, 1024} {
		h := benchHistory(b, f, n)
		raw := h.Bytes()
		b.Run(fmt.Sprintf("transfers=%d/bytes=%d", len(h.Transfers), len(raw)), func(b *testing.B) {
			b.ReportAllocs()
			if len(h.Transfers) <= MaxTransfers {
				for i := 0; i < b.N; i++ {
					if _, err := VerifyReturn(f.Cfg, raw); err != nil {
						b.Fatal(err)
					}
				}
				return
			}
			for i := 0; i < b.N; i++ {
				if _, _, err := verifyHistory(f.Cfg, h); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkMint(b *testing.B) {
	f := fix()
	h, err := f.BuildToken(1, amt, []*secp256k1.PrivateKey{KeyFromSeed("m")})
	require.NoError(b, err)
	raw := h.Bytes()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := VerifyMint(f.Cfg, raw); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkUnlock times the recovery-equality rule on its four outcomes.
func BenchmarkUnlock(b *testing.B) {
	k := KeyFromSeed("unlock-bench")
	sh, th := H([]byte("s")), H([]byte("t"))
	u := SignUnlock(k, sh, th)
	flipped := append([]byte{}, u...)
	flipped[64] ^= 1
	hk, hu := HighRecoveryUnlock(sh, th)
	hkey, _ := ParseKey(hk)
	b.Run("valid", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if VerifyUnlock(k.PubKey(), sh, th, u) != nil {
				b.Fatal("reject")
			}
		}
	})
	b.Run("wrong-recovered-key", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if VerifyUnlock(k.PubKey(), sh, th, flipped) == nil {
				b.Fatal("accept")
			}
		}
	})
	b.Run("id-out-of-range", func(b *testing.B) {
		bad := append([]byte{}, u...)
		bad[64] = 4
		for i := 0; i < b.N; i++ {
			if VerifyUnlock(k.PubKey(), sh, th, bad) == nil {
				b.Fatal("accept")
			}
		}
	})
	b.Run("id-2-or-3-valid", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if VerifyUnlock(hkey, sh, th, hu) != nil {
				b.Fatal("reject")
			}
		}
	})
}

func BenchmarkPolicyAndEnvelope(b *testing.B) {
	f := fix()
	e := &Envelope{PolicyBody: f.Policy.Bytes(), History: make([]byte, 4096),
		Anchors: []Anchor{{Partition: f.Policy.Partition, Shard: EmptyPrefixShard, ShardConfHash: f.Policy.ShardConf, UC: make([]byte, 4096)}}}
	for i := 0; i < MaxLeaves; i++ {
		e.LeafProofs = append(e.LeafProofs, LeafProof{Siblings: make([][32]byte, 16)})
	}
	raw, err := e.Encode()
	require.NoError(b, err)
	b.Run("decode+check", func(b *testing.B) {
		b.SetBytes(int64(len(raw)))
		for i := 0; i < b.N; i++ {
			d, err := DecodeEnvelope(raw)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := CheckPolicy(f.Cfg, d, MaxLeaves); err != nil {
				b.Fatal(err)
			}
		}
	})
}
