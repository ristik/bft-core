package bridgeprofile

import (
	"bytes"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Each case below changes exactly one property of an otherwise valid certificate. Without the bounded scan the first two are accepted
// by native verification; with it they fail before any allocation or cryptography, and the scan reason is the named one.
func TestLockCertificateIntersectionScan(t *testing.T) {
	e := newEnv(t)
	_, lp := e.backedToken(t, 5, amt, oneKey())
	verify := func(mut func(*LockProof)) error {
		return VerifyMintBacking(e.F.Cfg, e.remint(t, lp, mut), e.Trust, e.Pin)
	}
	require.NoError(t, verify(func(*LockProof) {}))

	// The seal rule is the upstream rule: only an exact canonical 65-byte recoverable signature of a member counts; any other byte string is a
	// well-formed witness that counts zero. Replacing every signature leaves no quorum (ErrLockUC); adding such a witness beside the honest
	// quorum changes nothing.
	truncated := func(n int) func(p *LockProof) {
		return func(p *LockProof) {
			var uc types.UnicityCertificate
			require.NoError(t, types.Cbor.Unmarshal(p.UC, &uc))
			names := []string{}
			for k := range uc.UnicitySeal.Signatures {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, k := range names {
				require.Len(t, uc.UnicitySeal.Signatures[k], SDKSignatureLength)
				uc.UnicitySeal.Signatures[k] = uc.UnicitySeal.Signatures[k][:n]
			}
			b, err := types.Cbor.Marshal(&uc)
			require.NoError(t, err)
			p.UC = b
		}
	}
	t.Run("every 65 byte seal signature truncated to 64 has no weight", func(t *testing.T) {
		err := verify(truncated(64))
		require.ErrorIs(t, err, ErrLockUC)
		require.NotErrorIs(t, err, ErrCertScan, "a 64-byte value is a well-formed witness")
	})
	recovery := func(f func(byte) byte) func(p *LockProof) {
		return func(p *LockProof) {
			var uc types.UnicityCertificate
			require.NoError(t, types.Cbor.Unmarshal(p.UC, &uc))
			for k, sig := range uc.UnicitySeal.Signatures {
				c := bytes.Clone(sig)
				c[64] = f(c[64])
				uc.UnicitySeal.Signatures[k] = c
			}
			b, err := types.Cbor.Marshal(&uc)
			require.NoError(t, err)
			p.UC = b
		}
	}
	t.Run("recovery byte swapped between 0 and 1 is binding", func(t *testing.T) {
		require.ErrorIs(t, verify(recovery(func(v byte) byte { return v ^ 1 })), ErrLockUC)
	})
	t.Run("recovery byte 2", func(t *testing.T) {
		require.ErrorIs(t, verify(recovery(func(byte) byte { return 2 })), ErrLockUC)
	})
	t.Run("63 byte seal signatures have no weight", func(t *testing.T) {
		err := verify(truncated(63))
		require.ErrorIs(t, err, ErrLockUC)
		require.NotErrorIs(t, err, ErrCertScan)
	})
	extra := func(id string, sig []byte) func(p *LockProof) {
		return func(p *LockProof) {
			var uc types.UnicityCertificate
			require.NoError(t, types.Cbor.Unmarshal(p.UC, &uc))
			uc.UnicitySeal.Signatures[id] = sig
			b, err := types.Cbor.Marshal(&uc)
			require.NoError(t, err)
			p.UC = b
		}
	}
	t.Run("unknown signer or malformed witnesses beside the honest quorum change nothing", func(t *testing.T) {
		require.NoError(t, verify(extra("not-a-member", bytes.Repeat([]byte{1}, 65))))
		require.NoError(t, verify(extra("not-a-member", []byte{1, 2, 3})))
		require.NoError(t, verify(extra("not-a-member", bytes.Repeat([]byte{1}, 64))))
		require.NoError(t, verify(extra("not-a-member", bytes.Repeat([]byte{1}, 4000))))
	})

	t.Run("summary over the native sublimit", func(t *testing.T) {
		p, err := e.World.CertifiedWith(e.F, e.Auth, e.EVMPDR, e.Trust, testRound, 5, 9, func(ir *types.InputRecord) { ir.SummaryValue = bytes.Repeat([]byte{1}, b1ref.MaxSummaryBytes+1) })
		require.NoError(t, err)
		err = verify(func(l *LockProof) { *l = *p })
		require.ErrorIs(t, err, b1ref.ErrSummaryTooLong)
		require.ErrorIs(t, err, ErrCertScan)
		require.ErrorIs(t, err, ErrLockUC)
	})

	t.Run("summary exactly at the sublimit is not a scan failure", func(t *testing.T) {
		p, err := e.World.CertifiedWith(e.F, e.Auth, e.EVMPDR, e.Trust, testRound, 5, 9, func(ir *types.InputRecord) { ir.SummaryValue = bytes.Repeat([]byte{1}, b1ref.MaxSummaryBytes) })
		require.NoError(t, err)
		err = verify(func(l *LockProof) { *l = *p })
		require.NotErrorIs(t, err, ErrCertScan)
	})

	t.Run("certificate over the native byte cap", func(t *testing.T) {
		_, err := b1ref.ScanUC(make([]byte, b1ref.MaxUCBytes+1))
		require.ErrorIs(t, err, b1ref.ErrUCTooLarge)
	})
}

// A token whose certificate is not decodable is never projected, whatever else in it is valid.
func TestTokenProjectionDecodesEveryCertificate(t *testing.T) {
	e := newEnv(t)
	c := e.composed(t, 2, irTimeOK)
	tok, good := c.token(t)
	_, err := ProjectToken(good)
	require.NoError(t, err)

	replaceUC := func(uc []byte) []byte {
		cp := *tok
		cp.MintProof.UC = uc
		return cp.Bytes()
	}
	t.Run("tagged but not a certificate", func(t *testing.T) {
		_, err := ProjectToken(replaceUC(CTag(1, CBytes([]byte{1}))))
		require.ErrorIs(t, err, ErrCertScan)
	})
	cut := func(n int) []byte {
		var uc types.UnicityCertificate
		require.NoError(t, types.Cbor.Unmarshal(tok.MintProof.UC, &uc))
		for k, s := range uc.UnicitySeal.Signatures {
			uc.UnicitySeal.Signatures[k] = s[:n]
		}
		b, err := types.Cbor.Marshal(&uc)
		require.NoError(t, err)
		return b
	}
	t.Run("signatures of any width are well formed witnesses for the scan", func(t *testing.T) {
		for _, n := range []int{64, 63, 1} {
			_, err := ProjectToken(replaceUC(cut(n)))
			require.NoError(t, err, "width %d", n)
		}
	})
}

func TestCertificateSDKIntersectionSentinels(t *testing.T) {
	e := newEnv(t)
	_, lp := e.backedToken(t, 5, amt, oneKey())
	tok, _ := e.composed(t, 2, irTimeOK).token(t)
	for _, mutation := range certificateMutations() {
		t.Run(mutation.name, func(t *testing.T) {
			raw, err := replaceCertificateItem(tok.MintProof.UC, mutation.replacement, mutation.path...)
			require.NoError(t, err)
			if mutation.nativeAccepted {
				_, err = b1ref.ScanUC(raw)
				require.NoError(t, err, "native B1 acceptance is preserved")
			}
			cp := *tok
			cp.MintProof.UC = raw
			_, err = ProjectToken(cp.Bytes())
			require.ErrorIs(t, err, ErrCertScan)
			backed := e.remint(t, lp, func(p *LockProof) {
				p.UC, err = replaceCertificateItem(p.UC, mutation.replacement, mutation.path...)
				require.NoError(t, err)
			})
			err = VerifyMintBacking(e.F.Cfg, backed, e.Trust, e.Pin)
			require.ErrorIs(t, err, ErrCertScan)
			require.ErrorIs(t, err, ErrLockUC)
		})
	}
}

// There is no cumulative path budget (owner section 36): every certificate is bounded by its own native sublimits, and a token whose
// RSMT paths and certificate steps sum past the former 2,048-step budget projects.
func TestNoCumulativePathBudget(t *testing.T) {
	e := newEnv(t)
	raw, err := certificateWithSteps(e.composed(t, 2, irTimeOK).cert.InclusionProofs()[0].UC, 31)
	require.NoError(t, err)
	for i := 0; i < 65; i++ {
		require.NoError(t, scanCertificate(raw))
	}
	h, err := e.F.BuildToken(5, amt, manyKeys(8))
	require.NoError(t, err)
	proofs := make([]InclusionProof, 8)
	for i := range proofs {
		for bit := 0; bit < 256; bit++ {
			proofs[i].Bitmap[bit/8] |= 1 << (bit % 8)
		}
		proofs[i].Siblings = make([][32]byte, 256)
		proofs[i].UC = raw
	}
	_, err = ProjectToken(TokenFromHistory(h, proofs).Bytes())
	require.NoError(t, err, "8 x (256 siblings + 31 steps) is far above the former 2,048-step budget")
}
