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

	t.Run("65 byte seal signature truncated to 64", func(t *testing.T) {
		err := verify(func(p *LockProof) {
			var uc types.UnicityCertificate
			require.NoError(t, types.Cbor.Unmarshal(p.UC, &uc))
			names := []string{}
			for k := range uc.UnicitySeal.Signatures {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, k := range names {
				require.Len(t, uc.UnicitySeal.Signatures[k], SDKSignatureLength)
				uc.UnicitySeal.Signatures[k] = uc.UnicitySeal.Signatures[k][:64]
			}
			b, err := types.Cbor.Marshal(&uc)
			require.NoError(t, err)
			p.UC = b
		})
		require.ErrorIs(t, err, ErrCertSigLength)
		require.ErrorIs(t, err, ErrLockUC)
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
	t.Run("signature truncated to 64 bytes", func(t *testing.T) {
		var uc types.UnicityCertificate
		require.NoError(t, types.Cbor.Unmarshal(tok.MintProof.UC, &uc))
		for k, s := range uc.UnicitySeal.Signatures {
			uc.UnicitySeal.Signatures[k] = s[:64]
		}
		b, err := types.Cbor.Marshal(&uc)
		require.NoError(t, err)
		_, err = ProjectToken(replaceUC(b))
		require.ErrorIs(t, err, ErrCertSigLength)
	})
}
