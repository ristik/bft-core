package archivewiring

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-core/network"
)

func resignWith(t *testing.T, signer abcrypto.Signer) func(*types.UnicityCertificate) {
	t.Helper()
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	pub, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(pub)
	require.NoError(t, err)
	return func(uc *types.UnicityCertificate) {
		uc.UnicitySeal.Signatures = nil
		require.NoError(t, uc.UnicitySeal.Sign(id.String(), signer))
	}
}

// A replica is only an availability source. If every replica serves a continuation whose certificates are signed solely by a
// key that is not in the trust base of the record's epoch (a key retired at a handoff), against a tip pinned from the current
// set, the restore is refused with a typed error, leaves no restore pin or observation, and the EL head stays at genesis.
// The control re-signs every record with the current key through the same path, so the only variable is the key.
func TestRestoreRefusesAContinuationSignedOnlyByRetiredKeys(t *testing.T) {
	t.Parallel()
	retry := FetchRetry{Initial: time.Millisecond, Max: 5 * time.Millisecond, Total: time.Hour}

	control := buildRetryRestoreFixtureMutating(t, 0, retry, func(f *wiringFixture, uc *types.UnicityCertificate) { resignWith(t, f.chain.Signer)(uc) }, nil)
	require.NoError(t, control.restore.Restore(context.Background()), "records re-signed by the current key are accepted")
	require.EqualValues(t, 5, control.executor.head.Number)

	retired, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	resign := resignWith(t, retired)
	fx := buildRetryRestoreFixtureMutating(t, 0, retry, func(_ *wiringFixture, uc *types.UnicityCertificate) { resign(uc) }, nil)
	err = fx.restore.Restore(context.Background())
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrRestore) || errors.Is(err, frontier.ErrInvalid), "got %v", err)
	image, loadErr := fx.journal.LoadJournal(context.Background(), fx.wf.context, fx.limits)
	require.NoError(t, loadErr)
	require.Nil(t, image.Restored, "a refused restore must not leave a restore pin")
	require.Empty(t, image.Observations)
	require.EqualValues(t, 0, fx.executor.head.Number, "the EL head must stay at the checked genesis")
	require.Less(t, fx.host.calls.Load(), int64(8), "an authentication failure is not retried")
}
