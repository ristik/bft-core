package configuredprogress

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

func journalWithEntries(t *testing.T) (*Store, *fixture) {
	t.Helper()
	f := newFixture(t, 2)
	s, _ := openJournal(t, f, testJournalLimits)
	t.Cleanup(func() { _ = s.Close() })
	bootstrap := f.bootstrap(1, 4)
	admitJournal(t, s, f, bootstrap)
	require.NoError(t, s.PutJournalCandidate(context.Background(), f.ctx, testJournalLimits, candidateB1(f, bootstrap)))
	admitJournal(t, s, f, f.first(1, 2, 5))
	return s, f
}

// bft-core#728: a journal load remembers the certificate verifications it made and does not repeat them; the answer is the one a load without the memo gives.
func TestLoadJournalMemoizesVerificationAndAnswersAsWithoutIt(t *testing.T) {
	s, f := journalWithEntries(t)
	s.vm.reset()
	require.Zero(t, s.vm.size())

	withMemo, err := s.loadJournal(context.Background(), f.ctx, testJournalLimits, true)
	require.NoError(t, err)
	filled := s.vm.size()
	require.Positive(t, filled, "the load remembered what it verified")

	again, err := s.loadJournal(context.Background(), f.ctx, testJournalLimits, true)
	require.NoError(t, err)
	require.Equal(t, filled, s.vm.size(), "a second load verifies nothing new")
	require.Equal(t, withMemo, again)

	s.vm.reset()
	without, err := s.loadJournal(context.Background(), f.ctx, testJournalLimits, false)
	require.NoError(t, err)
	require.Zero(t, s.vm.size(), "a load without the memo neither reads nor fills it")
	require.Equal(t, without, withMemo)
}

// A memoized verdict is not an answer for a different trust base: the same bytes under a trust base of different content verify again, and fail.
func TestLoadJournalMemoDoesNotOutliveTheTrustBase(t *testing.T) {
	s, f := journalWithEntries(t)
	_, err := s.LoadJournal(context.Background(), f.ctx, testJournalLimits)
	require.NoError(t, err)
	require.Positive(t, s.vm.size())

	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	other, ok := testtrustbase.NewTrustBase(t, signer).(*types.RootTrustBaseV1)
	require.True(t, ok)
	changed := f.ctx
	changed.Observation.TrustBases = testTrust{other}
	changed.Record.TrustBases = testTrust{other}
	_, err = s.LoadJournal(context.Background(), changed, testJournalLimits)
	require.Error(t, err, "the memo must not vouch for certificates under a trust base it has not seen")
}

// The memo is cleared when the store installs something its verdicts depend on, and on request.
func TestVerificationMemoIsClearedOnInstallAndOnRequest(t *testing.T) {
	f := newFixture(t, 2)
	s, _ := f.open(3)
	defer s.Close()
	g0 := s.vm.gen()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	g1 := s.vm.gen()
	require.Greater(t, g1, g0, "Initialize clears the memo")
	require.NoError(t, s.EnableJournal(context.Background(), f.ctx, testJournalLimits))
	g2 := s.vm.gen()
	require.Greater(t, g2, g1, "EnableJournal clears the memo")

	admitJournal(t, s, f, f.bootstrap(1, 4))
	_, err = s.LoadJournal(context.Background(), f.ctx, testJournalLimits)
	require.NoError(t, err)
	require.Positive(t, s.vm.size())
	s.ResetVerificationMemo()
	require.Zero(t, s.vm.size())
	require.Greater(t, s.vm.gen(), g2)
}

// Nothing is remembered for a certificate that failed verification.
func TestVerificationMemoRemembersOnlySuccesses(t *testing.T) {
	var m verifyMemo
	require.False(t, m.Verified([32]byte{1}))
	m.Remember([32]byte{1})
	require.True(t, m.Verified([32]byte{1}))
	require.False(t, m.Verified([32]byte{2}))
	m.reset()
	require.False(t, m.Verified([32]byte{1}))

	for i := 0; i < maxVerifyMemo+10; i++ {
		var k [32]byte
		k[0], k[1], k[2] = byte(i), byte(i>>8), byte(i>>16)
		m.Remember(k)
	}
	require.LessOrEqual(t, m.size(), maxVerifyMemo, "the memo is bounded")
}
