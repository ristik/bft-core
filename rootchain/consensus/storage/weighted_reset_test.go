package storage

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
)

// A weighted EVM assignment (only a verified Q3 activation installs one) installs its members and verifiers on a ShardInfo and no
// unit request context: counting under the legacy dispatch is refused, never a fallback to counting members, and the weighted count
// is the request view's. Every refusal differs from the control in one thing.
func TestAWeightedEVMConfigurationHasNoUnitRequestContext(t *testing.T) {
	f := newViewFixture(t)
	weightedConf, _ := f.pdr(1, 7, 2, fxBody0, f.member(0, 0, 6), f.member(1, 1, 1), f.member(2, 2, 1), f.member(3, 3, 1))
	committed, err := weightedConf.Hash(crypto.SHA256)
	require.NoError(t, err)
	reset := func(hash []byte) (*ShardInfo, error) {
		si := &ShardInfo{}
		si.resetFeeList(weightedConf)
		return si, si.resetTrustBase(weightedConf, crypto.SHA256, hash)
	}

	si, err := reset(committed)
	require.NoError(t, err, "acceptance control")
	require.Nil(t, si.RequestContext())
	require.Zero(t, si.TotalWeight())
	require.Zero(t, si.Threshold())
	_, err = si.SignerWeight(f.id(0))
	require.ErrorIs(t, err, quorumweight.ErrRequestContext, "no unit counting of a weighted configuration")
	require.Len(t, si.nodeIDs, 4, "the members are installed")
	require.Len(t, si.trustBase, 4, "and their verifiers")

	t.Run("the configuration must be the committed one", func(t *testing.T) {
		other := append([]byte(nil), committed...)
		other[0] ^= 1
		_, err := reset(other)
		require.ErrorIs(t, err, quorumweight.ErrRequestContext)
		_, err = reset(nil)
		require.ErrorIs(t, err, quorumweight.ErrRequestContext)
	})
	t.Run("an aggregator configuration is never weighted", func(t *testing.T) {
		agg := aggregatorWith(f, 1, 7, 6)
		h, err := agg.Hash(crypto.SHA256)
		require.NoError(t, err)
		bad := &ShardInfo{}
		bad.resetFeeList(agg)
		require.ErrorIs(t, bad.resetTrustBase(agg, crypto.SHA256, h), quorumweight.ErrWeightCap)
	})
	t.Run("a unit EVM configuration keeps its unit context", func(t *testing.T) {
		unit, _ := f.pdr(1, 7, 2, fxBody0, f.member(0, 0, 1), f.member(1, 1, 1), f.member(2, 2, 1))
		h, err := unit.Hash(crypto.SHA256)
		require.NoError(t, err)
		u := &ShardInfo{}
		u.resetFeeList(unit)
		require.NoError(t, u.resetTrustBase(unit, crypto.SHA256, h))
		require.NotNil(t, u.RequestContext())
		require.EqualValues(t, 3, u.TotalWeight())
	})
}
