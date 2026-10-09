package storage

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

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

// Membership of the installed configuration is answered from the installed verifiers, so it holds for a weighted EVM assignment (which has
// no unit request context, and so no SignerWeight) as for a unit one; a candidate the installed configuration does not name is not a member
// until its assignment is installed.
func TestShardInfoMembershipIsTheInstalledConfigurationsForWeightedAndUnitAlike(t *testing.T) {
	f := newViewFixture(t)
	install := func(si *ShardInfo, conf *types.PartitionDescriptionRecord) {
		t.Helper()
		h, err := conf.Hash(crypto.SHA256)
		require.NoError(t, err)
		si.resetFeeList(conf)
		require.NoError(t, si.resetTrustBase(conf, crypto.SHA256, h))
	}
	weighted, _ := f.pdr(1, 7, 2, fxBody0, f.member(0, 0, 6), f.member(1, 1, 1), f.member(2, 2, 1))
	si := &ShardInfo{}
	install(si, weighted)
	require.Nil(t, si.RequestContext(), "a weighted configuration has no unit request context")
	_, err := si.SignerWeight(f.id(0))
	require.ErrorIs(t, err, quorumweight.ErrRequestContext, "so SignerWeight cannot answer membership here")
	for i := 0; i < 3; i++ {
		require.True(t, si.IsMember(f.id(i)), "member %d of the weighted configuration", i)
	}
	require.False(t, si.IsMember(f.id(3)), "a candidate that is not installed is refused")

	// the successor assignment (the candidate joins, member 2 leaves) is installed: membership follows it, not before
	next, _ := f.pdr(1, 7, 3, fxBody0, f.member(0, 0, 6), f.member(1, 1, 1), f.member(3, 3, 1))
	install(si, next)
	require.True(t, si.IsMember(f.id(3)), "the joiner once its assignment is installed")
	require.False(t, si.IsMember(f.id(2)), "a validator the installed configuration stopped naming")

	unit, _ := f.pdr(1, 7, 2, fxBody0, f.member(0, 0, 1), f.member(1, 1, 1), f.member(2, 2, 1))
	u := &ShardInfo{}
	install(u, unit)
	require.NotNil(t, u.RequestContext())
	require.True(t, u.IsMember(f.id(2)))
	require.False(t, u.IsMember(f.id(3)))
	require.False(t, (&ShardInfo{}).IsMember(f.id(0)), "nothing is installed yet")
}
