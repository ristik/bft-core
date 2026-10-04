package types

import (
	"math"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
)

// skewedTrust makes a four-member trust base where the first (sorted) node weighs 6 and the others 1: total 9,
// threshold 7. The heavy node plus one light node is a minority by count and a quorum by weight; the three light
// nodes are a majority by count and not a quorum.
func skewedTrust(t *testing.T, sb *structBuilder) (tb *types.RootTrustBaseV1, heavy string, light []string) {
	t.Helper()
	ids := make([]string, 0, len(sb.signers))
	for id := range sb.signers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	heavy, light = ids[0], ids[1:]
	var nodes []*types.NodeInfo
	for _, id := range ids {
		pub, err := sb.verifiers[id].MarshalPublicKey()
		require.NoError(t, err)
		stake := uint64(1)
		if id == heavy {
			stake = 6
		}
		nodes = append(nodes, &types.NodeInfo{NodeID: id, SigKey: pub, Stake: stake})
	}
	tb, err := types.NewTrustBase(5, nodes)
	require.NoError(t, err)
	require.EqualValues(t, 7, tb.QuorumThreshold)
	for _, id := range ids {
		require.NoError(t, tb.Sign(id, sb.signers[id]))
	}
	return tb, heavy, light
}

func keep(sigs map[string]hex.Bytes, ids ...string) map[string]hex.Bytes {
	out := map[string]hex.Bytes{}
	for _, id := range ids {
		out[id] = sigs[id]
	}
	return out
}

func TestQuorumCert_VerifyIsWeightedNotCounted(t *testing.T) {
	sb := newStructBuilder(t, 4)
	tb, heavy, light := skewedTrust(t, sb)

	qc := sb.QC(t, 10)
	all := qc.Signatures

	qc.Signatures = keep(all, heavy, light[0])
	require.NoError(t, qc.Verify(tb), "2 of 4 by count, 7 of 9 by weight")

	qc.Signatures = keep(all, light...)
	err := qc.Verify(tb)
	require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached, "3 of 4 by count, 3 of 9 by weight")
	require.ErrorContains(t, err, "signed_votes=3 quorum_threshold=7")
}

func TestQuorumCert_VerifyFollowsD3ForBadAndUnknownSigners(t *testing.T) {
	sb := newStructBuilder(t, 4)
	tb, heavy, light := skewedTrust(t, sb)
	qc := sb.QC(t, 10)
	good := keep(qc.Signatures, heavy, light[0])

	t.Run("an invalid extra signature of a known member is skipped as under v1 (D3 compatibility)", func(t *testing.T) {
		qc.Signatures = keep(good, heavy, light[0])
		qc.Signatures[light[1]] = []byte{1, 2, 3}
		require.NoError(t, qc.Verify(tb))
	})
	t.Run("an invalid signature carries no weight", func(t *testing.T) {
		qc.Signatures = keep(good, light[0])
		qc.Signatures[heavy] = []byte{1, 2, 3}
		require.ErrorIs(t, qc.Verify(tb), quorumweight.ErrQuorumNotReached)
	})
	t.Run("an unknown extra signer fails an otherwise sufficient certificate", func(t *testing.T) {
		qc.Signatures = keep(good, heavy, light[0])
		qc.Signatures["stranger"] = good[heavy]
		err := qc.Verify(tb)
		require.ErrorIs(t, err, quorumweight.ErrUnknownSigner)
	})
}

func TestQuorumCert_VerifyRefusesWeightOverflow(t *testing.T) {
	sb := newStructBuilder(t, 2)
	var nodes []*types.NodeInfo
	for id := range sb.signers {
		pub, err := sb.verifiers[id].MarshalPublicKey()
		require.NoError(t, err)
		nodes = append(nodes, &types.NodeInfo{NodeID: id, SigKey: pub, Stake: math.MaxUint64 - 1})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].NodeID < nodes[j].NodeID }) // lookup is a binary search
	// built by hand: NewTrustBase itself sums the stake unchecked
	tb := &types.RootTrustBaseV1{Version: 1, NetworkID: 5, Epoch: 1, RootNodes: nodes, QuorumThreshold: 5}
	qc := sb.QC(t, 10)
	require.ErrorIs(t, qc.Verify(tb), quorumweight.ErrWeightOverflow)
}

func TestTimeoutCert_VerifyIsWeightedNotCounted(t *testing.T) {
	sb := newStructBuilder(t, 4)
	tb, heavy, light := skewedTrust(t, sb)
	tbs, err := trustbase.NewTrustBaseStore(memorydb.New(), logger.New(t))
	require.NoError(t, err)
	require.NoError(t, tbs.Store(tb))

	tc := sb.TimeoutCert(t)
	all := tc.Signatures
	pick := func(ids ...string) map[string]*TimeoutVote {
		out := map[string]*TimeoutVote{}
		for _, id := range ids {
			out[id] = all[id]
		}
		return out
	}

	tc.Signatures = pick(heavy, light[0])
	require.NoError(t, tc.Verify(tbs), "2 of 4 by count, 7 of 9 by weight")

	tc.Signatures = pick(light...)
	err = tc.Verify(tbs)
	require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached)
	require.ErrorContains(t, err, "quorum requires 7 votes but certificate has 3")
}

func TestTimeoutCert_VerifyRefusesWeightOverflow(t *testing.T) {
	sb := newStructBuilder(t, 2)
	ids := make([]string, 0, 2)
	var nodes []*types.NodeInfo
	for id := range sb.signers {
		pub, err := sb.verifiers[id].MarshalPublicKey()
		require.NoError(t, err)
		ids = append(ids, id)
		nodes = append(nodes, &types.NodeInfo{NodeID: id, SigKey: pub, Stake: math.MaxUint64 - 1})
	}
	sort.Strings(ids)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].NodeID < nodes[j].NodeID })
	tb := &types.RootTrustBaseV1{Version: 1, NetworkID: 5, Epoch: 1, RootNodes: nodes, QuorumThreshold: 5}
	tb.Signatures = map[string]hex.Bytes{}
	// the genesis trust base is self-signed; one member alone reaches the threshold, so it installs
	require.NoError(t, tb.Sign(ids[0], sb.signers[ids[0]]))
	tbs, err := trustbase.NewTrustBaseStore(memorydb.New(), logger.New(t))
	require.NoError(t, err)
	require.NoError(t, tbs.Store(tb))

	tc := sb.TimeoutCert(t)
	// the embedded high QC must authenticate (one member alone reaches the threshold), so that the refusal comes from the
	// TC's own weight sum over both signers
	tc.Timeout.HighQc.Signatures = keep(tc.Timeout.HighQc.Signatures, ids[0])
	err = tc.Verify(tbs)
	require.ErrorIs(t, err, quorumweight.ErrWeightOverflow)
	require.ErrorContains(t, err, "timeout certificate weight")
}

func TestTimeoutCert_AddRefusesDuplicateSigner(t *testing.T) {
	sb := newStructBuilder(t, 4)
	tc := sb.TimeoutCert(t)
	id := ""
	for id = range tc.Signatures {
		break
	}
	err := tc.Add(id, tc.Timeout, tc.Signatures[id].Signature)
	require.ErrorIs(t, err, quorumweight.ErrDuplicateSigner)
}
