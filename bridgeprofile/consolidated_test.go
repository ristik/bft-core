package bridgeprofile

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/b1ref"
)

// consolidatedRow is one measured shape: committee size N, partition shards m, leaves L.
type consolidatedRow struct {
	N, M, L    int
	K, E, S, Q uint64 // anchors, distinct epochs, distinct seals, seal signatures checked (b1ref grouping)
	Batch      uint64 // the native CERT_BATCH_V2 charge
	Gate       uint64 // the protocol gate total of the consolidated bundle
	PerSIDGate uint64 // the same token on the per-SID path, each leaf under its own seal (protocol 5's worst case)
	Envelope   int    // envelope bytes of the consolidated bundle
	View       int    // encoded partition view bytes (never on chain)
}

func consolidatedWorld(t *testing.T, n, depth int) *AggregatorWorld {
	t.Helper()
	auth, err := NewCommittee(fmt.Sprint("consolidation-committee-", n), n)
	require.NoError(t, err)
	tb, err := auth.Genesis(DevNetwork, 1, 1)
	require.NoError(t, err)
	w, err := NewShardedAggregator(auth, tb, depth)
	require.NoError(t, err)
	return w
}

func depthOf(m int) int {
	d := 0
	for 1<<d < m {
		d++
	}
	return d
}

func oneRound(int, Leaf) ShardRound { return ShardRound{BaseTime + 1000, 100} }

func encodeEnvelope(t *testing.T, f *Fixture, h *History, c *CertifiedLeaves) []byte {
	t.Helper()
	e := &Envelope{PolicyBody: f.Policy.Bytes(), History: h.Bytes(), Anchors: c.Anchors, LeafProofs: c.Proofs}
	b, err := e.Encode()
	require.NoError(t, err)
	return b
}

func measureConsolidated(t *testing.T, d *Deployment, n, m, transfers int) consolidatedRow {
	t.Helper()
	w := consolidatedWorld(t, n, depthOf(m))
	h, res, err := SpanningHistory(d.F, w, transfers)
	require.NoError(t, err)
	cl, err := w.CertifyConsolidated(res.Leaves, nil, oneRound)
	require.NoError(t, err)
	eb := encodeEnvelope(t, d.F, h, cl.CertifiedLeaves)
	gt, err := GateOf(d.F.Cfg, OpReturn, eb)
	require.NoError(t, err)
	grp, err := b1ref.Group(CertBatchRequest(cl.Anchors))
	require.NoError(t, err)
	require.NoError(t, RefB1{TB: w.TB}.AuthenticateAnchors(cl.Anchors), "B1 authenticates every derived certificate")
	per, err := w.CertifyAssigned(res.Leaves, nil, func(i int, _ Leaf) ShardRound { return ShardRound{BaseTime + 1000, 100 + uint64(i)} })
	require.NoError(t, err)
	pg, err := GateOf(d.F.Cfg, OpReturn, encodeEnvelope(t, d.F, h, per))
	require.NoError(t, err)
	return consolidatedRow{N: n, M: m, L: len(res.Leaves), K: grp.K, E: grp.E, S: grp.S, Q: grp.Q, Batch: grp.Gas, Gate: gt.Total(),
		PerSIDGate: pg.Total(), Envelope: len(eb), View: len(cl.Views[0])}
}

// TestConsolidatedGateTable is the measured table of bridgeprofile/README.md ("Consolidated bundles"): return histories of 8 and 16
// leaves spanning m = 1, 2, 4, 8 shards, consolidated under one seal of a 4- or 16-member committee. Every bundle has one anchor per
// shard and one seal (E = S = 1, Q = N); the same token on the per-SID path (one seal per leaf) costs more. No estimate is refused
// (owner section 36): the table only prices them.
func TestConsolidatedGateTable(t *testing.T) {
	d, err := NewDeployment()
	require.NoError(t, err)
	want := []consolidatedRow{
		{4, 1, 8, 1, 1, 1, 4, 136_008, 2_119_114, 3_646_536, 6_432, 193},
		{4, 1, 16, 1, 1, 1, 4, 136_008, 2_810_514, 6_084_408, 11_296, 193},
		{4, 2, 8, 2, 1, 1, 4, 154_740, 2_298_270, 3_685_464, 7_552, 382},
		{4, 2, 16, 2, 1, 1, 4, 154_740, 2_958_998, 6_162_264, 12_160, 382},
		{4, 4, 8, 4, 1, 1, 4, 196_792, 2_699_986, 3_724_392, 10_112, 760},
		{4, 4, 16, 4, 1, 1, 4, 196_792, 3_330_042, 6_240_120, 14_464, 760},
		{4, 8, 8, 8, 1, 1, 4, 296_072, 3_561_720, 3_763_320, 15_584, 1_516},
		{4, 8, 16, 8, 1, 1, 4, 296_072, 4_176_440, 6_317_976, 19_808, 1_516},
		{16, 1, 8, 1, 1, 1, 16, 245_832, 2_394_250, 5_847_624, 7_904, 193},
		{16, 1, 16, 1, 1, 1, 16, 245_832, 3_085_650, 10_486_584, 12_768, 193},
		{16, 2, 8, 2, 1, 1, 16, 287_988, 2_762_142, 5_886_552, 10_496, 382},
		{16, 2, 16, 2, 1, 1, 16, 287_988, 3_422_870, 10_564_440, 15_104, 382},
		{16, 4, 8, 4, 1, 1, 16, 376_888, 3_541_330, 5_925_480, 16_000, 760},
		{16, 4, 16, 4, 1, 1, 16, 376_888, 4_171_386, 10_642_296, 20_352, 760},
		{16, 8, 8, 8, 1, 1, 16, 569_864, 5_158_008, 5_964_408, 27_360, 1_516},
		{16, 8, 16, 8, 1, 1, 16, 569_864, 5_772_728, 10_720_152, 31_584, 1_516},
	}
	i := 0
	for _, n := range []int{4, 16} {
		for _, m := range []int{1, 2, 4, 8} {
			for _, transfers := range []int{6, fixtureAnchors - 2} {
				got := measureConsolidated(t, d, n, m, transfers)
				require.Equal(t, want[i], got, "N=%d m=%d transfers=%d", n, m, transfers)
				require.Equal(t, uint64(m), got.K, "one anchor per shard")
				require.Equal(t, [3]uint64{1, 1, uint64(n)}, [3]uint64{got.E, got.S, got.Q}, "one seal")
				require.Less(t, got.Gate, got.PerSIDGate)
				i++
			}
		}
	}
}

// The anchors CertifyConsolidated derives from the authenticated view are byte for byte the certificates the round's seal gives each
// shard directly (CertifyShards over the same shard tree): consolidation reconstructs ordinary UCs, it invents nothing.
func TestConsolidatedCertificatesAreTheRoundsOrdinaryUCs(t *testing.T) {
	d, err := NewDeployment()
	require.NoError(t, err)
	w := consolidatedWorld(t, 4, 3)
	_, res, err := SpanningHistory(d.F, w, fixtureAnchors-2)
	require.NoError(t, err)
	cl, err := w.CertifyConsolidated(res.Leaves, nil, oneRound)
	require.NoError(t, err)
	require.Len(t, cl.Anchors, 8)
	for i, a := range cl.Anchors {
		var uc types.UnicityCertificate
		require.NoError(t, types.Cbor.Unmarshal(a.UC, &uc))
		inputs := make([]ShardInput, len(w.PDRs))
		var view types.PartitionViewV1
		require.NoError(t, types.Cbor.Unmarshal(cl.Views[0], &view))
		for row, l := range view.Leaves {
			inputs[row] = ShardInput{PDR: w.PDRs[row], IR: l.InputRecord}
		}
		direct, err := w.Auth.CertifyShards(w.TB.GetNetworkID(), w.TB.GetEpoch(), 100, inputs, cl.Rows[i])
		require.NoError(t, err)
		db, err := types.Cbor.Marshal(direct)
		require.NoError(t, err)
		require.Equal(t, db, a.UC, "anchor %d (shard row %d)", i, cl.Rows[i])
	}
}

// A mixed bundle (one consolidated group plus a leaf under a later seal) has the group's anchors plus one, and two seals.
func TestConsolidatedMixedBundle(t *testing.T) {
	d, err := NewDeployment()
	require.NoError(t, err)
	w := consolidatedWorld(t, 4, 2)
	_, res, err := SpanningHistory(d.F, w, fixtureAnchors-2)
	require.NoError(t, err)
	last := len(res.Leaves) - 1
	cl, err := w.CertifyConsolidated(res.Leaves, nil, func(i int, _ Leaf) ShardRound {
		if i == last {
			return ShardRound{BaseTime + 1000, 101}
		}
		return ShardRound{BaseTime + 1000, 100}
	})
	require.NoError(t, err)
	grp, err := b1ref.Group(CertBatchRequest(cl.Anchors))
	require.NoError(t, err)
	require.Equal(t, [3]uint64{5, 1, 2}, [3]uint64{grp.K, grp.E, grp.S})
	require.Len(t, cl.Views, 2)
	require.NoError(t, RefB1{TB: w.TB}.AuthenticateAnchors(cl.Anchors))
}

// A derived certificate whose shard path was altered gets exactly the B1 refusal an ordinary certificate altered the same way gets:
// the chain never sees the view, so a forged derived UC is just a bad UC.
func TestConsolidatedAlteredShardLeafIsRefusedLikeAnyUC(t *testing.T) {
	d, err := NewDeployment()
	require.NoError(t, err)
	w := consolidatedWorld(t, 4, 2)
	_, res, err := SpanningHistory(d.F, w, fixtureAnchors-2)
	require.NoError(t, err)
	cl, err := w.CertifyConsolidated(res.Leaves, nil, oneRound)
	require.NoError(t, err)
	ordinary, err := w.CertifyAssigned(res.Leaves, nil, oneRound) // one UC per shard, each sealed on its own
	require.NoError(t, err)
	verdict := func(anchors []Anchor) b1ref.Verdict {
		st, pins, err := RefB1{TB: w.TB}.registry()
		require.NoError(t, err)
		v, err := b1ref.Cert(CertBatchRequest(anchors), st, pins)
		require.NoError(t, err)
		return v
	}
	alter := func(as []Anchor) []Anchor {
		out := append([]Anchor{}, as...)
		ucb, err := AlterShardSibling(out[1].UC)
		require.NoError(t, err)
		out[1].UC = ucb
		return out
	}
	require.True(t, verdict(cl.Anchors).Valid)
	require.True(t, verdict(ordinary.Anchors).Valid)
	vc, vo := verdict(alter(cl.Anchors)), verdict(alter(ordinary.Anchors))
	require.False(t, vc.Valid)
	require.False(t, vo.Valid)
	require.Error(t, vc.Why)
	require.True(t, errors.Is(vc.Why, vo.Why) || vc.Why.Error() == vo.Why.Error(), "the same refusal: %v / %v", vc.Why, vo.Why)
}

// The view's V1 limit is 8 shards: a 16-shard partition is refused by the generator, as consolidation refuses it.
func TestConsolidatedShardLimit(t *testing.T) {
	auth, err := NewCommittee("consolidation-committee-4", 4)
	require.NoError(t, err)
	tb, err := auth.Genesis(DevNetwork, 1, 1)
	require.NoError(t, err)
	_, err = NewShardedAggregator(auth, tb, 4)
	require.Error(t, err)
}

// RefB1 authenticates an anchor table under the composition's limits, as BRIDGE_COMPOSE_V1 does: 64 anchors (one UC per leaf) are
// above a standalone CERT_BATCH_V2 call's 16 claims and verify; the standalone evaluation refuses the same request's claim count.
func TestRefB1ComposedAnchorTable(t *testing.T) {
	d, err := NewDeployment()
	require.NoError(t, err)
	w := consolidatedWorld(t, 4, 2)
	_, res, _, err := ReturnHistorySeeded(d.F, 62, "refb1-composed")
	require.NoError(t, err)
	cert, err := w.CertifyAssigned(res.Leaves, nil, func(i int, _ Leaf) ShardRound { return ShardRound{BaseTime + 2000, 100 + uint64(i)} })
	require.NoError(t, err)
	require.Len(t, cert.Anchors, 64)
	require.NoError(t, RefB1{TB: w.TB}.AuthenticateAnchors(cert.Anchors))
	words, pins, err := RefB1{TB: w.TB}.Registry()
	require.NoError(t, err)
	_, err = b1ref.Cert(CertBatchRequest(cert.Anchors), words, pins)
	require.ErrorIs(t, err, b1ref.ErrCount)
}
