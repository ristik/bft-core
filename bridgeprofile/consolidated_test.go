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
		{4, 1, 8, 1, 1, 1, 4, 131_208, 2_114_314, 3_608_136, 6_432, 193},
		{4, 1, 16, 1, 1, 1, 4, 131_208, 2_805_714, 6_007_608, 11_296, 193},
		{4, 2, 8, 2, 1, 1, 4, 149_940, 2_293_470, 3_647_064, 7_552, 382},
		{4, 2, 16, 2, 1, 1, 4, 149_940, 2_954_198, 6_085_464, 12_160, 382},
		{4, 4, 8, 4, 1, 1, 4, 191_992, 2_695_186, 3_685_992, 10_112, 760},
		{4, 4, 16, 4, 1, 1, 4, 191_992, 3_325_242, 6_163_320, 14_464, 760},
		{4, 8, 8, 8, 1, 1, 4, 291_272, 3_556_920, 3_724_920, 15_584, 1_516},
		{4, 8, 16, 8, 1, 1, 4, 291_272, 4_171_640, 6_241_176, 19_808, 1_516},
		{16, 1, 8, 1, 1, 1, 16, 226_632, 2_375_050, 5_694_024, 7_904, 193},
		{16, 1, 16, 1, 1, 1, 16, 226_632, 3_066_450, 10_179_384, 12_768, 193},
		{16, 2, 8, 2, 1, 1, 16, 268_788, 2_742_942, 5_732_952, 10_496, 382},
		{16, 2, 16, 2, 1, 1, 16, 268_788, 3_403_670, 10_257_240, 15_104, 382},
		{16, 4, 8, 4, 1, 1, 16, 357_688, 3_522_130, 5_771_880, 16_000, 760},
		{16, 4, 16, 4, 1, 1, 16, 357_688, 4_152_186, 10_335_096, 20_352, 760},
		{16, 8, 8, 8, 1, 1, 16, 550_664, 5_138_808, 5_810_808, 27_360, 1_516},
		{16, 8, 16, 8, 1, 1, 16, 550_664, 5_753_528, 10_412_952, 31_584, 1_516},
	}
	i := 0
	for _, n := range []int{4, 16} {
		for _, m := range []int{1, 2, 4, 8} {
			for _, transfers := range []int{6, MaxAnchors - 2} {
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
	_, res, err := SpanningHistory(d.F, w, MaxAnchors-2)
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
	_, res, err := SpanningHistory(d.F, w, MaxAnchors-2)
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
	_, res, err := SpanningHistory(d.F, w, MaxAnchors-2)
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
