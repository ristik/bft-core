package bridgeprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// #526 step 5 (briefs/526-step5-limits.md): the measurements behind MaxLeaves 24.

// The oracle's return history is exactly 548 + 272*L bytes for L leaves, while its transfer array has a one-byte CBOR head
// (at most 23 transfers).
func TestStep5HistoryBytesAreLinearInTheLeaves(t *testing.T) {
	d, err := NewDeployment()
	require.NoError(t, err)
	for tr := 1; tr <= 22; tr++ {
		h, res, _, err := ReturnHistory(d.F, tr)
		require.NoError(t, err)
		require.Equal(t, 548+272*len(res.Leaves), len(h.Bytes()), "%d transfers", tr)
	}
}

// RSMT membership paths have about log2(n) siblings for n state IDs: the mean within one of log2(n), the 99th percentile within
// four above it. STEP5_RSMT_LARGE=1 adds 10^6 state IDs (about 20 siblings, p99 23).
func TestStep5RSMTPathsHaveLogDepth(t *testing.T) {
	sizes := []int{1_000, 10_000, 100_000}
	if os.Getenv("STEP5_RSMT_LARGE") != "" {
		sizes = append(sizes, 1_000_000)
	}
	for _, n := range sizes {
		kv := make([]rsmtKV, n)
		for i := range kv {
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], uint64(i))
			kv[i] = rsmtKV{key: sha256.Sum256(append([]byte("sid/"), b[:]...)), value: sha256.Sum256(b[:])}
		}
		sort.Slice(kv, func(i, j int) bool { return bytes.Compare(kv[i].key[:], kv[j].key[:]) < 0 })
		root := rsmtBuild(kv)
		samples := min(2000, n)
		depths := make([]int, samples)
		sum := 0
		for i := range depths {
			_, sibs := root.proof(kv[(i*7919)%n].key)
			depths[i] = len(sibs)
			sum += depths[i]
		}
		sort.Ints(depths)
		mean, l := float64(sum)/float64(samples), math.Log2(float64(n))
		require.InDelta(t, l, mean, 1, "n=%d mean %.1f", n, mean)
		require.LessOrEqual(t, float64(depths[samples*99/100]), l+4, "n=%d p99", n)
		t.Logf("n=%d mean=%.1f p99=%d max=%d", n, mean, depths[samples*99/100], depths[samples-1])
	}
}

// step5Gate prices a consolidated bundle of L leaves with s siblings each over the real anchors of an (N, m) world.
func step5Gate(t *testing.T, d *Deployment, n, m, s, l int) uint64 {
	t.Helper()
	w := consolidatedWorld(t, n, depthOf(m))
	_, res, err := SpanningHistory(d.F, w, fixtureAnchors-2)
	require.NoError(t, err)
	cl, err := w.CertifyConsolidated(res.Leaves, nil, oneRound)
	require.NoError(t, err)
	hist := 548 + 272*l
	e := &Envelope{PolicyBody: d.F.Policy.Bytes(), History: make([]byte, hist), Anchors: cl.Anchors}
	var bm [32]byte
	for k := 0; k < s; k++ {
		bm[k/8] |= 0x80 >> uint(k%8)
	}
	for i := 0; i < l; i++ {
		e.LeafProofs = append(e.LeafProofs, LeafProof{AnchorIndex: uint16(i % len(cl.Anchors)), Bitmap: bm, Siblings: make([][32]byte, s)})
	}
	eb, err := e.Encode()
	require.NoError(t, err)
	cfg := d.F.Cfg.Bytes()
	g, err := computeGate(cfg, len(eb), KernelRequestBytes(len(cfg), hist), e)
	require.NoError(t, err)
	return g.Total()
}

// The estimate has no ceiling (owner section 36): the heaviest consolidated shape (a 16-member committee over 8 shards, 24 siblings)
// at the native leaf bound is priced far above the former 7,000,000 budget and is not refused; it only needs that much gas.
func TestEstimateHasNoCeiling(t *testing.T) {
	d, err := NewDeployment()
	require.NoError(t, err)
	g := step5Gate(t, d, 16, 8, 24, MaxLeaves)
	require.Greater(t, g, uint64(7_000_000))
	t.Logf("N=16 m=8 s=24 L=%d estimate %d", MaxLeaves, g)
}
