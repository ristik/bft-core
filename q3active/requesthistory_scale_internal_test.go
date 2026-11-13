package q3active

import (
	"crypto"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-go-base/types"
)

type requestScaleCandidates map[string][]byte

func (c requestScaleCandidates) HandoffCandidate(id []byte) ([]byte, error) {
	return c[string(id)], nil
}

// requestScaleRuntime is a runtime whose verified history holds a coupled first activation followed by root-only ones, epochs in all, every
// one admitted. The history is the fixtures' own verified one: an install envelope carries at most q3format.MaxLinks links, so a chain
// of hundreds of epochs is not installed through the journal here; what is measured is the request history over it.
func requestScaleRuntime(t *testing.T, epochs int) (*Runtime, *q3fixture.Fixture) {
	t.Helper()
	first := q3fixture.New(t, q3fixture.Options{Assignment: true})
	tip := first
	for e := 3; e <= epochs; e++ {
		tip = q3fixture.New(t, q3fixture.Options{After: tip, LastLinkOnly: true})
	}
	require.NotNil(t, tip.History)
	require.EqualValues(t, epochs, tip.History.Tip().Epoch())
	rt := &Runtime{}
	rt.hist.Store(tip.History)
	for e := 2; e <= epochs; e++ {
		rt.completed.Store(uint64(e), struct{}{})
	}
	return rt, first
}

func requestScaleAnchor(conf *types.PartitionDescriptionRecord) AnchorSource {
	return func(p types.PartitionID, s types.ShardID) (*types.PartitionDescriptionRecord, error) {
		cp := *conf
		cp.PartitionID, cp.ShardID = p, s
		return &cp, nil
	}
}

// requestScaleParent is the committed state of an aggregator shard the activations left unchanged: certified under its anchor.
func requestScaleParent(t *testing.T, conf *types.PartitionDescriptionRecord, partition types.PartitionID) *storage.ShardInfo {
	t.Helper()
	pdr, err := requestScaleAnchor(conf)(partition, types.ShardID{})
	require.NoError(t, err)
	si, err := storage.NewShardInfo(pdr, crypto.SHA256)
	require.NoError(t, err)
	si.RootHash = make([]byte, 32)
	ir := &types.InputRecord{Version: 1, RoundNumber: si.TR.Round, Epoch: si.TR.Epoch, PreviousHash: []byte{1}, Hash: si.RootHash, BlockHash: []byte{2},
		SummaryValue: []byte{3}, Timestamp: 1000}
	si.LastCR = &certification.CertificationResponse{Partition: partition, Technical: si.TR, UC: types.UnicityCertificate{Version: 1, InputRecord: ir,
		UnicityTreeCertificate: &types.UnicityTreeCertificate{Version: 1, Partition: partition},
		UnicitySeal:            &types.UnicitySeal{Version: 1, NetworkID: q3fixture.Network, RootChainRoundNumber: 10, Timestamp: 1000, Hash: []byte{4}}}}
	require.NoError(t, si.LastCR.SetTechnicalRecord(si.TR))
	return si
}

// Resolving a request view costs the same whatever the number of installed epochs (#1032): the activation chain is derived once
// per epoch, never again from the genesis per resolution. Q3_SCALE_EPOCHS (comma separated; e.g. 1,34,200, where 1 is taken as 2,
// the first activation) measures other sizes; the default keeps the test short.
func TestRequestResolutionCostIsFlatInEpochs(t *testing.T) {
	sizes := []int{2, 34}
	if s := os.Getenv("Q3_SCALE_EPOCHS"); s != "" {
		sizes = nil
		for _, f := range strings.Split(s, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(f))
			require.NoError(t, err)
			sizes = append(sizes, max(n, 2))
		}
	}
	ns := map[int]int64{}
	for _, epochs := range sizes {
		rt, first := requestScaleRuntime(t, epochs)
		id := first.Body.Identity()
		hist, err := rt.RequestHistory(RequestHistoryConfig{Candidates: requestScaleCandidates{string(id[:]): first.Candidate}, HashAlg: crypto.SHA256,
			Network: q3fixture.Network, Version: 1, Anchor: requestScaleAnchor(first.ShardConf)})
		require.NoError(t, err)
		partition := q3fixture.PartitionID + 1
		parent := requestScaleParent(t, first.ShardConf, partition)
		parentID := make([]byte, 32)
		round := rt.History().Tip().Start() + 1
		resolve := func() {
			view, err := storage.ResolveParentView(hist, nil, parent, parentID, round, crypto.SHA256, storage.PurposeCollect, nil)
			require.NoError(t, err)
			require.NotNil(t, view)
		}
		resolve()
		res := testing.Benchmark(func(b *testing.B) {
			for range b.N {
				resolve()
			}
		})
		ns[epochs] = res.NsPerOp()
		t.Logf("epochs=%d: %d ns/op, %d B/op, %d allocs/op", epochs, res.NsPerOp(), res.AllocedBytesPerOp(), res.AllocsPerOp())
	}
	if os.Getenv("Q3_SCALE_EPOCHS") == "" {
		require.Less(t, ns[34], 3*ns[2], "a resolution at 34 epochs costs about what it costs at 2")
	}
}
