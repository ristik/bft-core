package q3active

import (
	"bytes"
	"crypto"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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
	rt, fixtures := requestScaleChain(t, epochs)
	return rt, fixtures[0]
}

// requestScaleChain is requestScaleRuntime with every fixture of the chain, first activation first.
func requestScaleChain(t *testing.T, epochs int) (*Runtime, []*q3fixture.Fixture) {
	t.Helper()
	first := q3fixture.New(t, q3fixture.Options{Assignment: true})
	tip := first
	all := []*q3fixture.Fixture{first}
	for e := 3; e <= epochs; e++ {
		tip = q3fixture.New(t, q3fixture.Options{After: tip, LastLinkOnly: true})
		all = append(all, tip)
	}
	require.NotNil(t, tip.History)
	require.EqualValues(t, epochs, tip.History.Tip().Epoch())
	rt := &Runtime{}
	rt.hist.Store(tip.History)
	for e := 2; e <= epochs; e++ {
		rt.completed.Store(uint64(e), struct{}{})
	}
	return rt, all
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
		rt, fixtures := requestScaleChain(t, epochs)
		first := fixtures[0]
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
		cold := testing.Benchmark(func(b *testing.B) {
			for range b.N {
				fresh, err := rt.RequestHistory(RequestHistoryConfig{Candidates: requestScaleCandidates{string(id[:]): first.Candidate}, HashAlg: crypto.SHA256,
					Network: q3fixture.Network, Version: 1, Anchor: requestScaleAnchor(first.ShardConf)})
				require.NoError(t, err)
				_, err = fresh.RequestChain(partition, types.ShardID{})
				require.NoError(t, err)
			}
		})
		t.Logf("epochs=%d: cold derivation %d ns/op, %d B/op, %d allocs/op", epochs, cold.NsPerOp(), cold.AllocedBytesPerOp(), cold.AllocsPerOp())
		// every activation in turn: the history extended by one epoch, then a resolution (the activation path)
		updates := testing.Benchmark(func(b *testing.B) {
			for range b.N {
				b.StopTimer()
				rt.hist.Store(fixtures[0].History)
				fresh, err := rt.RequestHistory(RequestHistoryConfig{Candidates: requestScaleCandidates{string(id[:]): first.Candidate}, HashAlg: crypto.SHA256,
					Network: q3fixture.Network, Version: 1, Anchor: requestScaleAnchor(first.ShardConf)})
				require.NoError(t, err)
				b.StartTimer()
				for _, f := range fixtures {
					rt.hist.Store(f.History)
					_, err = fresh.RequestChain(partition, types.ShardID{})
					require.NoError(t, err)
				}
			}
		})
		rt.hist.Store(fixtures[len(fixtures)-1].History)
		t.Logf("epochs=%d: all successive activation updates %d ns/op, %d B/op", epochs, updates.NsPerOp(), updates.AllocedBytesPerOp())
	}
	if os.Getenv("Q3_SCALE_EPOCHS") == "" {
		require.Less(t, ns[34], 3*ns[2], "a resolution at 34 epochs costs about what it costs at 2")
	}
}

// sliceHistory hides RequestChain: the resolver then validates the chain slice from the anchor on every resolution, as before #1032.
type sliceHistory struct{ h *RequestHistory }

func (s sliceHistory) Chain(p types.PartitionID, sh types.ShardID) ([]*storage.RequestActivation, error) {
	return s.h.Chain(p, sh)
}
func (s sliceHistory) Network() uint64 { return s.h.Network() }
func (s sliceHistory) Version() uint64 { return s.h.Version() }
func (s sliceHistory) RootIdentity(round uint64) (uint64, []byte, error) {
	return s.h.RootIdentity(round)
}

// The cached, incrementally derived chain resolves exactly the views a cold derivation validated from the anchor resolves: for every root
// interval of the history (each a different authorising root identity), for collection and certification, and for two different parents.
func TestCachedChainResolvesTheViewsOfAColdRebuild(t *testing.T) {
	rt, fixtures := requestScaleChain(t, 12)
	first := fixtures[0]
	id := first.Body.Identity()
	cfg := func() RequestHistoryConfig {
		return RequestHistoryConfig{Candidates: requestScaleCandidates{string(id[:]): first.Candidate}, HashAlg: crypto.SHA256, Network: q3fixture.Network,
			Version: 1, Anchor: requestScaleAnchor(first.ShardConf)}
	}
	cached, err := rt.RequestHistory(cfg())
	require.NoError(t, err)
	partition := q3fixture.PartitionID + 2
	parent := requestScaleParent(t, first.ShardConf, partition)
	other := requestScaleParent(t, first.ShardConf, partition)
	other.RootHash = bytes.Repeat([]byte{7}, 32)
	other.LastCR.UC.InputRecord.Hash = other.RootHash
	resolved := 0
	for epoch := uint64(1); epoch <= rt.History().Tip().Epoch(); epoch++ {
		e, err := rt.History().ForEpoch(epoch)
		require.NoError(t, err)
		for _, round := range []uint64{e.Start() + 1, e.Start() + 3} {
			for _, purpose := range []storage.RequestPurpose{storage.PurposeCollect, storage.PurposeCertify} {
				for i, p := range []*storage.ShardInfo{parent, other} {
					parentID := bytes.Repeat([]byte{byte(i + 1)}, 32)
					fresh, err := rt.RequestHistory(cfg())
					require.NoError(t, err)
					want, werr := storage.ResolveParentView(sliceHistory{fresh}, nil, p, parentID, round, crypto.SHA256, purpose, nil)
					got, gerr := storage.ResolveParentView(cached, nil, p, parentID, round, crypto.SHA256, purpose, nil)
					require.Equal(t, werr == nil, gerr == nil, "epoch %d round %d: %v / %v", epoch, round, werr, gerr)
					if werr != nil {
						continue
					}
					resolved++
					require.Equal(t, want.ViewKey(), got.ViewKey(), "epoch %d round %d purpose %d", epoch, round, purpose)
					require.Equal(t, want.AssignmentKey(), got.AssignmentKey())
					require.Equal(t, want.ExpectedTR(), got.ExpectedTR())
					require.Equal(t, want.Threshold(), got.Threshold())
					require.Equal(t, want.TotalWeight(), got.TotalWeight())
				}
			}
		}
	}
	require.Greater(t, resolved, 40, "views of every root interval were compared")
}

// Readers resolving concurrently with activations (the history extended epoch by epoch) and recoveries (Invalidate) always get a chain
// that is a prefix-consistent derivation of the history they read, and finish on the chain a fresh derivation produces. Run with -race.
func TestRequestHistoryUnderConcurrentActivationAndRecovery(t *testing.T) {
	rt, fixtures := requestScaleChain(t, 10)
	first := fixtures[0]
	id := first.Body.Identity()
	cfg := RequestHistoryConfig{Candidates: requestScaleCandidates{string(id[:]): first.Candidate}, HashAlg: crypto.SHA256, Network: q3fixture.Network,
		Version: 1, Anchor: requestScaleAnchor(first.ShardConf)}
	// start at the first activation only, and replay the activations while readers run
	rt.hist.Store(fixtures[0].History)
	hist, err := rt.RequestHistory(cfg)
	require.NoError(t, err)
	partitions := []types.PartitionID{q3fixture.PartitionID + 1, q3fixture.PartitionID + 2, q3fixture.PartitionID + 3}
	done := make(chan struct{})
	var wg sync.WaitGroup
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func(r int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-done:
					return
				default:
				}
				p := partitions[(r+i)%len(partitions)]
				c, err := hist.RequestChain(p, types.ShardID{})
				if err != nil {
					t.Errorf("resolution: %v", err)
					return
				}
				acts := c.Activations()
				for j := 1; j < len(acts); j++ {
					if acts[j].PDRHash() == nil || len(acts[j].RootBody()) == 0 {
						t.Errorf("incomplete entry %d", j)
						return
					}
				}
			}
		}(r)
	}
	for i, f := range fixtures[1:] {
		rt.hist.Store(f.History)
		if i%3 == 2 {
			hist.Invalidate()
		}
		time.Sleep(time.Millisecond)
	}
	close(done)
	wg.Wait()
	fresh, err := rt.RequestHistory(cfg)
	require.NoError(t, err)
	for _, p := range partitions {
		want, err := fresh.Chain(p, types.ShardID{})
		require.NoError(t, err)
		got, err := hist.Chain(p, types.ShardID{})
		require.NoError(t, err)
		require.Len(t, got, len(want))
		for i := range want {
			require.Equal(t, want[i].RootBody(), got[i].RootBody())
			require.Equal(t, want[i].PDRHash(), got[i].PDRHash())
		}
	}
}
