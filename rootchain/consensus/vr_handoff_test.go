package consensus

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/vrschedule"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

type recordingReader struct {
	out map[[32]byte]*vrhandoff.Output
}

// HeaderNumber resolves the certified block's true EVM number: the fixture certifies block hash {b..} at height 100+b, unequal to the shard
// round (b) it also carries, so the test can tell the two apart.
func (r recordingReader) HeaderNumber(_ context.Context, h [32]byte) (uint64, error) {
	return 100 + uint64(h[0]), nil
}

func (r recordingReader) OpenOutput(_ context.Context, _, root [32]byte) (*vrhandoff.Output, error) {
	return r.out[root], nil
}

// The commit observer's worker: committed blocks reach the observer oldest first with their parent links, so the first committed block at
// which R is published becomes its source.
func TestTheCommitWorkerRecordsTheSource(t *testing.T) {
	evm := types.PartitionShardID{PartitionID: 8, ShardID: types.ShardID{}.Key()}
	r := vrschema.Word{0x52}
	published := &vrhandoff.Output{State: vradmit.OutputState{ResultID: r, OpenOutput: r, Output: vrschema.OutputRecord{State: vrschema.OutPublished, OutputCommit: vrschema.Word{9}}}}
	sources, err := vrschedule.NewSources("")
	require.NoError(t, err)
	outputs := vrschedule.NewOutputs()
	v := &vrHandoff{cfg: VRHandoffConfig{EVM: evm, Log: slog.New(slog.DiscardHandler)}, commits: make(chan []vrschedule.CertifiedEVM, 4),
		update: func() (vrschedule.Committed, error) {
			return vrschedule.Committed{}, errors.New("not derivable in this test")
		},
		observer: &vrschedule.Observer{Reader: recordingReader{out: map[[32]byte]*vrhandoff.Output{{2}: published}}, Sources: sources, Outputs: outputs}}
	block := func(round, parent uint64, ts uint64, evmBlock, root byte) *storage.ExecutedBlock {
		si := &storage.ShardInfo{IR: &types.InputRecord{BlockHash: bytes.Repeat([]byte{evmBlock}, 32), Hash: append([]byte{root}, make([]byte, 31)...), RoundNumber: uint64(evmBlock)}}
		return &storage.ExecutedBlock{BlockData: &rctypes.BlockData{Round: round, Timestamp: ts, Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: parent}}},
			ShardState: storage.ShardStates{States: map[types.PartitionShardID]*storage.ShardInfo{evm: si}}}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go v.run(ctx)
	v.onCommit([]*storage.ExecutedBlock{block(10, 9, 1000, 1, 1)})
	v.onCommit([]*storage.ExecutedBlock{block(11, 10, 1011, 2, 2), block(12, 11, 1012, 2, 2)})
	require.Eventually(t, func() bool { _, ok := sources.Get(r); return ok }, 5*time.Second, 10*time.Millisecond)
	s, _ := sources.Get(r)
	require.EqualValues(t, 11, s.CertRootRound)
	require.EqualValues(t, 1011, s.CertUCTime)
	require.EqualValues(t, 102, s.EVMBlockNumber, "the verified EVM height of block 2, not its shard round")
}
