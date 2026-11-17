package consensus

import (
	"bytes"
	"context"
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

// I-RET: the first verified certificate of an intent is held; a later one of the same intent and epoch is not taken, one of another intent
// replaces it.
func TestTheFirstCertificateOfAnIntentWins(t *testing.T) {
	v := &vrHandoff{}
	p := vrschedule.PreparePlan{Intent: [32]byte{1}, Epoch: 1, Certificate: vrschema.ViewCertificate{Assembly: vrschema.Assembly{Slot: 0}}}
	require.True(t, v.hold(p))
	later := p
	later.Certificate.Assembly.Slot = 3
	require.False(t, v.hold(later))
	require.EqualValues(t, 0, v.current().cert.Assembly.Slot)
	next := p
	next.Intent = [32]byte{2}
	require.True(t, v.hold(next))
	require.Equal(t, [32]byte{2}, v.current().intent)
}

type recordingReader struct {
	out map[[32]byte]*vrhandoff.Output
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
	v := &vrHandoff{cfg: VRHandoffConfig{EVM: evm, Log: slog.New(slog.DiscardHandler)}, queue: make(chan []vrschedule.CertifiedEVM, 4),
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
}
