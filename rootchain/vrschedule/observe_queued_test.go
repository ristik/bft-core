package vrschedule

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/unicitynetwork/bft-core/vrclient"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
)

type queuedFake struct {
	queued []vrschema.Activation
	got    *[][32]byte
}

func (queuedFake) OpenOutput(context.Context, [32]byte, [32]byte) (*vrhandoff.Output, error) {
	return nil, nil // VR has no open output
}
func (f queuedFake) QueuedSchedules(_ context.Context, h [32]byte) ([]vrschema.Activation, error) {
	*f.got = append(*f.got, h)
	return f.queued, nil
}

// Through the real observer path: with NO open output at all, a ScheduleActivation change VR still holds Queued is reported to the
// warning (design section 7.4, astra r3 item 3), and keeps being reported with every later observation until the next read says otherwise.
func TestObserverReportsAQueuedChangeWithNoOpenOutput(t *testing.T) {
	queued := vrschema.Activation{RuleID: vrschema.RuleID("unknown"), ReleaseDigest: vrschema.Word{1}, RootEpoch: 12, State: vrschema.ActActive, ChangeID: 3}
	var got [][]vrschema.Activation
	var hashes [][32]byte
	o := &Observer{Reader: queuedFake{queued: []vrschema.Activation{queued}, got: &hashes}, Outputs: NewOutputs(), SyncQueued: true,
		OnPending: func(a []vrschema.Activation) { got = append(got, a) }}
	require.NoError(t, o.Observe(context.Background(), CertifiedEVM{BlockHash: [32]byte{7}, ShardRound: 3, StateRoot: [32]byte{1}, RootRound: 1}))
	require.NotEmpty(t, got)
	require.Equal(t, []vrschema.Activation{queued}, got[len(got)-1], "the queued change is reported although no output is open")
	require.Equal(t, [][32]byte{{7}}, hashes, "the queue is read at the certified block's hash, not its number")
	// the next observed block (within QueuedEvery, so no new read) still carries it
	require.NoError(t, o.Observe(context.Background(), CertifiedEVM{BlockHash: [32]byte{8}, ShardRound: 3, StateRoot: [32]byte{2}, RootRound: 2, ParentRound: 1}))
	require.Equal(t, []vrschema.Activation{queued}, got[len(got)-1])
}

// The real RPC selector: the queue reads carry the certified block's HASH (EIP-1898), unequal to anything derived from a round or number
// (astra r4 item 2), for pendingChanges and for every change.
type captureRPC struct{ blocks []any }

func (c *captureRPC) CallContext(_ context.Context, result any, method string, args ...any) error {
	if method == "eth_call" && len(args) == 2 {
		c.blocks = append(c.blocks, args[1])
	}
	return errStop
}

var errStop = errors.New("stop")

func TestQueuedSchedulesReadAtTheCertifiedBlockHash(t *testing.T) {
	c := &captureRPC{}
	cl := vrclient.New(c, common.Address{})
	cl.Block = hexutil.Encode(bytes.Repeat([]byte{0xab}, 32))
	_, err := cl.PendingChanges(context.Background())
	require.Error(t, err)
	require.Equal(t, []any{map[string]string{"blockHash": cl.Block}}, c.blocks, "a hash is sent as the EIP-1898 object")
	cl.Block = "0x2a"
	c.blocks = nil
	_, _ = cl.PendingChanges(context.Background())
	require.Equal(t, []any{"0x2a"}, c.blocks, "a number stays a number")
}
