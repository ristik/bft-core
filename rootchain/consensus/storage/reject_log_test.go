package storage

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// #1303: every root logs each committed RejectResult with the ready bitmap the leader ordered (the evidence of who an expiry parked).
func TestACommittedRejectionIsLoggedWithItsOrderedBitmap(t *testing.T) {
	var rid vrschema.Word
	rid[0], rid[31] = 0xab, 0xcd
	v2 := rctypes.PosControl{Registry: true, Op: rctypes.OpRejectResult,
		Data: vrschema.OutputRejected{ResultID: rid, Reason: vrschema.RejExpired, ReadyBitmap: 0b01111}.Encode()}
	legacy := rctypes.PosControl{Op: rctypes.OpRejectResult, Data: bytes.Repeat([]byte{0x11}, 32)}
	other := rctypes.PosControl{Op: rctypes.OpRetirement}
	var buf bytes.Buffer
	x := &BlockStore{log: slog.New(slog.NewTextHandler(&buf, nil))}
	x.logCommittedRejections([]*ExecutedBlock{
		nil,
		{BlockData: &rctypes.BlockData{Round: 7}},
		{BlockData: &rctypes.BlockData{Round: 8, Payload: &rctypes.Payload{PosControls: []rctypes.PosControl{other, v2}}}},
		{BlockData: &rctypes.BlockData{Round: 9, Payload: &rctypes.Payload{PosControls: []rctypes.PosControl{legacy}}}},
	})
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	require.Len(t, lines, 2, buf.String())
	require.Contains(t, string(lines[0]), `msg="election result rejection committed" rootRound=8 registry=true result=ab`)
	require.Contains(t, string(lines[0]), "cd reason=1 readyBitmap=0x000f")
	require.Contains(t, string(lines[1]), "rootRound=9 registry=false result=1111")
	require.NotContains(t, string(lines[1]), "readyBitmap")

	// a control that does not decode is still logged, with its raw data
	bad := RejectionLogAttrs(rctypes.PosControl{Registry: true, Op: rctypes.OpRejectResult, Data: []byte{1}})
	require.Equal(t, []any{"registry", true, "data", "01"}, bad[:4])

	// no logger: nothing happens
	(&BlockStore{}).logCommittedRejections([]*ExecutedBlock{{BlockData: &rctypes.BlockData{Payload: &rctypes.Payload{PosControls: []rctypes.PosControl{v2}}}}})
}
