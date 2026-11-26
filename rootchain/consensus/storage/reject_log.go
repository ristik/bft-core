package storage

import (
	"fmt"

	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// RejectionLogAttrs are the log attributes of a RejectResult control: its result and, for a VR-mode (v2) control, the reason and the
// ready bitmap it orders. The bitmap is shape-checked only, never judged, and an Expired rejection parks the elected joiners whose bit is
// clear (ristik/bft-core#1303, design 3.7.4 on the PoS stack), so the ordered bitmap is the evidence of who was parked and why.
func RejectionLogAttrs(c rctypes.PosControl) []any {
	attrs := []any{"registry", c.Registry}
	if !c.Registry {
		return append(attrs, "result", fmt.Sprintf("%x", c.Data))
	}
	d, err := vrschema.DecodeOutputRejected(c.Data)
	if err != nil {
		return append(attrs, "data", fmt.Sprintf("%x", c.Data), "decodeError", err.Error())
	}
	return append(attrs, "result", fmt.Sprintf("%x", d.ResultID), "reason", d.Reason, "readyBitmap", fmt.Sprintf("0x%04x", d.ReadyBitmap))
}

// logCommittedRejections reports every RejectResult a commit passes, on every root, with the bitmap the leader ordered.
func (x *BlockStore) logCommittedRejections(blocks []*ExecutedBlock) {
	if x.log == nil {
		return
	}
	for _, b := range blocks {
		if b == nil || b.BlockData == nil || b.BlockData.Payload == nil {
			continue
		}
		for _, c := range b.BlockData.Payload.PosControls {
			if c.Op != rctypes.OpRejectResult {
				continue
			}
			x.log.Info("election result rejection committed", append([]any{"rootRound", b.BlockData.Round}, RejectionLogAttrs(c)...)...)
		}
	}
}
