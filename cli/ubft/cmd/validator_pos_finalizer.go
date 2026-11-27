package cmd

// #1323: one designated finalizer per ready P85 result. Every active member's `pos-publish --participate` sees the result ready (every frozen
// member's possession proof is stored) at about the same block, and each used to send finalizeCandidate and VR.publish at once: every
// simulation passed, and all but the first finalizeCandidate reverted in the mined block. The members now take turns: the frozen roster in
// ascending identity order, the lowest first, at once; the member of rank k only after k steps of chain time since the block that made the
// result ready, if nobody has finished by then. The order is read from the chain alone (the frozen roster and the PoPAccepted logs), so it
// needs no coordinator and no relay: any member still finalizes and publishes after its delay, and the delay is bounded.

import (
	"context"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/unicitynetwork/bft-core/vrclient"
)

const (
	// defaultFinalizerStep is the chain time between two finalizer ranks: the designated finalizer's finalizeCandidate and VR.publish are two
	// receipts, about two 10 s blocks after it first polls the ready result.
	defaultFinalizerStep = 30 * time.Second
	// finalizerMaxRank bounds the delay: the members from this rank on share the last turn (8 steps).
	finalizerMaxRank = 8
	// finalizerLogWindow is the block range the PoPAccepted logs are read in (the public gateway's eth_getLogs limit). A result whose proofs
	// were not all accepted in it has been ready for longer than every turn: every member may finalize.
	finalizerLogWindow = 10_000
)

// popAcceptedTopic is ElectionPolicy's PoPAccepted(bytes32 indexed resultID, uint64 indexed id, bytes32 signatureHash).
var popAcceptedTopic = ethcrypto.Keccak256Hash([]byte("PoPAccepted(bytes32,uint64,bytes32)"))

// finalizerRank is a sender's turn for a result: its position in the frozen roster by ascending identity id; a sender that is no frozen
// member comes after all of them. Every member computes the same order from the same roster.
func finalizerRank(members []vrclient.FrozenMember, id uint64) int {
	ids := make([]uint64, 0, len(members))
	for _, m := range members {
		ids = append(ids, m.Id)
	}
	slices.Sort(ids)
	if i, ok := slices.BinarySearch(ids, id); ok {
		return i
	}
	return len(ids)
}

// finalizerDelay is how long after the result became ready the member of this rank waits: rank steps, at most finalizerMaxRank steps.
func finalizerDelay(rank int, step time.Duration) time.Duration {
	return time.Duration(min(rank, finalizerMaxRank)) * step
}

// finalizerReadiness is when the result became ready, in chain time: the timestamp of the block that accepted its last possession proof
// (Known false: not found in the log window, so it has been ready for longer than any turn), and the head's timestamp.
type finalizerReadiness struct {
	Known   bool
	ReadyAt uint64 // unix seconds
	Now     uint64 // unix seconds
}

// finalizerTurn is one member's decision.
type finalizerTurn struct {
	Rank  int
	Delay time.Duration
	Due   bool
	From  uint64 // unix seconds from which this rank finalizes (Known readiness only)
}

// planFinalizerTurn decides whether the member of this rank finalizes now. Rank 0 always does; a later rank once its delay has passed in chain
// time, or at once when the readiness is unknown (older than the log window). A zero step lets every member finalize at once (the pre-#1323
// behavior).
func planFinalizerTurn(rank int, step time.Duration, ready finalizerReadiness) finalizerTurn {
	t := finalizerTurn{Rank: rank, Delay: finalizerDelay(rank, step)}
	if t.Delay <= 0 || !ready.Known {
		t.Due = true
		return t
	}
	t.From = ready.ReadyAt + uint64((t.Delay+time.Second-1)/time.Second)
	t.Due = ready.Now >= t.From
	return t
}

// finalizerOrder is what --participate adds to a relayer run: the sender's member id and the step between ranks.
type finalizerOrder struct {
	ID    uint64
	Step  time.Duration
	Clock finalizerClock
}

// finalizerClock reads a result's readiness from the chain.
type finalizerClock interface {
	Readiness(ctx context.Context, rid [32]byte, members int) (finalizerReadiness, error)
}

// awaitFinalizerTurn reports whether this member finalizes now; it writes one stable line when it waits (the container's loop polls every 5 s
// and prints a repeated line once).
func awaitFinalizerTurn(ctx context.Context, w io.Writer, o *finalizerOrder, rid [32]byte, members []vrclient.FrozenMember) (bool, error) {
	if o == nil || o.Step <= 0 {
		return true, nil
	}
	rank := finalizerRank(members, o.ID)
	if rank == 0 {
		return true, nil
	}
	ready, err := o.Clock.Readiness(ctx, rid, len(members))
	if err != nil {
		// liveness first: without the order this member acts as before #1323 (the race costs gas, never correctness)
		fmt.Fprintf(w, "finalizer order unavailable (%v): finalizing now\n", err)
		return true, nil
	}
	t := planFinalizerTurn(rank, o.Step, ready)
	if !t.Due {
		fmt.Fprintf(w, "result %x is ready: identity %d is finalizer rank %d and finalizes from chain time %s if no lower rank has by then\n",
			rid, o.ID, rank, time.Unix(int64(t.From), 0).UTC().Format(time.RFC3339))
		return false, nil
	}
	if ready.Known {
		fmt.Fprintf(w, "result %x: no lower finalizer rank finished within %s; identity %d (rank %d) finalizes\n", rid, t.Delay, o.ID, rank)
	}
	return true, nil
}

// Readiness reads the PoPAccepted logs of the result in the last finalizerLogWindow blocks: the block of the last one is the ready block.
func (r posPublishReader) Readiness(ctx context.Context, rid [32]byte, members int) (finalizerReadiness, error) {
	var out finalizerReadiness
	rpc := r.ch.vr.RPC
	var head hexutil.Uint64
	if err := rpc.CallContext(ctx, &head, "eth_blockNumber"); err != nil {
		return out, err
	}
	stamp := func(n uint64) (uint64, error) {
		var b struct {
			Timestamp hexutil.Uint64 `json:"timestamp"`
		}
		if err := rpc.CallContext(ctx, &b, "eth_getBlockByNumber", hexutil.EncodeUint64(n), false); err != nil {
			return 0, err
		}
		return uint64(b.Timestamp), nil
	}
	now, err := stamp(uint64(head))
	if err != nil {
		return out, err
	}
	out.Now = now
	from := uint64(0)
	if uint64(head)+1 > finalizerLogWindow {
		from = uint64(head) + 1 - finalizerLogWindow
	}
	var logs []popLog
	q := map[string]any{"address": r.election, "fromBlock": hexutil.EncodeUint64(from), "toBlock": hexutil.EncodeUint64(uint64(head)),
		"topics": []any{popAcceptedTopic, common.Hash(rid)}}
	if err := rpc.CallContext(ctx, &logs, "eth_getLogs", q); err != nil {
		return out, err
	}
	ready, seen := readyBlock(logs, r.election, rid)
	if seen < members {
		return out, nil // some proofs were accepted before the window: ready for longer than any turn
	}
	if out.ReadyAt, err = stamp(ready); err != nil {
		return out, err
	}
	out.Known = true
	return out, nil
}

// popLog is one eth_getLogs answer entry, the fields the order reads.
type popLog struct {
	Address     common.Address `json:"address"`
	Topics      []common.Hash  `json:"topics"`
	BlockNumber hexutil.Uint64 `json:"blockNumber"`
	Removed     bool           `json:"removed"`
}

// readyBlock is the block of the last PoPAccepted log of the result, and how many distinct members' logs there are.
func readyBlock(logs []popLog, election common.Address, rid [32]byte) (block uint64, members int) {
	ids := map[common.Hash]bool{}
	for _, l := range logs {
		if l.Removed || l.Address != election || len(l.Topics) != 3 || l.Topics[0] != popAcceptedTopic || l.Topics[1] != common.Hash(rid) {
			continue
		}
		ids[l.Topics[2]] = true
		block = max(block, uint64(l.BlockNumber))
	}
	return block, len(ids)
}
