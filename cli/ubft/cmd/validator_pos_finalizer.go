package cmd

// #1323: one designated finalizer per ready P85 result. Every active member's `pos-publish --participate` sees the result ready (every frozen
// member's possession proof is stored) at about the same block, and each used to send finalizeCandidate and VR.publish at once: every
// simulation passed, and all but the first finalizeCandidate reverted in the mined block. The members now take turns: the frozen roster in
// ascending identity order, the lowest first, at once; the member of rank k only after k steps of chain time since the block that made the
// result ready, if nobody has finished by then. The order is read from the chain alone (the frozen roster and the PoPAccepted logs), so it
// needs no coordinator and no relay: any member still finalizes and publishes after its delay, and the delay is bounded.

import (
	"context"
	"errors"
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
	// defaultFinalizerStep is the chain time between two finalizer ranks. It must cover the designated finalizer's whole turn: its node sees
	// the ready block only after the node's lag behind the head, then finalizeCandidate's receipt (seen after that lag again) and VR.publish.
	// The #1323 lane measured 127 s from the ready block to the finalizer's VR.publish block (a member's node about 4 blocks behind, 10 s
	// blocks); with a 30 s step the next ranks' turns came first and two of them sent.
	defaultFinalizerStep = 180 * time.Second
	// finalizerMaxRank bounds the delay: the members from this rank on share the last turn (4 steps, 12 minutes by default).
	finalizerMaxRank = 4
	// finalizerLogWindow is the public gateway's eth_getLogs limit.
	finalizerLogWindow = 10_000
	// Reservations are usually recent. Look for the opening event in progressively larger, disjoint ranges.
	finalizerReservationWindow = 256
)

// popAcceptedTopic is ElectionPolicy's PoPAccepted(bytes32 indexed resultID, uint64 indexed id, bytes32 signatureHash).
var popAcceptedTopic = ethcrypto.Keccak256Hash([]byte("PoPAccepted(bytes32,uint64,bytes32)"))
var electionOpenedTopic = ethcrypto.Keccak256Hash([]byte("ElectionOpened(bytes32,uint64,bytes32,bytes32,bytes32)"))

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

// finalizerReadiness measures from the block that accepted the last proof, or from a later
// block whose state proves all proofs were already present. Now is the finalized head's time.
type finalizerReadiness struct {
	ReadyAt uint64
	Now     uint64
}

// finalizerTurn is one member's decision.
type finalizerTurn struct {
	Rank  int
	Delay time.Duration
	Due   bool
	From  uint64 // unix seconds from which this rank finalizes (Known readiness only)
}

// planFinalizerTurn lets rank zero and zero-step runs act at once. Later ranks wait in chain time.
func planFinalizerTurn(rank int, step time.Duration, ready finalizerReadiness) finalizerTurn {
	t := finalizerTurn{Rank: rank, Delay: finalizerDelay(rank, step)}
	if t.Delay <= 0 {
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
		// The designated finalizer can act without logs. A later rank retries with the next poll.
		fmt.Fprintf(w, "finalizer order unavailable (%v): identity %d waits for a consistent read\n", err, o.ID)
		return false, nil
	}
	t := planFinalizerTurn(rank, o.Step, ready)
	if !t.Due {
		fmt.Fprintf(w, "result %x is ready: identity %d is finalizer rank %d and finalizes from chain time %s if no lower rank has by then\n",
			rid, o.ID, rank, time.Unix(int64(t.From), 0).UTC().Format(time.RFC3339))
		return false, nil
	}
	fmt.Fprintf(w, "result %x: no lower finalizer rank finished within %s; identity %d (rank %d) finalizes\n", rid, t.Delay, o.ID, rank)
	return true, nil
}

type finalizerBlock struct {
	Hash      common.Hash     `json:"hash"`
	Number    *hexutil.Uint64 `json:"number"`
	Timestamp *hexutil.Uint64 `json:"timestamp"`
}

func (r posPublishReader) finalizerHeader(ctx context.Context, tag string) (finalizerBlock, error) {
	var b finalizerBlock
	if err := r.ch.vr.RPC.CallContext(ctx, &b, "eth_getBlockByNumber", tag, false); err != nil {
		return b, err
	}
	if b.Hash == (common.Hash{}) || b.Number == nil || b.Timestamp == nil || (tag != "finalized" && b.Number.String() != tag) {
		return b, fmt.Errorf("missing or mismatched finalizer header at %s", tag)
	}
	return b, nil
}

func (r posPublishReader) finalizerLogs(ctx context.Context, rid [32]byte, topic common.Hash, from, to uint64) ([]popLog, error) {
	var logs []popLog
	q := map[string]any{"address": r.election, "fromBlock": hexutil.EncodeUint64(from), "toBlock": hexutil.EncodeUint64(to),
		"topics": []any{topic, common.Hash(rid)}}
	if err := r.ch.vr.RPC.CallContext(ctx, &logs, "eth_getLogs", q); err != nil {
		return nil, err
	}
	if logs == nil {
		return nil, errors.New("missing finalizer log response")
	}
	for _, log := range logs {
		if log.Removed || log.Address != r.election || len(log.Topics) < 2 ||
			log.Topics[0] != topic || log.Topics[1] != common.Hash(rid) ||
			log.BlockHash == (common.Hash{}) || uint64(log.BlockNumber) < from || uint64(log.BlockNumber) > to {
			return nil, errors.New("finalizer log does not match the requested range and topics")
		}
	}
	return logs, nil
}

func (r posPublishReader) reservationStart(ctx context.Context, rid [32]byte, floor, head uint64) (uint64, error) {
	for end, width := head, uint64(finalizerReservationWindow); ; width *= 2 {
		start := end - min(end-floor, width-1)
		logs, err := r.finalizerLogs(ctx, rid, electionOpenedTopic, start, end)
		if err != nil {
			return 0, err
		}
		if len(logs) == 1 {
			b, err := r.finalizerHeader(ctx, logs[0].BlockNumber.String())
			if err != nil {
				return 0, err
			}
			if b.Hash != logs[0].BlockHash {
				return 0, errors.New("reservation log is from a different block")
			}
			return uint64(logs[0].BlockNumber), nil
		}
		if len(logs) > 1 {
			return 0, errors.New("multiple reservation logs for the finalizer result")
		}
		if start == floor {
			return floor, nil
		}
		end = start - 1
	}
}

// Readiness anchors the publication and chain time to the finalized head. The gateway
// keeps its numeric-range log filter. Validate the last proof's block hash and check the
// publication with requireCanonical at both the head and the readiness block.
func (r posPublishReader) Readiness(ctx context.Context, rid [32]byte, members int) (finalizerReadiness, error) {
	var out finalizerReadiness
	head, err := r.finalizerHeader(ctx, "finalized")
	if err != nil {
		return out, err
	}
	requireReady := func(b finalizerBlock) error {
		c := *r.ch.vr
		c.BlockHash, c.Canonical = b.Hash.Hex(), true
		pub, err := c.Publication(ctx, r.election, rid)
		if err != nil {
			return err
		}
		if pub.Lost || int(pub.PopCount) != members {
			return errors.New("the publication is not ready at the referenced block")
		}
		return nil
	}
	if err := requireReady(head); err != nil {
		return out, err
	}
	height := uint64(*head.Number)
	floor := height - min(height, finalizerLogWindow-1)
	from, err := r.reservationStart(ctx, rid, floor, height)
	if err != nil {
		return out, err
	}
	logs, err := r.finalizerLogs(ctx, rid, popAcceptedTopic, from, height)
	if err != nil {
		return out, err
	}
	last, seen := readyBlock(logs, r.election, rid)
	var ready finalizerBlock
	switch {
	case seen > members:
		return out, errors.New("too many members in the finalizer proof history")
	case seen > 0 && last.BlockNumber == *head.Number:
		ready = head
	case seen > 0:
		// Earlier proofs may fall outside the range. The canonical state at the
		// last observed proof must contain every proof, including any missing logs.
		ready, err = r.finalizerHeader(ctx, last.BlockNumber.String())
	case from == floor && floor > 0:
		// All proofs may predate the capped range. The state just before the
		// range can establish an upper bound on the readiness time.
		ready, err = r.finalizerHeader(ctx, hexutil.EncodeUint64(floor-1))
	default:
		return out, errors.New("incomplete finalizer proof history")
	}
	if err != nil {
		return out, err
	}
	if seen > 0 && ready.Hash != last.BlockHash {
		return out, errors.New("the readiness log is from a different block")
	}
	if ready.Hash != head.Hash {
		if err := requireReady(ready); err != nil {
			return out, err
		}
	}
	out.ReadyAt, out.Now = uint64(*ready.Timestamp), uint64(*head.Timestamp)
	if out.ReadyAt > out.Now {
		return finalizerReadiness{}, errors.New("readiness time is after the finalized head")
	}
	return out, nil
}

// popLog is one eth_getLogs answer entry, the fields the order reads.
type popLog struct {
	Address     common.Address `json:"address"`
	Topics      []common.Hash  `json:"topics"`
	BlockNumber hexutil.Uint64 `json:"blockNumber"`
	BlockHash   common.Hash    `json:"blockHash"`
	Removed     bool           `json:"removed"`
}

// readyBlock is the log of the last proof and the number of distinct members with logs.
func readyBlock(logs []popLog, election common.Address, rid [32]byte) (last popLog, members int) {
	ids := map[common.Hash]bool{}
	for _, l := range logs {
		if l.Removed || l.Address != election || len(l.Topics) != 3 || l.Topics[0] != popAcceptedTopic || l.Topics[1] != common.Hash(rid) {
			continue
		}
		ids[l.Topics[2]] = true
		if l.BlockNumber >= last.BlockNumber {
			last = l
		}
	}
	return last, len(ids)
}
