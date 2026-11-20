package vrclient

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/unicitynetwork/bft-core/vrrules"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// BatchRPC is an RPC connection that can send several calls in one round trip (*rpc.Client does).
type BatchRPC interface {
	BatchCallContext(ctx context.Context, b []rpc.BatchElem) error
}

// ScheduleSource is a vrrules.Source over VR's activation schedule. Every read is made at ONE block, named by its hash (never `latest`
// per call), and the read verifies that block's VR deployment: the registry address is the genesis constant and, when RegistryCode is
// set, its runtime code at that block hashes to the pinned code hash. The endpoint is the operator's own execution client.
type ScheduleSource struct {
	Client *Client
	// RegistryCode is the pinned runtime code hash of VR's core (the b1 profile's VR measurement); nil leaves the code unchecked.
	RegistryCode *[32]byte
}

type pinnedCall struct {
	method string
	args   []any
	out    any
}

// Read implements vrrules.Source: the head block, the deployment check, then two batched rounds (config, counts and pending ids; then
// every entry and every pending change) all at that block hash.
func (s ScheduleSource) Read(ctx context.Context) (vrrules.Evidence, error) {
	var ev vrrules.Evidence
	if s.Client == nil || s.Client.Registry != DefaultRegistry {
		return ev, fmt.Errorf("%w: the activation schedule is read from VR at %s only", ErrVR, DefaultRegistry.Hex())
	}
	var head struct {
		Hash   common.Hash    `json:"hash"`
		Number hexutil.Uint64 `json:"number"`
	}
	if err := s.Client.RPC.CallContext(ctx, &head, "eth_getBlockByNumber", "latest", false); err != nil {
		return ev, err
	}
	if head.Hash == (common.Hash{}) {
		return ev, fmt.Errorf("%w: the head block has no hash", ErrVR)
	}
	p := *s.Client
	p.BlockHash = head.Hash.Hex()
	ev.BlockHash, ev.BlockNumber = head.Hash, uint64(head.Number)

	if s.RegistryCode != nil {
		var code hexutil.Bytes
		if err := p.RPC.CallContext(ctx, &code, "eth_getCode", p.Registry, map[string]any{"blockHash": p.BlockHash}); err != nil {
			return ev, err
		}
		if len(code) == 0 || crypto.Keccak256Hash(code) != common.Hash(*s.RegistryCode) {
			return ev, fmt.Errorf("%w: the code at %s in block %s is not the pinned VR generation", ErrVR, p.Registry.Hex(), p.BlockHash)
		}
	}

	var (
		cfg     ConfigView
		count   uint32
		pending []uint64
	)
	if err := p.callBatch(ctx, []pinnedCall{{"config", nil, &cfg}, {"activationCount", nil, &count}, {"pendingChanges", nil, &pending}}); err != nil {
		return ev, err
	}
	if count > vrrules.MaxActivations || len(pending) > vrrules.MaxPending {
		return ev, fmt.Errorf("%w: VR reports %d activations and %d pending changes, past its bounds", ErrVR, count, len(pending))
	}
	ev.CoveredEpoch = cfg.KnownRootEpoch

	acts := make([]Activation, count)
	changes := make([]ChangeView, len(pending))
	calls := make([]pinnedCall, 0, int(count)+len(pending))
	for i := range acts {
		calls = append(calls, pinnedCall{"activationAt", []any{uint32(i)}, &acts[i]})
	}
	for i, id := range pending {
		calls = append(calls, pinnedCall{"change", []any{id}, &changes[i]})
	}
	if err := p.callBatch(ctx, calls); err != nil {
		return ev, err
	}
	for _, a := range acts {
		ev.Schedule = append(ev.Schedule, vrschema.Activation{RuleID: a.RuleId, ReleaseDigest: a.ReleaseDigest, RootEpoch: a.RootEpoch,
			NotBeforeUcTime: a.NotBeforeUcTime, State: a.State, ChangeID: a.ChangeId})
	}
	for i, ch := range changes {
		if ch.Kind != KindScheduleActivation {
			continue
		}
		sc, err := vrschema.DecodeSchedule(ch.Payload)
		if err != nil {
			continue // a pending change is a warning only; one that does not decode warns nothing
		}
		ev.Pending = append(ev.Pending, vrrules.PendingEntry{State: ChangeState(ch.State), Activation: vrschema.Activation{
			RuleID: sc.RuleID, ReleaseDigest: sc.ReleaseDigest, RootEpoch: sc.RootEpoch, NotBeforeUcTime: sc.NotBeforeUcTime, ChangeID: pending[i]}})
	}
	return ev, nil
}

// callBatch makes the VR view calls in one round trip when the connection batches, one by one otherwise; every call is at c's block.
func (c *Client) callBatch(ctx context.Context, calls []pinnedCall) error {
	if len(calls) == 0 {
		return nil
	}
	datas := make([][]byte, len(calls))
	for i, k := range calls {
		d, err := VRABI.Pack(k.method, k.args...)
		if err != nil {
			return fmt.Errorf("%w: packing %s: %v", ErrVR, k.method, err)
		}
		datas[i] = d
	}
	rets := make([]hexutil.Bytes, len(calls))
	if b, ok := c.RPC.(BatchRPC); ok {
		elems := make([]rpc.BatchElem, len(calls))
		for i := range calls {
			elems[i] = rpc.BatchElem{Method: "eth_call", Args: []any{map[string]any{"to": c.Registry, "data": hexutil.Bytes(datas[i])}, c.blockArg()}, Result: &rets[i]}
		}
		if err := b.BatchCallContext(ctx, elems); err != nil {
			return err
		}
		for i, e := range elems {
			if e.Error != nil {
				return fmt.Errorf("%s: %w", calls[i].method, WrapRevert(e.Error))
			}
		}
	} else {
		for i := range calls {
			r, err := c.CallRaw(ctx, c.Registry, datas[i])
			if err != nil {
				return fmt.Errorf("%s: %w", calls[i].method, err)
			}
			rets[i] = r
		}
	}
	for i, k := range calls {
		if len(rets[i]) == 0 {
			return fmt.Errorf("%w: %s returned nothing (no contract there?)", ErrVR, k.method)
		}
		vals, err := VRABI.Methods[k.method].Outputs.Unpack(rets[i])
		if err != nil {
			return fmt.Errorf("%w: decoding %s: %v", ErrVR, k.method, err)
		}
		if err := copyOut(k.method, k.out, vals); err != nil {
			return err
		}
	}
	return nil
}
