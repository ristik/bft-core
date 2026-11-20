package vrclient

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/unicitynetwork/bft-core/vrschema"
)

// RPC is the part of an rpc.Client this package uses.
type RPC interface {
	CallContext(ctx context.Context, result any, method string, args ...any) error
}

// DefaultRegistry is VR's genesis address (0xff..03); DefaultSealRegistry the SealRegistry's (0xff..02), VR's clock and record source.
var (
	DefaultRegistry     = ethcommon.Address(vrschema.ValidatorRegistry)
	DefaultSealRegistry = ethcommon.Address(vrschema.SealRegistry)
)

var sealABI = mustABI(`[
 {"type":"function","name":"progress","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"uint64"}]},
 {"type":"function","name":"ucTime","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"uint64"}]},
 {"type":"function","name":"recordCount","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"uint64"}]}]`)

func mustABI(s string) abi.ABI {
	a, err := abi.JSON(strings.NewReader(s))
	if err != nil {
		panic(err)
	}
	return a
}

// Client reads VR, its active module and the SealRegistry clock over eth_call. Pin fixes the block so that one status is one state.
type Client struct {
	RPC      RPC
	Registry ethcommon.Address
	Seal     ethcommon.Address
	// Block is the block tag every read is made at ("latest" when empty).
	Block string
}

// New returns a client of VR at registry (DefaultRegistry when zero).
func New(c RPC, registry ethcommon.Address) *Client {
	if registry == (ethcommon.Address{}) {
		registry = DefaultRegistry
	}
	return &Client{RPC: c, Registry: registry, Seal: DefaultSealRegistry}
}

// Pin returns a copy that reads at the current head, and the head's number.
func (c *Client) Pin(ctx context.Context) (*Client, uint64, error) {
	var head hexutil.Uint64
	if err := c.RPC.CallContext(ctx, &head, "eth_blockNumber"); err != nil {
		return nil, 0, err
	}
	p := *c
	p.Block = hexutil.EncodeUint64(uint64(head))
	return &p, uint64(head), nil
}

// blockParam is the eth_call block argument: a 32-byte hash (0x + 64 hex) is sent as the EIP-1898 {"blockHash": ...} object, so the read
// is of that exact block and never of whatever block carries its number; anything else is a number or tag.
func (c *Client) blockParam() any {
	if len(c.Block) == 66 {
		return map[string]string{"blockHash": c.Block}
	}
	return c.block()
}

func (c *Client) block() string {
	if c.Block == "" {
		return "latest"
	}
	return c.Block
}

// CallRaw is one eth_call.
func (c *Client) CallRaw(ctx context.Context, to ethcommon.Address, data []byte) ([]byte, error) {
	var out hexutil.Bytes
	arg := map[string]any{"to": to, "data": hexutil.Bytes(data)}
	if err := c.RPC.CallContext(ctx, &out, "eth_call", arg, c.blockParam()); err != nil {
		return nil, WrapRevert(err)
	}
	return out, nil
}

// CallRawFrom simulates tx from an account (eth_call with a sender), for the return value of a write method.
func (c *Client) CallRawFrom(ctx context.Context, from ethcommon.Address, tx Tx) ([]byte, error) {
	var out hexutil.Bytes
	arg := map[string]any{"from": from, "to": tx.To, "data": hexutil.Bytes(tx.Data)}
	if err := c.RPC.CallContext(ctx, &out, "eth_call", arg, c.blockParam()); err != nil {
		return nil, WrapRevert(err)
	}
	return out, nil
}

func (c *Client) call(ctx context.Context, to ethcommon.Address, a abi.ABI, method string, out any, args ...any) error {
	data, err := a.Pack(method, args...)
	if err != nil {
		return fmt.Errorf("%w: packing %s: %v", ErrVR, method, err)
	}
	ret, err := c.CallRaw(ctx, to, data)
	if err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	if len(ret) == 0 {
		return fmt.Errorf("%w: %s at %s returned nothing (no contract there?)", ErrVR, method, to.Hex())
	}
	vals, err := a.Methods[method].Outputs.Unpack(ret)
	if err != nil {
		return fmt.Errorf("%w: decoding %s: %v", ErrVR, method, err)
	}
	return copyOut(method, out, vals)
}

// copyOut copies one decoded return value into out: directly when assignable, otherwise field by field by name (abi.ConvertType, which
// also converts slices of tuples). Arguments.Copy is not used: it takes a struct for a wrapper of several returns, not for one tuple.
func copyOut(method string, out any, vals []any) (err error) {
	dst := reflect.ValueOf(out)
	if len(vals) != 1 || dst.Kind() != reflect.Pointer {
		return fmt.Errorf("%w: copying %s: %d values into %T", ErrVR, method, len(vals), out)
	}
	src := reflect.ValueOf(vals[0])
	if src.Type().AssignableTo(dst.Elem().Type()) {
		dst.Elem().Set(src)
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: copying %s: %v", ErrVR, method, r)
		}
	}()
	abi.ConvertType(vals[0], out)
	return nil
}

func (c *Client) vr(ctx context.Context, method string, out any, args ...any) error {
	return c.call(ctx, c.Registry, VRABI, method, out, args...)
}

// Identity is VR.identity(id).
func (c *Client) Identity(ctx context.Context, id uint64) (IdentityView, error) {
	var v IdentityView
	return v, c.vr(ctx, "identity", &v, id)
}

// OwnerOf is VR.ownerOf(id).
func (c *Client) OwnerOf(ctx context.Context, id uint64) (ethcommon.Address, error) {
	var v ethcommon.Address
	return v, c.vr(ctx, "ownerOf", &v, id)
}

// RegistrationNonce is VR.registrationNonce(owner).
func (c *Client) RegistrationNonce(ctx context.Context, owner ethcommon.Address) (uint64, error) {
	var v uint64
	return v, c.vr(ctx, "registrationNonce", &v, owner)
}

// Config is VR.config().
func (c *Client) Config(ctx context.Context) (ConfigView, error) {
	var v ConfigView
	return v, c.vr(ctx, "config", &v)
}

// ActiveModule is VR.activeModule().
func (c *Client) ActiveModule(ctx context.Context) (ModuleView, error) {
	var v ModuleView
	return v, c.vr(ctx, "activeModule", &v)
}

// Committee is VR.committee(): the committee in force.
func (c *Client) Committee(ctx context.Context) ([]Member, error) {
	var v []Member
	return v, c.vr(ctx, "committee", &v)
}

// OpenOutput is VR.openOutput() (zero when none is open).
func (c *Client) OpenOutput(ctx context.Context) ([32]byte, error) {
	var v [32]byte
	return v, c.vr(ctx, "openOutput", &v)
}

// PendingPair is VR.pendingPair(): an output whose Ack is applied while its Boundary is awaited.
func (c *Client) PendingPair(ctx context.Context) ([32]byte, error) {
	var v [32]byte
	return v, c.vr(ctx, "pendingPair", &v)
}

// Output is VR.output(resultId).
func (c *Client) Output(ctx context.Context, rid [32]byte) (OutputView, error) {
	var v OutputView
	return v, c.vr(ctx, "output", &v, rid)
}

// PendingChanges is VR.pendingChanges(): the ids of changes that are not Active, Cancelled or Rejected.
func (c *Client) PendingChanges(ctx context.Context) ([]uint64, error) {
	var v []uint64
	return v, c.vr(ctx, "pendingChanges", &v)
}

// Change is VR.change(id).
func (c *Client) Change(ctx context.Context, id uint64) (ChangeView, error) {
	var v ChangeView
	return v, c.vr(ctx, "change", &v, id)
}

// Activations is VR's activation schedule.
func (c *Client) Activations(ctx context.Context) ([]Activation, error) {
	var n uint32
	if err := c.vr(ctx, "activationCount", &n); err != nil {
		return nil, err
	}
	if n > vrschema.MaxActivations { // the schedule is bounded by the schema: an answer beyond it is refused before anything is allocated or read
		return nil, fmt.Errorf("%w: activationCount %d exceeds the schema's %d", ErrVR, n, vrschema.MaxActivations)
	}
	out := make([]Activation, 0, n)
	for i := uint32(0); i < n; i++ {
		var a Activation
		if err := c.vr(ctx, "activationAt", &a, i); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// Clock is the SealRegistry's progress and UC time, the clock of every VR delay and deadline, and its record count next to VR's cursor.
type Clock struct {
	Progress     uint64
	UcTime       uint64
	RecordCount  uint64
	RecordCursor uint64
}

// Clock reads the SealRegistry clock and VR's record cursor.
func (c *Client) Clock(ctx context.Context) (Clock, error) {
	var k Clock
	err := errors.Join(c.call(ctx, c.Seal, sealABI, "progress", &k.Progress), c.call(ctx, c.Seal, sealABI, "ucTime", &k.UcTime),
		c.call(ctx, c.Seal, sealABI, "recordCount", &k.RecordCount), c.vr(ctx, "recordCursor", &k.RecordCursor))
	return k, err
}

// PoaStatus is PoaElection.status(id) on module.
func (c *Client) PoaStatus(ctx context.Context, module ethcommon.Address, id uint64) (state uint8, since uint64, err error) {
	data, err := PoaABI.Pack("status", id)
	if err != nil {
		return 0, 0, err
	}
	ret, err := c.CallRaw(ctx, module, data)
	if err != nil {
		return 0, 0, fmt.Errorf("status: %w", err)
	}
	vals, err := PoaABI.Methods["status"].Outputs.Unpack(ret)
	if err != nil || len(vals) != 2 {
		return 0, 0, fmt.Errorf("%w: the active module's status(id) is not PoaElection's (%v)", ErrVR, err)
	}
	return vals[0].(uint8), vals[1].(uint64), nil
}

// PoaQueue is PoaElection.queue(): the tracked non-members in admission order.
func (c *Client) PoaQueue(ctx context.Context, module ethcommon.Address) ([]uint64, error) {
	var v []uint64
	return v, c.call(ctx, module, PoaABI, "queue", &v)
}

// ModuleTagPoA is PoaElection's moduleTag, keccak256("unicity.vr.poa.v1").
var ModuleTagPoA = vrschema.DomainWord("unicity.vr.poa.v1")

// ModuleAction is a decoded PoA ModuleAction change: the target module, the action and the identity.
type ModuleAction struct {
	Module ethcommon.Address
	Action uint64
	ID     uint64
}

// DecodeModuleAction reads a ModuleAction payload abi.encode(address module, bytes action) whose action is abi.encode(uint64, uint64).
func DecodeModuleAction(payload []byte) (ModuleAction, bool) {
	outer, err := vrschema.DecodeABI([]string{"address", "bytes"}, payload)
	if err != nil {
		return ModuleAction{}, false
	}
	inner, err := vrschema.DecodeABI([]string{"uint64", "uint64"}, outer[1].([]byte))
	if err != nil {
		return ModuleAction{}, false
	}
	return ModuleAction{Module: ethcommon.Address(outer[0].([20]byte)), Action: inner[0].(uint64), ID: inner[1].(uint64)}, true
}

// EncodeModuleAction is the ModuleAction payload for a PoA action (what the Foundation multisig queues as change kind 2).
func EncodeModuleAction(module ethcommon.Address, action, id uint64) ([]byte, error) {
	inner, err := vrschema.EncodeABI([]string{"uint64", "uint64"}, []any{action, id})
	if err != nil {
		return nil, err
	}
	return vrschema.EncodeABI([]string{"address", "bytes"}, []any{[20]byte(module), inner})
}

// IdentitiesOf finds the identities registered by owner from VR's Registered(id indexed, owner indexed, bindingRef) logs, oldest first,
// each once. Every returned log must be VR's Registered event for this owner with a uint64 id; any other answer is refused as malformed
// (it does not establish ownership: callers check VR.ownerOf). A public endpoint may refuse a log query over the whole chain; the caller
// then asks for the id.
func (c *Client) IdentitiesOf(ctx context.Context, owner ethcommon.Address) ([]uint64, error) {
	ev := VRABI.Events["Registered"]
	ownerTopic := ethcommon.BytesToHash(owner.Bytes())
	q := map[string]any{"address": c.Registry, "fromBlock": "0x0", "toBlock": c.block(), "topics": []any{ev.ID, nil, ownerTopic}}
	var logs []struct {
		Address ethcommon.Address `json:"address"`
		Topics  []ethcommon.Hash  `json:"topics"`
		Removed bool              `json:"removed"`
	}
	if err := c.RPC.CallContext(ctx, &logs, "eth_getLogs", q); err != nil {
		return nil, err
	}
	var ids []uint64
	seen := map[uint64]bool{}
	for i, l := range logs {
		if l.Removed {
			continue
		}
		if l.Address != c.Registry || len(l.Topics) != 3 || l.Topics[0] != ev.ID || l.Topics[2] != ownerTopic {
			return nil, fmt.Errorf("%w: eth_getLogs answer %d is not VR's Registered log for %s (address %s, %d topics)", ErrVR, i,
				owner.Hex(), l.Address.Hex(), len(l.Topics))
		}
		idw := new(big.Int).SetBytes(l.Topics[1].Bytes())
		if !idw.IsUint64() || idw.Sign() == 0 {
			return nil, fmt.Errorf("%w: eth_getLogs answer %d has id topic %s", ErrVR, i, l.Topics[1].Hex())
		}
		if id := idw.Uint64(); !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// WrapRevert turns a JSON-RPC error that carries revert data into an error that also names the decoded VR or module error.
func WrapRevert(err error) error {
	var de rpc.DataError
	if !errors.As(err, &de) {
		return err
	}
	s, ok := de.ErrorData().(string)
	if !ok {
		return err
	}
	b, derr := hexutil.Decode(s)
	if derr != nil {
		return err
	}
	if r := DecodeRevert(b); r != nil {
		return fmt.Errorf("%w (%w)", err, r)
	}
	return err
}
