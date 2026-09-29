// Package mintproof implements bounded, offline-verifiable EVM mint reasons.
package mintproof

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/unicitynetwork/bft-go-base/types"
)

var ErrInvalid = errors.New("mint proof invalid")
var ErrUnavailable = errors.New("mint proof material unavailable")
var ErrTooLarge = errors.New("mint proof exceeds configured limits")

type Context struct {
	Network   types.NetworkID
	Partition types.PartitionID
	Shard     []byte
	ShardConf [32]byte
}

type Evidence struct {
	Absence       bool
	TxIndex       uint64
	TxEnvelope    []byte
	TxProof       [][]byte
	Receipt       []byte
	ReceiptProof  [][]byte
	LogIndex      uint64
	AllReceipts   [][]byte
}

type MintReasonBundleV1 struct {
	Context Context
	SubjectUC []byte
	HeaderRLP []byte
	Evidence Evidence
}

type Limits struct { MaxBytes, MaxNodes, MaxWork int }
func DefaultLimits() Limits { return Limits{MaxBytes: 8 << 20, MaxNodes: 4096, MaxWork: 1 << 20} }
func (l Limits) valid() bool { return l.MaxBytes > 0 && l.MaxNodes > 0 && l.MaxWork > 0 }

var canonicalEnc cbor.EncMode
var strictDec cbor.DecMode
func init() {
	canonicalEnc, _ = cbor.CanonicalEncOptions().EncMode()
	strictDec, _ = (cbor.DecOptions{MaxNestedLevels: 8, MaxArrayElements: 1 << 20, MaxMapPairs: 0, ExtraReturnErrors: cbor.ExtraDecErrorUnknownField}).DecMode()
}

func (b MintReasonBundleV1) value() ([]any, error) {
	ctx := []any{uint64(b.Context.Network), uint64(b.Context.Partition), b.Context.Shard, b.Context.ShardConf[:]}
	var ev []any
	if b.Evidence.Absence {
		ev = []any{uint64(1), b.Evidence.AllReceipts}
	} else {
		ev = []any{uint64(0), b.Evidence.TxIndex, b.Evidence.TxEnvelope, b.Evidence.TxProof, b.Evidence.Receipt, b.Evidence.ReceiptProof, b.Evidence.LogIndex}
	}
	return []any{uint64(1), ctx, b.SubjectUC, b.HeaderRLP, ev}, nil
}

func (b MintReasonBundleV1) MarshalCBOR() ([]byte, error) {
	if !b.valid() { return nil, ErrInvalid }
	v, _ := b.value()
	raw, err := canonicalEnc.Marshal(v)
	if err != nil { return nil, err }
	if len(raw) > DefaultLimits().MaxBytes { return nil, ErrTooLarge }
	return raw, nil
}

func (b MintReasonBundleV1) valid() bool {
	if len(b.Context.Shard) == 0 || len(b.Context.Shard) > 513 || b.Context.ShardConf == ([32]byte{}) || len(b.SubjectUC) == 0 || len(b.HeaderRLP) == 0 { return false }
	if b.Evidence.Absence { return b.Evidence.TxEnvelope == nil && b.Evidence.Receipt == nil && len(b.Evidence.AllReceipts) <= DefaultLimits().MaxNodes }
	return len(b.Evidence.TxEnvelope) != 0 && len(b.Evidence.Receipt) != 0 && len(b.Evidence.AllReceipts) == 0 && len(b.Evidence.TxProof) <= DefaultLimits().MaxNodes && len(b.Evidence.ReceiptProof) <= DefaultLimits().MaxNodes
}

func DecodeBundle(raw []byte, limits Limits) (MintReasonBundleV1, error) {
	var b MintReasonBundleV1
	if !limits.valid() || len(raw) > limits.MaxBytes { return b, ErrTooLarge }
	var root any
	if err := strictDec.Unmarshal(raw, &root); err != nil { return b, fmt.Errorf("%w: CBOR: %v", ErrInvalid, err) }
	r, ok := root.([]any); if !ok || len(r) != 5 || asUint(r[0]) != 1 { return b, ErrInvalid }
	c, ok := r[1].([]any); if !ok || len(c) != 4 { return b, ErrInvalid }
	n, ok1 := asUintOK(c[0]); p, ok2 := asUintOK(c[1]); shard, ok3 := c[2].([]byte); conf, ok4 := c[3].([]byte)
	if !ok1 || !ok2 || !ok3 || !ok4 || len(conf) != 32 { return b, ErrInvalid }
	b.Context.Network, b.Context.Partition = types.NetworkID(n), types.PartitionID(p)
	b.Context.Shard = bytes.Clone(shard)
	copy(b.Context.ShardConf[:], conf)
	var ok bool
	b.SubjectUC, ok = r[2].([]byte); if !ok { return MintReasonBundleV1{}, ErrInvalid }
	b.HeaderRLP, ok = r[3].([]byte); if !ok { return MintReasonBundleV1{}, ErrInvalid }
	ev, ok := r[4].([]any); if !ok || len(ev) < 2 { return MintReasonBundleV1{}, ErrInvalid }
	kind, ok := asUintOK(ev[0]); if !ok { return MintReasonBundleV1{}, ErrInvalid }
	if kind == 0 {
		if len(ev) != 7 { return MintReasonBundleV1{}, ErrInvalid }
		b.Evidence.TxIndex, ok = asUintOK(ev[1]); if !ok { return MintReasonBundleV1{}, ErrInvalid }
		b.Evidence.TxEnvelope, ok = ev[2].([]byte); if !ok { return MintReasonBundleV1{}, ErrInvalid }
		b.Evidence.TxProof, ok = bytes2d(ev[3]); if !ok { return MintReasonBundleV1{}, ErrInvalid }
		b.Evidence.Receipt, ok = ev[4].([]byte); if !ok { return MintReasonBundleV1{}, ErrInvalid }
		b.Evidence.ReceiptProof, ok = bytes2d(ev[5]); if !ok { return MintReasonBundleV1{}, ErrInvalid }
		b.Evidence.LogIndex, ok = asUintOK(ev[6]); if !ok { return MintReasonBundleV1{}, ErrInvalid }
	} else if kind == 1 {
		if len(ev) != 2 { return MintReasonBundleV1{}, ErrInvalid }
		b.Evidence.Absence = true
		b.Evidence.AllReceipts, ok = bytes2d(ev[1]); if !ok { return MintReasonBundleV1{}, ErrInvalid }
	} else { return MintReasonBundleV1{}, ErrInvalid }
	if !b.valid() || countNodes(b) > limits.MaxNodes { return MintReasonBundleV1{}, ErrTooLarge }
	canonical, err := b.MarshalCBOR()
	if err != nil || !bytes.Equal(canonical, raw) { return MintReasonBundleV1{}, ErrInvalid }
	return b, nil
}

func asUint(v any) uint64 { n, _ := asUintOK(v); return n }
func asUintOK(v any) (uint64, bool) { n, ok := v.(uint64); return n, ok }
func bytes2d(v any) ([][]byte, bool) { a, ok := v.([]any); if !ok { return nil, false }; out := make([][]byte, len(a)); for i, x := range a { out[i], ok = x.([]byte); if !ok { return nil, false } }; return out, true }
func countNodes(b MintReasonBundleV1) int { return len(b.Evidence.TxProof)+len(b.Evidence.ReceiptProof)+len(b.Evidence.AllReceipts) }
