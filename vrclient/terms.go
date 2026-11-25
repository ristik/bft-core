package vrclient

import (
	"context"
	"fmt"
	"math/big"

	ethcommon "github.com/ethereum/go-ethereum/common"
)

// CustodyTermsABI is custody's report-anchor surface (#1297/#1298): a lot cannot mature while a closed term of it has no report anchors, and
// anyone may capture them with anchorTerm, opening the term's applied Closure with its H RecordID and terminal root.
var CustodyTermsABI = mustABI(`[
 {"type":"function","name":"anchorTerm","stateMutability":"nonpayable","inputs":[{"name":"assignmentID","type":"bytes32"},{"name":"hRecordID","type":"bytes32"},{"name":"terminalRoot","type":"bytes32"}],"outputs":[]},
 {"type":"function","name":"lotUnanchoredTerms","stateMutability":"view","inputs":[{"name":"lotID","type":"uint256"}],"outputs":[{"name":"","type":"uint32"}]},
 {"type":"function","name":"termAnchors","stateMutability":"view","inputs":[{"name":"assignmentID","type":"bytes32"}],"outputs":[{"name":"terminalRoot","type":"bytes32"},{"name":"hRecordID","type":"bytes32"},{"name":"p0","type":"uint64"},{"name":"t0","type":"uint64"},{"name":"anchored","type":"bool"}]},
 {"type":"function","name":"assignments","stateMutability":"view","inputs":[{"name":"assignmentID","type":"bytes32"}],"outputs":[{"name":"state","type":"uint8"},{"name":"lineage","type":"bytes32"},{"name":"rootEpoch","type":"uint64"},{"name":"evmEpoch","type":"uint64"},{"name":"offset","type":"uint64"},{"name":"firstRound","type":"uint64"},{"name":"offsetSet","type":"bool"},{"name":"hKnown","type":"bool"},{"name":"hRound","type":"uint64"},{"name":"closed","type":"bool"},{"name":"pClose","type":"uint64"},{"name":"tClose","type":"uint64"},{"name":"closureKey","type":"bytes32"},{"name":"exposureDigest","type":"bytes32"},{"name":"keyDigest","type":"bytes32"},{"name":"policyID","type":"uint32"}]},
 {"type":"function","name":"roots","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"address"}]},
 {"type":"function","name":"assignmentExposures","stateMutability":"view","inputs":[{"name":"assignmentID","type":"bytes32"}],"outputs":[{"name":"","type":"bytes32[]"}]},
 {"type":"function","name":"exposureLots","stateMutability":"view","inputs":[{"name":"exposureID","type":"bytes32"}],"outputs":[{"name":"","type":"uint256[]"}]},
 {"type":"function","name":"assignmentSeatCount","stateMutability":"view","inputs":[{"name":"assignmentID","type":"bytes32"}],"outputs":[{"name":"","type":"uint256"}]},
 {"type":"function","name":"assignmentSeat","stateMutability":"view","inputs":[{"name":"assignmentID","type":"bytes32"},{"name":"ordinal","type":"uint256"}],"outputs":[{"name":"","type":"tuple","components":[{"name":"binding","type":"tuple","components":[{"name":"id","type":"uint64"},{"name":"generation","type":"uint64"},{"name":"rootNode","type":"bytes32"},{"name":"rootKeyHash","type":"bytes32"},{"name":"evmNode","type":"bytes32"},{"name":"evmKeyHash","type":"bytes32"},{"name":"payee","type":"address"}]},{"name":"weight","type":"uint64"},{"name":"rawWeight","type":"uint64"},{"name":"bindingHash","type":"bytes32"},{"name":"exposureID","type":"bytes32"},{"name":"memberDigest","type":"bytes32"},{"name":"lotID","type":"uint256"}]}]}]`)

// SealRecordsABI is the SealRegistry's root-record views.
var SealRecordsABI = mustABI(`[
 {"type":"function","name":"recordCount","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"uint64"}]},
 {"type":"function","name":"recordAt","stateMutability":"view","inputs":[{"name":"index","type":"uint64"}],"outputs":[{"name":"r","type":"tuple","components":[{"name":"index","type":"uint64"},{"name":"recordID","type":"bytes32"},{"name":"predecessor","type":"bytes32"},{"name":"kind","type":"uint8"},{"name":"progress","type":"uint64"},{"name":"ucTime","type":"uint64"},{"name":"data","type":"bytes"}]}]}]`)

// RecordKindClosure is RecordKind.Closure; its data is abi.encode(assignmentID, hRound, hRecordID, terminalRoot, exposureDigest, keyHistoryDigest).
const RecordKindClosure = 4

// RootRecord is SealRegistry.recordAt's tuple.
type RootRecord struct {
	Index       uint64
	RecordID    [32]byte
	Predecessor [32]byte
	Kind        uint8
	Progress    uint64
	UcTime      uint64
	Data        []byte
}

// PendingTerm is a closed term whose report anchors are not captured: the words anchorTerm takes, from its Closure record.
type PendingTerm struct {
	AssignmentID, HRecordID, TerminalRoot [32]byte
}

// PendingTerms lists the closed, unanchored terms the given lots wait on: only terms whose assignment references one of the lots (an exposure's
// lots, or a compact seat's lot). supported is false on contracts that predate anchoring (no lotUnanchoredTerms view): there is nothing to anchor.
// It scans the Closure records of custody's root-record source; a term custody has not closed yet, has anchored, or that no lot of the caller
// backs is left out. The caller previews each anchorTerm (one may not be anchorable yet, or be anchored concurrently).
func (c *Client) PendingTerms(ctx context.Context, custody ethcommon.Address, lots []*big.Int) (terms []PendingTerm, supported bool, err error) {
	waiting := false
	for _, lot := range lots {
		var n uint32
		if err := c.call(ctx, custody, CustodyTermsABI, "lotUnanchoredTerms", &n, lot); err != nil {
			return nil, false, nil
		}
		waiting = waiting || n != 0
	}
	if !waiting {
		return nil, true, nil
	}
	var roots ethcommon.Address
	if err := c.call(ctx, custody, CustodyTermsABI, "roots", &roots); err != nil {
		return nil, true, err
	}
	var count uint64
	if err := c.call(ctx, roots, SealRecordsABI, "recordCount", &count); err != nil {
		return nil, true, err
	}
	seen := map[[32]byte]bool{}
	for i := uint64(0); i < count; i++ {
		var r RootRecord
		if err := c.call(ctx, roots, SealRecordsABI, "recordAt", &r, i); err != nil {
			return nil, true, err
		}
		if r.Kind != RecordKindClosure {
			continue
		}
		if len(r.Data) != 6*32 {
			return nil, true, fmt.Errorf("%w: record %d is a Closure whose data is %d bytes", ErrVR, i, len(r.Data))
		}
		var t PendingTerm
		copy(t.AssignmentID[:], r.Data[0:32])
		copy(t.HRecordID[:], r.Data[64:96])
		copy(t.TerminalRoot[:], r.Data[96:128])
		if seen[t.AssignmentID] {
			continue
		}
		seen[t.AssignmentID] = true
		var anchor struct {
			TerminalRoot, HRecordID [32]byte
			P0, T0                  uint64
			Anchored                bool
		}
		if err := c.CallPosMulti(ctx, custody, CustodyTermsABI, "termAnchors", &anchor, t.AssignmentID); err != nil {
			return nil, true, err
		}
		if anchor.Anchored {
			continue
		}
		var a struct {
			State                                   uint8
			Lineage                                 [32]byte
			RootEpoch, EvmEpoch, Offset, FirstRound uint64
			OffsetSet, HKnown                       bool
			HRound                                  uint64
			Closed                                  bool
			PClose, TClose                          uint64
			ClosureKey, ExposureDigest, KeyDigest   [32]byte
			PolicyID                                uint32
		}
		if err := c.CallPosMulti(ctx, custody, CustodyTermsABI, "assignments", &a, t.AssignmentID); err != nil {
			return nil, true, err
		}
		if !a.Closed {
			continue
		}
		backs, err := c.termBacksLots(ctx, custody, t.AssignmentID, lots)
		if err != nil {
			return nil, true, err
		}
		if backs {
			terms = append(terms, t)
		}
	}
	return terms, true, nil
}

// termBacksLots reports whether the assignment references one of lots: a compact seat's lot or a legacy exposure's lots.
func (c *Client) termBacksLots(ctx context.Context, custody ethcommon.Address, assignmentID [32]byte, lots []*big.Int) (bool, error) {
	mine := map[string]bool{}
	for _, l := range lots {
		mine[l.String()] = true
	}
	var seats *big.Int
	if err := c.call(ctx, custody, CustodyTermsABI, "assignmentSeatCount", &seats, assignmentID); err != nil {
		return false, err
	}
	for i := int64(0); i < seats.Int64(); i++ {
		var seat struct {
			Binding struct {
				Id, Generation                             uint64
				RootNode, RootKeyHash, EvmNode, EvmKeyHash [32]byte
				Payee                                      ethcommon.Address
			}
			Weight, RawWeight                     uint64
			BindingHash, ExposureID, MemberDigest [32]byte
			LotID                                 *big.Int
		}
		if err := c.call(ctx, custody, CustodyTermsABI, "assignmentSeat", &seat, assignmentID, big.NewInt(i)); err != nil {
			return false, err
		}
		if seat.LotID != nil && mine[seat.LotID.String()] {
			return true, nil
		}
	}
	var exposures [][32]byte
	if err := c.call(ctx, custody, CustodyTermsABI, "assignmentExposures", &exposures, assignmentID); err != nil {
		return false, err
	}
	for _, e := range exposures {
		var ids []*big.Int
		if err := c.call(ctx, custody, CustodyTermsABI, "exposureLots", &ids, e); err != nil {
			return false, err
		}
		for _, id := range ids {
			if mine[id.String()] {
				return true, nil
			}
		}
	}
	return false, nil
}

// TermAnchored reports whether custody has captured the term's report anchors (termAnchors.anchored).
func (c *Client) TermAnchored(ctx context.Context, custody ethcommon.Address, assignmentID [32]byte) (bool, error) {
	var anchor struct {
		TerminalRoot, HRecordID [32]byte
		P0, T0                  uint64
		Anchored                bool
	}
	if err := c.CallPosMulti(ctx, custody, CustodyTermsABI, "termAnchors", &anchor, assignmentID); err != nil {
		return false, err
	}
	return anchor.Anchored, nil
}
