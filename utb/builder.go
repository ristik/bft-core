// Package utb builds the signed Unicity Trust Base entries (types.RootTrustBaseV2, bft-go-base record version 2) from the facts of a validated successor.
//
// There is one builder. The root's handoff installer, the Q3 history, the shard restore and the exporter all derive the entry's unsigned bytes and EntryID
// from SuccessorFacts through BuildUnsigned, so they cannot disagree. The entry is the public trust record; the runtime projection (Projection) is a
// V1 value for existing key/weight consumers only and its Hash() must never be used as lineage.
//
// Three identities stay distinct: the UTB EntryID (types.RootTrustBaseV2.EntryID), the handoff body identity (evmroot/q3format Identity) and the
// epoch-anchor/genesis identity. This package produces only the first.
package utb

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
)

// MaxMembers is the deployment's committee ceiling (the admitted 16-member profile). go-base's decoder bound is larger; a larger committee is never
// admitted through the wire cap. A future profile raises this deliberately.
const MaxMembers = evmassign.MaxValidators

var (
	ErrFacts = errors.New("utb: invalid successor facts")
	ErrChain = errors.New("utb: facts do not extend the predecessor")
)

// Member is one committee member of the successor epoch.
type Member struct {
	NodeID string
	Key    []byte // compressed secp256k1 consensus key
	Weight uint64
}

// SuccessorFacts is everything an entry contains besides the predecessor link and the signatures. It is derived only from locally validated
// handoff execution (during voting) or a fully verified transition (during install and replay). EpochStart is the committed handoff record's actual
// ActivationRound: not the body's earliest activation and not the later acknowledgement round.
type SuccessorFacts struct {
	Network          uint64
	Epoch            uint64
	EpochStart       uint64
	Members          []Member
	Threshold        uint64
	StateHash        []byte
	ChangeRecordHash []byte
}

// FromWeightSet adapts a candidate/body weight set (the V2 body and the Q3 body both carry one) to the facts.
func FromWeightSet(network, epoch, epochStart uint64, ws evmroot.WeightSet, threshold uint64, stateSummary, changeRecordHash []byte) SuccessorFacts {
	ms := make([]Member, len(ws))
	for i, m := range ws {
		ms[i] = Member{NodeID: m.NodeID, Key: bytes.Clone(m.ConsensusKey), Weight: m.Weight}
	}
	return SuccessorFacts{Network: network, Epoch: epoch, EpochStart: epochStart, Members: ms, Threshold: threshold,
		StateHash: bytes.Clone(stateSummary), ChangeRecordHash: bytes.Clone(changeRecordHash)}
}

// FromBodyV2 adapts a V2 handoff body and the committed record's actual activation round.
func FromBodyV2(b evmroot.TrustBaseBodyV2, activationRound uint64) SuccessorFacts {
	return FromWeightSet(b.NetworkID, b.Epoch, activationRound, b.Members, b.RootThreshold, b.StateSummary, b.ChangeRecordHash)
}

// FromProjection adapts a runtime V1 projection (what the root installers, the Q3 history and the shard restore hold for an epoch) to the facts. Every
// path that holds a projection therefore derives the same unsigned entry from the same epoch.
func FromProjection(tb *types.RootTrustBaseV1) SuccessorFacts {
	ms := make([]Member, len(tb.RootNodes))
	for i, n := range tb.RootNodes {
		ms[i] = Member{NodeID: n.NodeID, Key: bytes.Clone(n.SigKey), Weight: n.Stake}
	}
	return SuccessorFacts{Network: uint64(tb.NetworkID), Epoch: tb.Epoch, EpochStart: tb.EpochStart, Members: ms, Threshold: tb.QuorumThreshold,
		StateHash: bytes.Clone(tb.StateHash), ChangeRecordHash: bytes.Clone(tb.ChangeRecordHash)}
}

// BuildUnsigned returns the entry for f extending prev, without signatures: epoch prev+1, a strictly later start, PreviousEntryID =
// prev.EntryID(). It needs no commit QC (that would be circular while a vote is built); the finalized entry is checked against the QC separately.
// With prev == nil it builds a genesis entry (zero predecessor); its authority is a pin on its EntryID.
func BuildUnsigned(prev *types.RootTrustBaseV2, f SuccessorFacts) (*types.RootTrustBaseV2, error) {
	prevID := make([]byte, types.TrustBaseV2IDLen)
	if prev != nil {
		if err := validateShape(prev); err != nil {
			return nil, fmt.Errorf("%w: predecessor: %v", ErrChain, err)
		}
		if f.Network != uint64(prev.NetworkID) {
			return nil, fmt.Errorf("%w: network %d, predecessor %d", ErrChain, f.Network, prev.NetworkID)
		}
		if prev.Epoch == math.MaxUint64 || f.Epoch != prev.Epoch+1 {
			return nil, fmt.Errorf("%w: epoch %d, predecessor %d", ErrChain, f.Epoch, prev.Epoch)
		}
		if f.EpochStart <= prev.EpochStart {
			return nil, fmt.Errorf("%w: epoch start %d, predecessor %d", ErrChain, f.EpochStart, prev.EpochStart)
		}
		id, err := prev.EntryID()
		if err != nil {
			return nil, err
		}
		prevID = id[:]
	}
	if n := len(f.Members); n == 0 || n > MaxMembers {
		return nil, fmt.Errorf("%w: %d members (1..%d)", ErrFacts, n, MaxMembers)
	}
	if f.Network > math.MaxUint32 {
		return nil, fmt.Errorf("%w: network %d", ErrFacts, f.Network)
	}
	ms := append([]Member(nil), f.Members...)
	sort.Slice(ms, func(i, j int) bool { return ms[i].NodeID < ms[j].NodeID }) // raw UTF-8 byte order
	nodes := make([]*types.NodeInfo, len(ms))
	var total uint64
	for i, m := range ms {
		// the node id is the libp2p peer id of the member's network (auth) key, a different key from the consensus key, so only its form is checked
		if _, err := peer.Decode(m.NodeID); err != nil {
			return nil, fmt.Errorf("%w: node id %q: %v", ErrFacts, m.NodeID, err)
		}
		if m.Weight == 0 || m.Weight > types.MaxTrustBaseV2Weight {
			return nil, fmt.Errorf("%w: member %q weight %d", ErrFacts, m.NodeID, m.Weight)
		}
		total += m.Weight // at most 16 * 2^40
		nodes[i] = &types.NodeInfo{NodeID: m.NodeID, SigKey: bytes.Clone(m.Key), Stake: m.Weight}
	}
	if want := total*2/3 + 1; f.Threshold != want {
		return nil, fmt.Errorf("%w: threshold %d, expected %d for total weight %d", ErrFacts, f.Threshold, want, total)
	}
	e := &types.RootTrustBaseV2{Version: types.TrustBaseV2Version, NetworkID: types.NetworkID(f.Network), Epoch: f.Epoch, EpochStart: f.EpochStart,
		RootNodes: nodes, QuorumThreshold: f.Threshold, StateHash: bytes.Clone(f.StateHash), ChangeRecordHash: bytes.Clone(f.ChangeRecordHash), PreviousEntryID: prevID}
	if err := validateShape(e); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFacts, err)
	}
	return e, nil
}

// validateShape is types.RootTrustBaseV2.Validate for an entry that may still lack its signatures: Validate requires a non-genesis entry to carry a
// non-empty signature map, so an unsigned one is checked as a copy with a placeholder. Signatures are verified by VerifySuccessor, never here.
func validateShape(e *types.RootTrustBaseV2) error {
	probe := *e
	if !probe.IsGenesis() && len(probe.Signatures) == 0 {
		probe.Signatures = map[string]hex.Bytes{"-": nil}
	}
	return probe.Validate()
}

// Projection is the runtime V1 view of an entry for existing consumers that need a concrete *types.RootTrustBaseV1 (keys, weights, threshold, epoch
// start). It is not a public trust entry and must not be exported or hashed as one: its PreviousEntryHash is deliberately empty and its Hash()
// says nothing about the UTB lineage.
func Projection(e *types.RootTrustBaseV2) (*types.RootTrustBaseV1, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	nodes := make([]*types.NodeInfo, len(e.RootNodes))
	for i, m := range e.RootNodes {
		nodes[i] = &types.NodeInfo{NodeID: m.NodeID, SigKey: bytes.Clone(m.SigKey), Stake: m.Stake}
	}
	tb, err := quorumweight.NewTrustBase(e.NetworkID, nodes, types.WithEpoch(e.Epoch), types.WithEpochStart(e.EpochStart), types.WithQuorumThreshold(e.QuorumThreshold))
	if err != nil {
		return nil, err
	}
	tb.StateHash, tb.ChangeRecordHash = bytes.Clone(e.StateHash), bytes.Clone(e.ChangeRecordHash)
	return tb, nil
}
