// Package q4replay is the offline half of the Q4 #51 evidence: a Bundle is the export of one fault run (the manifest, the merged
// message trace with the serialized messages, the per-node committed chains and the progress/stall windows with their frozen
// deadlines), and Check re-derives every verdict from the bundle alone.
//
// The checker is independent of the run that produced the bundle. It never reads a live counter, the shim's or the harness's own
// classification, the production quorum accumulator or the leader selector: class, epoch, round, author and signed statement of a
// message are recomputed from its serialized bytes, signatures are verified with the keys of the bundle's manifest, and quorum
// arithmetic is plain integers. It reuses only the canonical codecs and signature primitives. It is a library and a command
// (cmd/q4replay) that no production binary links.
package q4replay

import (
	"encoding/json"
	"fmt"
	"os"
)

// Version of the bundle format.
const Version = 1

// Class is the assumption class of a row, separate from its pass/fail outcome.
const (
	InBound            = "IN-BOUND"
	OutsideAssumptions = "OUTSIDE-ASSUMPTIONS"
)

// Bundle is the export of one run.
type Bundle struct {
	Version  int    `json:"version"`
	Scenario string `json:"scenario"` // the test or lane row that produced it
	Coverage string `json:"coverage"` // ORACLE-ONLY, IN-PROCESS or REAL-PROCESS
	Scope    string `json:"scope"`    // what the run covers and what it does not (EVM, aggregator, crash model)
	Seed     string `json:"seed,omitempty"`
	// Class is the class the run claims. The checker recomputes it from the Byzantine weight and refuses a mismatch.
	Class     string   `json:"class"`
	Epochs    []Epoch  `json:"epochs"`
	Byzantine []string `json:"byzantine,omitempty"` // member names that were declared Byzantine for the run
	// Injected is the number of deliberately forged or mixed-statement sends the run declared. The checker must flag exactly that
	// many sends as malformed, each by its own reason; with 0 any malformed send is a violation.
	Injected int `json:"injected,omitempty"`
	// Frozen are the bounds fixed before the run. Windows are judged against them; a window carrying a longer deadline is refused.
	Frozen  Frozen   `json:"frozen"`
	Events  []Event  `json:"events"`
	Chains  []Chain  `json:"chains,omitempty"`
	Windows []Window `json:"windows,omitempty"`
}

// Epoch is the authenticated membership of one root epoch as the run installed it.
type Epoch struct {
	Epoch uint64 `json:"epoch"`
	// Scheme 1 is the legacy signing form, 2 the domain-bound form; for 2 the checker rebuilds the signed statement from Network
	// and Genesis.
	Scheme  uint64   `json:"scheme"`
	Network uint64   `json:"network,omitempty"`
	Genesis []byte   `json:"genesis,omitempty"`
	Members []Member `json:"members"`
	// Total, Quorum and Faulty are the arithmetic the run claims; the checker recomputes them from the weights.
	Total  uint64 `json:"total"`
	Quorum uint64 `json:"quorum"`
	Faulty uint64 `json:"faulty"`
}

// Member is one root validator of an epoch. ID is the canonical decoded root node ID the messages carry as author.
type Member struct {
	Name   string `json:"name"`
	ID     string `json:"id"`
	PubKey []byte `json:"pubKey"`
	Weight uint64 `json:"weight"`
}

// Frozen are the run's bounds, fixed before it started.
type Frozen struct {
	DeadlineMs int64 `json:"deadlineMs"` // post-fault recovery deadline
	// MaxCommitGapMs, when set, bounds the gap between two consecutive ordinary commits of a node inside a progress window.
	MaxCommitGapMs int64 `json:"maxCommitGapMs,omitempty"`
}

// Event is one entry of the merged message trace. Class, Epoch, Round and Author are what the producer claims; the checker
// recomputes them from Raw and refuses a difference.
type Event struct {
	Seq        uint64 `json:"seq"`
	Kind       string `json:"kind"` // attempt deliver drop hold release offline discard
	SendID     uint64 `json:"sendId,omitempty"`
	DeliveryID uint64 `json:"deliveryId,omitempty"`
	From       string `json:"from,omitempty"`
	To         string `json:"to,omitempty"`
	Rule       string `json:"rule,omitempty"`
	Class      string `json:"class,omitempty"`
	Epoch      uint64 `json:"epoch,omitempty"`
	Round      uint64 `json:"round,omitempty"`
	Author     string `json:"author,omitempty"`
	Raw        []byte `json:"raw,omitempty"`
}

// Chain is one node's committed history: the blocks of its committed chain and the times it observed ordinary commits.
type Chain struct {
	Node     string    `json:"node"`
	Blocks   []Block   `json:"blocks"`
	Observed []Observe `json:"observed,omitempty"`
}

// Block is a committed block: its round, hash and parent round.
type Block struct {
	Round  uint64 `json:"round"`
	Hash   []byte `json:"hash"`
	Parent uint64 `json:"parent"`
}

// Observe is one ordinary commit observed by a node at AtMs (Unix milliseconds).
type Observe struct {
	Round uint64 `json:"round"`
	AtMs  int64  `json:"atMs"`
}

// Window is one expectation over a span of the run: progress (the nodes make MinCommits new ordinary commits within the frozen
// deadline) or stall (the nodes make none between StartMs and EndMs). Progress by timeout certificate or round advance does not
// count; only ordinary commits do.
type Window struct {
	Name       string   `json:"name"`
	Expect     string   `json:"expect"` // progress or stall
	Nodes      []string `json:"nodes"`
	StartMs    int64    `json:"startMs"`
	EndMs      int64    `json:"endMs,omitempty"` // stall windows only
	MinCommits int      `json:"minCommits,omitempty"`
}

// Load reads a bundle from a JSON file.
func Load(path string) (*Bundle, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &b, nil
}

// Save writes the bundle as indented JSON.
func (b *Bundle) Save(path string) error {
	raw, err := json.MarshalIndent(b, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}
