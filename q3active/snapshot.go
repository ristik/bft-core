package q3active

import (
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// Member is one root member of the active committee with its exact weight.
type Member struct {
	NodeID string
	Weight uint64
}

// Snapshot is the one immutable handle the Q1 and Q2 selections are read from once an activation is installed: the epoch's
// signing scheme and configuration, the validation rules (bounded weights, mirrored EVM request policy) and the committee with its
// exact total and threshold. It is built from a verified history entry and published once, atomically, as the last install step,
// so no thread sees new weights with old signing or the reverse. It has no setters.
type Snapshot struct {
	claim     q3format.Claim
	signing   votesig.Config
	configID  [32]byte
	mode      weightvalidation.Mode
	members   []Member
	total     uint64
	threshold uint64
}

func newSnapshot(e q3format.Entry, cfg q3format.ProtocolConfig) (*Snapshot, error) {
	tb := e.Projection()
	total, err := quorumweight.TotalWeight(tb.RootNodes)
	if err != nil {
		return nil, err
	}
	s := &Snapshot{claim: e.Claim(), signing: votesigConfig(cfg), configID: cfg.Identity(), mode: weightvalidation.ModeWeighted,
		total: total, threshold: tb.QuorumThreshold}
	for _, n := range tb.RootNodes {
		s.members = append(s.members, Member{NodeID: n.NodeID, Weight: n.Stake})
	}
	return s, nil
}

func votesigConfig(c q3format.ProtocolConfig) votesig.Config {
	return votesig.Config{Scheme: c.SigningScheme, Network: c.Network, Genesis: c.Genesis}
}

// Epoch is the activated root epoch; Start its actual activation boundary A*.
func (s *Snapshot) Epoch() uint64 { return s.claim.Epoch }
func (s *Snapshot) Start() uint64 { return s.claim.Start }

// Claim is the committed record this snapshot was published for.
func (s *Snapshot) Claim() q3format.Claim { return s.claim }

// Signing is the epoch's signing configuration (scheme 2 and the chain's genesis identity).
func (s *Snapshot) Signing() votesig.Config { return s.signing }

// ConfigID is the identity of the protocol tuple the epoch runs.
func (s *Snapshot) ConfigID() [32]byte { return s.configID }

// Mode is the validation rule set of the epoch's data: weighted, never a legacy unit rule.
func (s *Snapshot) Mode() weightvalidation.Mode { return s.mode }

// Members is a copy of the committee in node-id order, Total the sum of the weights and Threshold the exact quorum weight.
func (s *Snapshot) Members() []Member { return append([]Member(nil), s.members...) }
func (s *Snapshot) Total() uint64     { return s.total }
func (s *Snapshot) Threshold() uint64 { return s.threshold }
