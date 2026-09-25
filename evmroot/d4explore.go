package evmroot

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
)

// BranchState is the authenticated state at a proposal's certified parent.
// Every byte represented here is copied on an old suffix. Round and QC metadata
// live outside it. Missing parent state cannot be interpreted as pre-handoff.
type D4BranchState struct {
	Control     *ControlState
	Shards      []ShardSnapshot
	PendingWork [][]byte
}

func (s D4BranchState) Clone() D4BranchState {
	out := D4BranchState{PendingWork: make([][]byte, len(s.PendingWork)), Shards: make([]ShardSnapshot, len(s.Shards))}
	if s.Control != nil {
		c := *s.Control
		out.Control = &c
	}
	copy(out.Shards, s.Shards)
	for i, v := range s.PendingWork {
		out.PendingWork[i] = bytes.Clone(v)
	}
	return out
}
func (s D4BranchState) Equal(t D4BranchState) bool {
	if (s.Control == nil) != (t.Control == nil) || len(s.Shards) != len(t.Shards) || len(s.PendingWork) != len(t.PendingWork) {
		return false
	}
	if s.Control != nil && !bytes.Equal(s.Control.Bytes(), t.Control.Bytes()) {
		return false
	}
	for i := range s.Shards {
		a, b := s.Shards[i], t.Shards[i]
		if a.Partition != b.Partition || !bytes.Equal(a.Root, b.Root) || !bytes.Equal(a.InputRecord, b.InputRecord) || !bytes.Equal(a.TechnicalRecord, b.TechnicalRecord) || !bytes.Equal(a.LastCR, b.LastCR) || !bytes.Equal(a.PendingConfig, b.PendingConfig) || !bytes.Equal(a.FeeStats, b.FeeStats) {
			return false
		}
	}
	for i := range s.PendingWork {
		if !bytes.Equal(s.PendingWork[i], t.PendingWork[i]) {
			return false
		}
	}
	return true
}

type D4Proposal struct {
	Epoch, Round                                              uint64
	PayloadKind                                               string
	Payload                                                   []byte
	ScheduledConfig, NextEpoch, TimeoutUpdate, HiddenMutation bool
}

func CanVoteOldSuffix(parent *D4BranchState, p D4Proposal) error {
	if parent == nil || parent.Control == nil {
		return ErrD4Unready
	}
	if parent.Control.Phase != "committed" {
		return nil
	}
	if p.Epoch != parent.Control.Epoch || p.Round <= parent.Control.OrderedRound {
		return ErrD4Epoch
	}
	if p.PayloadKind != "" || len(p.Payload) != 0 || p.ScheduledConfig || p.NextEpoch || p.TimeoutUpdate || p.HiddenMutation {
		return ErrD4Suffix
	}
	return nil
}
func ExecuteOldSuffix(parent *D4BranchState, p D4Proposal) (D4BranchState, error) {
	if e := CanVoteOldSuffix(parent, p); e != nil {
		return D4BranchState{}, e
	}
	out := parent.Clone()
	// Model the ordinary executor's state change behind the suffix gate. If
	// that gate is removed, a payload reaches a different committed root.
	if p.PayloadKind != "" || len(p.Payload) != 0 || p.ScheduledConfig || p.NextEpoch || p.TimeoutUpdate || p.HiddenMutation {
		if len(out.Shards) > 0 {
			out.Shards[0].InputRecord = append(bytes.Clone(out.Shards[0].InputRecord), p.Payload...)
			out.Shards[0].InputRecord = append(out.Shards[0].InputRecord, byte(1))
			out.Shards[0].Root = out.Shards[0].CalculatedRoot()
		} else {
			out.PendingWork = append(out.PendingWork, []byte("executed-payload"))
		}
	}
	return out, nil
}
func RecoverOldSuffix(parent *D4BranchState, p D4Proposal) (D4BranchState, error) {
	return ExecuteOldSuffix(parent, p)
}

type D4Position struct{ Epoch, Round uint64 }

func (a D4Position) Less(b D4Position) bool {
	return a.Epoch < b.Epoch || a.Epoch == b.Epoch && a.Round < b.Round
}

type D4ShardUC struct {
	Shard                       uint32
	Position                    D4Position
	Root, InputRecord, ParentIR []byte
	SignerEpoch                 uint64
	Valid                       bool
}
type D4Consumer struct {
	Current                          *D4ShardUC
	TransitionInstalled, Ready       bool
	OldEpoch, NewEpoch, OrderedRound uint64
	TerminalRoot                     []byte
	TerminalIR                       map[uint32][]byte
	History                          []D4ShardUC
	TimeoutCount, RevertCount        uint64
}

func (c *D4Consumer) Install(v VerifiedHandoff) {
	c.TransitionInstalled = true
	c.OldEpoch = v.Epoch
	c.NewEpoch = v.Epoch + 1
	c.OrderedRound = v.OrderRound
	c.TerminalRoot = bytes.Clone(v.Root)
	c.TerminalIR = map[uint32][]byte{}
	for _, s := range v.Snapshot.Shards {
		c.TerminalIR[uint32(s.Partition)] = bytes.Clone(s.InputRecord)
	}
}
func CanAcceptShardUC(c *D4Consumer, u D4ShardUC) error {
	if !u.Valid || u.SignerEpoch != u.Position.Epoch {
		return ErrD4Proof
	}
	if !c.TransitionInstalled {
		if c.Current == nil || u.Position.Epoch != c.Current.Position.Epoch || !c.Current.Position.Less(u.Position) {
			return ErrD4Epoch
		}
		// A higher-round same-IR old UC may be a minted terminal repeat. Until
		// the checkpoint supplies IR_H, defer its effects and fetch evidence.
		if c.OrderedRound != 0 && u.Position.Round >= c.OrderedRound && bytes.Equal(u.InputRecord, c.Current.InputRecord) {
			return ErrD4Unready
		}
		return nil
	}
	if u.Position.Epoch == c.OldEpoch {
		if u.Position.Round >= c.OrderedRound && bytes.Equal(u.Root, c.TerminalRoot) && bytes.Equal(u.InputRecord, c.TerminalIR[u.Shard]) {
			return ErrD4TerminalRepeat
		}
		return ErrD4Epoch
	}
	if u.Position.Epoch != c.NewEpoch || !c.Ready {
		return ErrD4Epoch
	}
	expected, known := c.TerminalIR[u.Shard]
	if !known || len(u.Root) != 32 {
		return ErrD4Proof
	}
	if c.Current != nil && c.Current.Position.Epoch == c.NewEpoch {
		expected = c.Current.InputRecord
	}
	if !bytes.Equal(u.ParentIR, expected) {
		return ErrD4Proof
	}
	if c.Current != nil && !c.Current.Position.Less(u.Position) {
		return ErrD4Epoch
	}
	return nil
}
func (c *D4Consumer) Accept(u D4ShardUC) error {
	e := CanAcceptShardUC(c, u)
	if e == nil {
		if !c.TransitionInstalled && c.Current != nil && bytes.Equal(u.InputRecord, c.Current.InputRecord) {
			// Ordinary old-epoch repeats use the legacy timeout/revert path.
			// The pre-install terminal guard above must keep late repeats out.
			c.TimeoutCount++
			c.RevertCount++
		}
		cp := u
		c.Current = &cp
		c.History = append(c.History, cp)
	} else if errors.Is(e, ErrD4TerminalRepeat) {
		c.History = append(c.History, u)
	}
	return e
}
func (c D4Consumer) Restart() D4Consumer { return c }

// NextEpoch is deferred through every old suffix, then applied exactly once
// by the first ordinary new block. It changes TR/config/fee state without
// claiming Changed or emitting a UC on that fact alone.
type D4DeferredShard struct {
	IR, TR, LastCR, PendingConfig, ActiveConfig, FeeStats []byte
	IREpoch, TREpoch                                      uint64
	Changed, Applied                                      bool
}

func (s *D4DeferredShard) NewEpochBlock() error {
	if s.Applied {
		return nil
	}
	if s.TREpoch != s.IREpoch {
		s.IREpoch = s.TREpoch
		s.ActiveConfig = bytes.Clone(s.PendingConfig)
		s.PendingConfig = nil
		s.FeeStats = append(bytes.Clone(s.FeeStats), byte(1))
	}
	s.Applied = true
	return nil
}
func (s *D4DeferredShard) PayloadCertification(ir []byte) { s.IR = bytes.Clone(ir); s.Changed = true }

// ExploreCommittedHistories compares actual committed state and accepted UC
// histories across replicas. The caller supplies branch transitions; no
// assertion is a restatement of Authorized(round).
type D4Replica struct {
	ID                   string
	Committed            []D4Committed
	Consumer             D4Consumer
	LastVoted, LockRound uint64
}
type D4Committed struct {
	Position D4Position
	Root     []byte
	State    D4BranchState
	RecordID []byte
}

func ExploreCommittedHistories(replicas []D4Replica) error {
	byPosition := map[D4Position]D4Committed{}
	successors := map[string]struct{}{}
	for _, rep := range replicas {
		var prior D4Position
		for i, c := range rep.Committed {
			if i > 0 && !prior.Less(c.Position) {
				return fmt.Errorf("replica %s: nonmonotone commit", rep.ID)
			}
			prior = c.Position
			if old, ok := byPosition[c.Position]; ok && (!bytes.Equal(old.Root, c.Root) || !bytes.Equal(old.RecordID, c.RecordID) || !old.State.Equal(c.State)) {
				return fmt.Errorf("replicas disagree at %v", c.Position)
			}
			byPosition[c.Position] = c
			if len(c.RecordID) > 0 {
				successors[string(c.RecordID)] = struct{}{}
			}
		}
		for i := 1; i < len(rep.Consumer.History); i++ {
			a, b := rep.Consumer.History[i-1], rep.Consumer.History[i]
			if !a.Position.Less(b.Position) && !(a.Position.Epoch == rep.Consumer.OldEpoch && b.Position.Epoch == a.Position.Epoch && bytes.Equal(a.InputRecord, b.InputRecord) && bytes.Equal(a.Root, b.Root)) {
				return fmt.Errorf("replica %s: certificate rollback", rep.ID)
			}
		}
	}
	if len(successors) > 1 {
		return errors.New("conflicting committed successor records")
	}
	return nil
}
func D4TraceNames() []string {
	out := []string{"suffix_payload_refused", "suffix_payload_no_qc", "leader_c_plus_2_crash", "deterministic_genesis", "new_bootstrap_timeout", "consumer_epoch_and_round", "proof_negatives", "pause_measurement", "minted_late_suffix_uc", "different_c_fixed_start", "next_epoch_carry_over", "payload_bearing_recovered_suffix", "missing_forged_control", "anchor_commit_refused", "mixed_historical_lastcr"}
	sort.Strings(out)
	return out
}

// ExploreD4GuardInvariants actively tries the four dangerous transitions.
// Each probe is applied to independent state and checked against committed
// history or certificate history, so removing an admission guard creates a
// visible invariant violation rather than merely changing an expected error.
func ExploreD4GuardInvariants(parent D4BranchState, v VerifiedHandoff, g EpochGenesis, newTrust D4TrustBase) error {
	baseline := parent.Clone()
	payload := D4Proposal{Epoch: v.Epoch, Round: v.OrderRound + 1, PayloadKind: "shard_success", Payload: []byte("evil")}
	if got, e := ExecuteOldSuffix(&parent, payload); e == nil {
		if !got.Equal(baseline) {
			return errors.New("suffix changed committed state")
		}
		return errors.New("payload suffix reached committed history")
	}
	tampered := g
	tampered.Start++
	if CanBootstrapNew(v, tampered, v.Snapshot) == nil {
		return errors.New("different fixed A* accepted")
	}
	b := D4Bootstrap{}
	if e := b.Install(v, g, v.Snapshot, newTrust); e != nil {
		return e
	}
	if b.Commit(b.HighestQC, D4QC{}) == nil || len(b.Committed) != 0 {
		return errors.New("anchor entered committed history")
	}
	c := D4Consumer{}
	c.Install(v)
	c.Ready = true
	old := D4ShardUC{Shard: uint32(v.Snapshot.Shards[0].Partition), Position: D4Position{v.Epoch, v.OrderRound + 100}, Root: v.Root, InputRecord: v.Snapshot.Shards[0].InputRecord, SignerEpoch: v.Epoch, Valid: true}
	if c.Accept(old) == nil || c.Current != nil {
		return errors.New("late terminal UC became current")
	}
	return nil
}
