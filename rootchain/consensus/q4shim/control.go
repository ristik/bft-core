package q4shim

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"time"
)

// Control is the document a lane writes to steer a live shim: the full rule set (replacing the previous one; counters of a rule that
// keeps its name are kept), the triggers, the Byzantine instructions and the releases to perform. Gen only has to change when the
// document does; it is reported back in the status file so that a lane can wait until the shim has read what it wrote.
type Control struct {
	Gen          uint64         `json:"gen"`
	Rules        []Rule         `json:"rules,omitempty"`
	Triggers     []Trigger      `json:"triggers,omitempty"`
	Equivocation []Equivocation `json:"equivocation,omitempty"`
	Forgery      []Forgery      `json:"forgery,omitempty"`
	Releases     []Release      `json:"releases,omitempty"`
}

// Status is what the shim reports about itself, for a lane to assert that every injection happened.
type Status struct {
	Gen        uint64         `json:"gen"`
	Self       string         `json:"self"`
	Sends      uint64         `json:"sends"`
	Deliveries uint64         `json:"deliveries"`
	Rules      map[string]int `json:"rules"`     // rule name -> messages matched
	Triggers   map[string]int `json:"triggers"`  // trigger name -> times fired
	Held       map[string]int `json:"held"`      // rule name -> messages held now
	Byzantine  map[string]int `json:"byzantine"` // equivocation name -> messages sent
	Forged     map[string]int `json:"forged"`    // forgery name -> messages sent
	Faults     []string       `json:"faults,omitempty"`
}

func validate(c Control) error {
	names := map[string]struct{}{}
	for _, r := range c.Rules {
		if r.Name == "" {
			return fmt.Errorf("%w: a rule has no name", ErrBadControl)
		}
		if _, dup := names[r.Name]; dup {
			return fmt.Errorf("%w: duplicate rule %q", ErrBadControl, r.Name)
		}
		names[r.Name] = struct{}{}
		switch r.Action {
		case Pass, Drop, Hold, Duplicate:
		default:
			return fmt.Errorf("%w: rule %q has action %q", ErrBadControl, r.Name, r.Action)
		}
		if r.After != "" && !slices.ContainsFunc(c.Triggers, func(t Trigger) bool { return t.Name == r.After }) {
			return fmt.Errorf("%w: rule %q waits for unknown trigger %q", ErrBadControl, r.Name, r.After)
		}
	}
	tnames := map[string]struct{}{}
	for _, t := range c.Triggers {
		if t.Name == "" {
			return fmt.Errorf("%w: a trigger has no name", ErrBadControl)
		}
		if _, dup := tnames[t.Name]; dup {
			return fmt.Errorf("%w: duplicate trigger %q", ErrBadControl, t.Name)
		}
		tnames[t.Name] = struct{}{}
	}
	for _, rel := range c.Releases {
		switch rel.Order {
		case "", FIFO, LIFO, RoundAsc, RoundDsc:
		default:
			return fmt.Errorf("%w: release %q has order %q", ErrBadControl, rel.ID, rel.Order)
		}
		if rel.ID == "" || rel.Rule == "" {
			return fmt.Errorf("%w: a release needs an id and a rule", ErrBadControl)
		}
	}
	return nil
}

// Apply installs a control document. An invalid document changes nothing and is returned as ErrBadControl. Rules that keep their name
// keep their hit counters and what they hold; triggers keep their fired counts; a release whose ID was performed before is skipped.
func (n *Net) Apply(ctx context.Context, c Control) error {
	if err := validate(c); err != nil {
		return err
	}
	if err := n.SetEquivocations(c.Equivocation); err != nil {
		return err
	}
	if err := n.SetForgeries(c.Forgery); err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	old := n.rules
	n.rules = n.rules[:0:0]
	for _, r := range c.Rules {
		st := &ruleState{Rule: r}
		if i := slices.IndexFunc(old, func(o *ruleState) bool { return o.Name == r.Name }); i >= 0 {
			st.hits, st.retired = old[i].hits, old[i].retired
		}
		n.rules = append(n.rules, st)
	}
	oldT := n.triggers
	n.triggers = n.triggers[:0:0]
	for _, t := range c.Triggers {
		st := &triggerState{Trigger: t}
		if i := slices.IndexFunc(oldT, func(o *triggerState) bool { return o.Name == t.Name }); i >= 0 {
			st.fired = oldT[i].fired
		}
		n.triggers = append(n.triggers, st)
	}
	n.gen = c.Gen
	for _, rel := range c.Releases {
		if _, done := n.released[rel.ID]; done {
			continue
		}
		n.released[rel.ID] = struct{}{}
		if _, err := n.release(ctx, rel.Rule, rel.Order); err != nil {
			return err
		}
	}
	return nil
}

// Status is the shim's report.
func (n *Net) Status() Status {
	n.mu.Lock()
	defer n.mu.Unlock()
	st := Status{Gen: n.gen, Self: n.cfg.Self.String(), Sends: n.sends, Deliveries: n.deliveries,
		Rules: map[string]int{}, Triggers: map[string]int{}, Held: map[string]int{}, Byzantine: map[string]int{}, Forged: map[string]int{}}
	for _, r := range n.rules {
		st.Rules[r.Name] = r.hits
	}
	for _, t := range n.triggers {
		st.Triggers[t.Name] = t.fired
	}
	for _, h := range n.held {
		st.Held[h.rule]++
	}
	for _, e := range n.equivs {
		st.Byzantine[e.Name] = e.sent
	}
	for _, f := range n.forges {
		st.Forged[f.Name] = f.sent
	}
	for _, f := range n.faults {
		st.Faults = append(st.Faults, f.Error())
	}
	return st
}

// Watch polls the control file and applies it whenever its content changes, until ctx ends. A file that is missing is no control; one
// that is invalid is a fault in the trace and leaves the previous rules in force. After every poll the status is written next to it
// as statusPath (when set), so that a lane can read what has been injected.
func (n *Net) Watch(ctx context.Context, controlPath, statusPath string, every time.Duration) {
	var last []byte
	var lastStatus []byte
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		if raw, err := os.ReadFile(controlPath); err == nil && !bytes.Equal(raw, last) {
			last = raw
			var c Control
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&c); err != nil {
				n.mu.Lock()
				n.fault(fmt.Errorf("%w: %w", ErrBadControl, err))
				n.mu.Unlock()
			} else if err := n.Apply(ctx, c); err != nil {
				n.mu.Lock()
				n.fault(err)
				n.mu.Unlock()
			}
		}
		if statusPath != "" {
			if b, err := json.MarshalIndent(n.Status(), "", " "); err == nil && !bytes.Equal(b, lastStatus) {
				lastStatus = b
				tmp := statusPath + ".tmp"
				if os.WriteFile(tmp, b, 0o600) == nil {
					_ = os.Rename(tmp, statusPath)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
