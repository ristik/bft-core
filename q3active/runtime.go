// Package q3active wires the verified Q3 history and the durable installation journal into the consumers of the root chain
// (briefs/q3-design-v2.md sections 2, 4 and 6, slice D2): the root consensus manager, the safety module, the shard node, the
// signing authority and the certificate consumers.
//
// Nothing here is a switch. A Runtime owns one verified history rooted in the trusted genesis trust base and rebuilt, on every
// start, from the proof bytes the journal retains; whether an epoch is weighted, signs with scheme 2 or may be signed in is
// derived from that history and from the journal's completion marker, never from a flag or a configuration value. Production
// is inactive: nothing in the node constructs a Runtime, and a store that is not bound to one behaves exactly as before.
package q3active

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
	"github.com/unicitynetwork/bft-core/keyvaluedb"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/q3install"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	// ErrNotActive is returned for the data of an epoch that the verified history holds as a Q3 activation whose installation is not
	// complete (or not recovered since the last start): neither weights nor scheme 2 may be used before the journal says so.
	// It wraps q3install.ErrIncomplete.
	ErrNotActive = fmt.Errorf("q3active: activation is not installed: %w", q3install.ErrIncomplete)
	// ErrNotBound is returned when a participant that must install an activation is not wired to this runtime's gates.
	ErrNotBound = errors.New("q3active: participant is not bound to the verified history")
	// ErrRegress is returned for a snapshot that would replace a later one.
	ErrRegress = errors.New("q3active: snapshot would go back to an earlier epoch")
	// ErrHistory is returned when a staged bundle does not replay into the verified history: the journal holds a record the
	// history from the trusted genesis does not authenticate.
	ErrHistory = errors.New("q3active: staged activation is not authenticated by the history")
	// ErrSnapshot is returned by the snapshot step's check when the provisional snapshot is missing, older than the activation, or
	// another record's of the same epoch. The journal wraps it in q3install.ErrStoreConflict.
	ErrSnapshot = errors.New("q3active: the snapshot is not the activation's")
	// ErrConflict is returned when a legacy view disagrees with the verified history for an epoch.
	ErrConflict = errors.New("q3active: trust base differs from the verified history")
)

// RootSink is the root consensus manager (rootchain/consensus.ConsensusManager). InstallVerifiedEpoch must be idempotent for the
// same entry; HoldsVerifiedEpoch reports an error unless the manager's stores hold exactly that entry's epoch.
type RootSink interface {
	InstallVerifiedEpoch(entry q3format.Entry, proof handoff.OldCommitProof, head *abdrc.CommittedBlock, candidate []byte) (*rctypes.EpochAnchor, error)
	HoldsVerifiedEpoch(entry q3format.Entry) error
}

// RootRestorer is implemented by a root sink whose installed state is volatile (a shard node's in-memory shard configuration set and
// execution transitions): after a restart the journal restores every finished activation through it, in epoch order, before it verifies the
// sinks. RestoreVerifiedEpoch must be idempotent and must rebuild exactly what InstallVerifiedEpoch installed.
type RootRestorer interface {
	RestoreVerifiedEpoch(entry q3format.Entry, proof handoff.OldCommitProof, head *abdrc.CommittedBlock, candidate []byte) error
}

// Consumer is a participant whose view of the root trust comes from a runtime: the safety module (its activation gate), the shard
// node's trust lookup and the signing authority's TrustBases (a Guarded). BoundTo reports whether it is wired to that runtime.
type Consumer interface {
	BoundTo(authority any) bool
}

// Config opens a runtime: the install journal's durable store and the trusted genesis trust base the history is rooted in.
type Config struct {
	DB      keyvaluedb.KeyValueDB
	Genesis *types.RootTrustBaseV1
}

// Participants are the five installers. They exist only after the runtime does (the manager takes the runtime as its gate and
// anchor authority, and is itself the root installer), so they attach once, before Recover or Activate.
type Participants struct {
	Root RootSink
	// Safety is the safety module, Shard the shard node's trust lookup and Authority the signing authority's TrustBases.
	Safety, Shard, Authority Consumer
}

// Runtime is the verified history, the install journal and the published snapshot of one process.
type Runtime struct {
	mu        sync.Mutex // serialises activation and recovery
	journal   *q3install.Journal
	hist      atomic.Pointer[q3format.History]
	snap      atomic.Pointer[Snapshot] // the installer's provisional snapshot: private until its epoch is journaled complete
	active    atomic.Pointer[Snapshot] // the published active context: the provisional one once its epoch is complete
	parts     atomic.Pointer[Participants]
	completed sync.Map // epoch -> struct{}: journaled complete in this process
}

// ErrNotAttached is returned when an activation or recovery is asked before the participants were attached.
var ErrNotAttached = errors.New("q3active: participants are not attached")

// New opens the journal, then rebuilds the verified history from the genesis and every staged bundle, each
// authenticated in turn. A staged bundle the history does not authenticate refuses the start. After Attach, Recover must run
// before anything is admitted: until then no activated epoch is usable.
func New(cfg Config) (*Runtime, error) {
	if cfg.Genesis == nil {
		return nil, q3install.ErrComponents
	}
	r := &Runtime{}
	j, err := q3install.Open(q3install.Config{DB: cfg.DB, Bundles: r.verify, Components: map[q3install.Step]q3install.Component{
		q3install.StepRoot:      &rootComponent{r: r},
		q3install.StepSafety:    &consumerComponent{r: r, name: "safety", pick: func(p *Participants) Consumer { return p.Safety }},
		q3install.StepShard:     &consumerComponent{r: r, name: "shard", pick: func(p *Participants) Consumer { return p.Shard }},
		q3install.StepAuthority: &consumerComponent{r: r, name: "authority", pick: func(p *Participants) Consumer { return p.Authority }},
		q3install.StepSnapshot:  &snapshotComponent{r: r},
	}})
	if err != nil {
		return nil, err
	}
	r.journal = j
	h, err := q3format.NewHistory(cfg.Genesis)
	if err != nil {
		return nil, err
	}
	staged, err := j.Staged()
	if err != nil {
		return nil, err
	}
	for _, a := range staged {
		_, env, err := DecodeBundle(a.Bundle)
		if err != nil {
			return nil, errors.Join(ErrHistory, err)
		}
		if h, err = h.VerifyEnvelope(env); err != nil {
			return nil, errors.Join(ErrHistory, err)
		}
		if e, err := h.ForEpoch(a.Claim.Epoch); err != nil || e.Claim() != a.Claim {
			return nil, fmt.Errorf("%w: epoch %d", ErrHistory, a.Claim.Epoch)
		}
	}
	r.hist.Store(h)
	return r, nil
}

// Attach wires the installers. It succeeds once; every participant is required.
func (r *Runtime) Attach(p Participants) error {
	if p.Root == nil || p.Safety == nil || p.Shard == nil || p.Authority == nil {
		return q3install.ErrComponents
	}
	if !r.parts.CompareAndSwap(nil, &p) {
		return fmt.Errorf("%w: already attached", ErrNotAttached)
	}
	return nil
}

func (r *Runtime) participants() (*Participants, error) {
	p := r.parts.Load()
	if p == nil {
		return nil, ErrNotAttached
	}
	return p, nil
}

// Activated is the verified entry of an epoch that the history holds as a Q3 activation, installed or not.
func (r *Runtime) Activated(epoch uint64) (q3format.Entry, bool) {
	e, err := r.History().ForEpoch(epoch)
	if err != nil {
		return q3format.Entry{}, false
	}
	if _, active := e.Config(); !active {
		return q3format.Entry{}, false
	}
	return e, true
}

// History is the verified history. It is immutable: a later activation replaces it with an extended copy.
func (r *Runtime) History() *q3format.History { return r.hist.Load() }

// ActiveEpoch is the latest root epoch whose installation is complete and recovered, or 0 before the first activation completes. A node
// anchored at the genesis epoch is at that epoch until then.
func (r *Runtime) ActiveEpoch() uint64 {
	if s := r.active.Load(); s != nil {
		return s.Epoch()
	}
	return 0
}

// Snapshot is the published active-context handle, or nil before the first activation completes. An installation that is not
// durably complete and recovered publishes nothing, however far its steps got.
func (r *Runtime) Snapshot() *Snapshot { return r.active.Load() }

// complete records that an epoch's installation is durably complete (and recovered), admits it, and publishes the provisional
// snapshot when that is the epoch's.
func (r *Runtime) complete(epoch uint64) {
	r.completed.Store(epoch, struct{}{})
	if s := r.snap.Load(); s != nil {
		if _, ok := r.completed.Load(s.Epoch()); ok {
			r.active.Store(s)
		}
	}
}

// Signing is the signing configuration of an epoch, from the verified history. An epoch the history does not hold is an error. It
// is the trustbase.SigningAuthority a trust-base store is bound to; Admit is what gates signing.
func (r *Runtime) Signing(epoch uint64) (votesig.Config, error) { return r.History().Signing(epoch) }

// Admit is the signer admission check for an epoch: a verified legacy epoch is admitted, an unknown epoch is refused (never
// scheme 1 by default), and an activated epoch only once its journal is complete and recovered.
func (r *Runtime) Admit(epoch uint64) error {
	e, err := r.History().ForEpoch(epoch)
	if err != nil {
		return err
	}
	if _, active := e.Config(); !active {
		return nil
	}
	if _, ok := r.completed.Load(epoch); !ok {
		return fmt.Errorf("%w: epoch %d", ErrNotActive, epoch)
	}
	return nil
}

// Mode is the validation rule set of an epoch's data: unit for a verified legacy epoch, weighted for an activated epoch whose
// installation is complete (the snapshot is published by then: it is the last install step, before the completion marker).
// Anything else is an error, never a default.
func (r *Runtime) Mode(epoch uint64) (weightvalidation.Mode, error) {
	e, err := r.History().ForEpoch(epoch)
	if err != nil {
		return 0, err
	}
	if _, active := e.Config(); !active {
		return weightvalidation.ModeUnit, nil
	}
	if err := r.Admit(epoch); err != nil {
		return 0, err
	}
	return weightvalidation.ModeWeighted, nil
}

// verify is the journal's BundleVerifier: the bundle's envelope must verify against the history, and the history must derive the
// record the journal is asked to stage for that epoch. It changes nothing.
func (r *Runtime) verify(raw []byte, committed q3format.Claim) error {
	_, env, err := DecodeBundle(raw)
	if err != nil {
		return err
	}
	next, err := r.History().VerifyEnvelope(env)
	if err != nil {
		return err
	}
	if e, err := next.ForEpoch(committed.Epoch); err != nil || e.Claim() != committed {
		return fmt.Errorf("%w: the verified history derives another record for epoch %d", ErrBundle, committed.Epoch)
	}
	return nil
}

// adopt extends the history with a staged bundle's lineage. It is idempotent and runs in the root step, after the stage is durable,
// so the history never holds an activation that a restart would not rebuild.
func (r *Runtime) adopt(env q3format.Envelope) error {
	for {
		cur := r.hist.Load()
		next, err := cur.VerifyEnvelope(env)
		if err != nil {
			return err
		}
		if r.hist.CompareAndSwap(cur, next) {
			return nil
		}
	}
}

// resolve turns a journaled activation into the verified entry and the artifacts its installers need.
func (r *Runtime) resolve(a q3install.Activation) (q3format.Entry, handoff.OldCommitProof, Bundle, error) {
	b, env, err := DecodeBundle(a.Bundle)
	if err != nil {
		return q3format.Entry{}, handoff.OldCommitProof{}, Bundle{}, err
	}
	if env.Links[len(env.Links)-1].Claim != a.Claim {
		return q3format.Entry{}, handoff.OldCommitProof{}, Bundle{}, fmt.Errorf("%w: the envelope's last link is not the activation", ErrBundle)
	}
	e, err := r.History().ForEpoch(a.Claim.Epoch)
	if err != nil || e.Claim() != a.Claim {
		return q3format.Entry{}, handoff.OldCommitProof{}, Bundle{}, fmt.Errorf("%w: epoch %d", ErrHistory, a.Claim.Epoch)
	}
	p, err := activatingProof(env)
	return e, p, b, err
}

// Activate is the only way an activation starts: it authenticates the bundle against the history, then the journal stages it and
// carries every participant to completion in the section 4 order. It returns nil only after the completion marker is durable and
// the epoch is admitted.
func (r *Runtime) Activate(ctx context.Context, b Bundle) error {
	if _, err := r.participants(); err != nil {
		return err
	}
	raw, err := EncodeBundle(b)
	if err != nil {
		return err
	}
	_, env, err := DecodeBundle(raw)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	claim := env.Links[len(env.Links)-1].Claim
	if err := r.journal.Install(ctx, claim, raw); err != nil {
		return err
	}
	r.complete(claim.Epoch)
	return nil
}

// Recover is the startup pass: the journal completes any unfinished installation and checks every finished one against every
// store, over the history this runtime rebuilt. Only after it returns nil are activated epochs admitted.
func (r *Runtime) Recover(ctx context.Context) error {
	if _, err := r.participants(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	err := r.journal.Recover(ctx, func(epoch uint64) (q3format.Claim, bool) {
		e, ok := r.Activated(epoch)
		if !ok {
			return q3format.Claim{}, false
		}
		return e.Claim(), true
	})
	if err != nil {
		return err
	}
	staged, err := r.journal.Staged()
	if err != nil {
		return err
	}
	for _, a := range staged { // Recover finished or checked every one of them against every store
		r.complete(a.Claim.Epoch)
	}
	return nil
}

// Gate is the journal's signer admission for a record: complete, the same record, every store in agreement.
func (r *Runtime) Gate(ctx context.Context, c q3format.Claim) error { return r.journal.Gate(ctx, c) }

// publish makes the epoch's snapshot the installer's provisional context (Snapshot serves it once the epoch is complete). A later epoch replaces an earlier one; the same epoch is a no-op; going
// back is refused.
func (r *Runtime) publish(e q3format.Entry) error {
	cfg, ok := e.Config()
	if !ok {
		return fmt.Errorf("%w: epoch %d is not an activation", ErrHistory, e.Epoch())
	}
	next, err := newSnapshot(e, cfg)
	if err != nil {
		return err
	}
	for {
		cur := r.snap.Load()
		if err := supersedes(cur, next); err != nil {
			return err
		}
		if r.snap.CompareAndSwap(cur, next) {
			return nil
		}
	}
}

// supersedes checks that next may replace cur as the active context: a later epoch may, the same record again may, going back to
// an earlier epoch or to another record of the same epoch may not.
func supersedes(cur, next *Snapshot) error {
	switch {
	case cur == nil:
		return nil
	case cur.Epoch() > next.Epoch():
		return fmt.Errorf("%w: epoch %d after %d", ErrRegress, next.Epoch(), cur.Epoch())
	case cur.Epoch() == next.Epoch() && cur.claim != next.claim:
		return fmt.Errorf("%w: another record of epoch %d", ErrRegress, next.Epoch())
	}
	return nil
}

type rootComponent struct{ r *Runtime }

func (c *rootComponent) Install(_ context.Context, a q3install.Activation) error {
	_, env, err := DecodeBundle(a.Bundle)
	if err != nil {
		return err
	}
	if err := c.r.adopt(env); err != nil {
		return err
	}
	e, proof, b, err := c.r.resolve(a)
	if err != nil {
		return err
	}
	p, err := c.r.participants()
	if err != nil {
		return err
	}
	_, err = p.Root.InstallVerifiedEpoch(e, proof, b.Snapshot, b.Candidate)
	return err
}

// Restore rebuilds the volatile state of a sink that has any; for one that does not (the root consensus manager is durable) it is a no-op.
func (c *rootComponent) Restore(_ context.Context, a q3install.Activation) error {
	p, err := c.r.participants()
	if err != nil {
		return err
	}
	restorer, ok := p.Root.(RootRestorer)
	if !ok {
		return nil
	}
	e, proof, b, err := c.r.resolve(a)
	if err != nil {
		return err
	}
	return restorer.RestoreVerifiedEpoch(e, proof, b.Snapshot, b.Candidate)
}

func (c *rootComponent) Verify(_ context.Context, a q3install.Activation) error {
	e, _, _, err := c.r.resolve(a)
	if err != nil {
		return err
	}
	p, err := c.r.participants()
	if err != nil {
		return err
	}
	return p.Root.HoldsVerifiedEpoch(e)
}

// consumerComponent installs nothing of its own: a safety module, shard lookup or signing authority holds no V3 state besides the
// verified history and the journal, so its install is the proof that it admits and resolves only through this runtime. A
// participant that is not bound to the runtime would keep signing or verifying without the history; the journal then cannot complete.
type consumerComponent struct {
	r    *Runtime
	name string
	pick func(*Participants) Consumer
}

func (c *consumerComponent) check(a q3install.Activation) error {
	p, err := c.r.participants()
	if err != nil {
		return err
	}
	if consumer := c.pick(p); consumer == nil || !consumer.BoundTo(c.r) {
		return fmt.Errorf("%w: %s", ErrNotBound, c.name)
	}
	_, _, _, err = c.r.resolve(a)
	return err
}

func (c *consumerComponent) Install(_ context.Context, a q3install.Activation) error {
	return c.check(a)
}
func (c *consumerComponent) Verify(_ context.Context, a q3install.Activation) error {
	return c.check(a)
}

type snapshotComponent struct{ r *Runtime }

func (c *snapshotComponent) Install(_ context.Context, a q3install.Activation) error {
	e, _, _, err := c.r.resolve(a)
	if err != nil {
		return err
	}
	return c.r.publish(e)
}

// Restore republishes the snapshot of a finished activation after a restart, in epoch order, so the last one is the tip.
func (c *snapshotComponent) Restore(ctx context.Context, a q3install.Activation) error {
	return c.Install(ctx, a)
}

func (c *snapshotComponent) Verify(_ context.Context, a q3install.Activation) error {
	s := c.r.snap.Load()
	switch {
	case s == nil || s.Epoch() < a.Claim.Epoch:
		return fmt.Errorf("%w: epoch %d is not published", ErrSnapshot, a.Claim.Epoch)
	case s.Epoch() == a.Claim.Epoch && s.claim != a.Claim:
		return fmt.Errorf("%w: the snapshot published for epoch %d is another record's", ErrSnapshot, a.Claim.Epoch)
	}
	return nil
}
