// Package q3install is the durable, crash-atomic installation journal of a Q3 activation (briefs/q3-design-v2.md section 4).
// It persists the committed activation record and the progress of the ordered participant installs, so that a crash at any
// point resumes or completes the exact installation and never leaves a half-installed epoch that signers can use. It is
// inactive: nothing in the node opens a Journal yet, and the component wiring (root, safety module, shard, signing authority,
// snapshot publication) is a later slice.
//
// A journal never erases or rewrites anything: it appends a staged record, one marker per finished step and a completion
// marker. It performs no Delete, so no safety decision, history entry or high-water mark can be cleared to repair an
// interrupted install.
package q3install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/unicitynetwork/bft-core/keyvaluedb"
	"github.com/unicitynetwork/bft-core/q3format"
	bfttypes "github.com/unicitynetwork/bft-go-base/types"
)

var (
	// ErrRecordMismatch is returned when a journal entry does not match the committed record it is presented with: another
	// body, boundary, commit or predecessor, a different bundle, or an epoch the committed history does not hold.
	ErrRecordMismatch = errors.New("q3install: journal entry does not match the committed record")
	// ErrBundle is returned when the staged bundle is not authenticated as carrying the committed record.
	ErrBundle = errors.New("q3install: staged bundle is not authenticated by the committed record")
	// ErrJournal is returned for a journal that is damaged, noncanonical or internally inconsistent: stray keys, markers without
	// their predecessors, a step recorded for another activation.
	ErrJournal = errors.New("q3install: damaged or inconsistent journal")
	// ErrStoreConflict is returned when a participant store disagrees with the activation after its install, or when a completed
	// journal no longer agrees with a store.
	ErrStoreConflict = errors.New("q3install: participant store conflicts with the activation")
	// ErrIncomplete is returned when signers are asked to start on an activation whose installation has not completed.
	ErrIncomplete = errors.New("q3install: activation installation is not complete")
	// ErrBusy is returned when a second activation is staged while another has not completed.
	ErrBusy = errors.New("q3install: another activation is still being installed")
	// ErrComponents is returned for a Config without exactly one component per step, or without a bundle verifier.
	ErrComponents = errors.New("q3install: configuration is incomplete")
)

// Step is one participant install, in the order of section 4.
type Step uint8

const (
	StepRoot      Step = iota + 1 // history, block/anchor and configuration stores of the root chain
	StepSafety                    // safety module: configuration identity bound to its decisions
	StepShard                     // shard node history
	StepAuthority                 // signing authority
	StepSnapshot                  // the Q1/Q2 snapshot: scheme-2 codecs, weighted resolver, caches rebuilt, one immutable handle
	numSteps      = int(StepSnapshot)
)

// Steps is the install order. Publication of the snapshot is last: no thread can see new weights before every store holds them.
var Steps = [numSteps]Step{StepRoot, StepSafety, StepShard, StepAuthority, StepSnapshot}

func (s Step) String() string {
	switch s {
	case StepRoot:
		return "root"
	case StepSafety:
		return "safety"
	case StepShard:
		return "shard"
	case StepAuthority:
		return "authority"
	case StepSnapshot:
		return "snapshot"
	}
	return "step(" + strconv.Itoa(int(s)) + ")"
}

// Activation is what every component installs: the committed record's claim, the identity binding it to the staged bundle, and
// the bundle itself (a canonical proof envelope the component verifies under its own authority).
type Activation struct {
	Claim  q3format.Claim
	ID     [32]byte
	Bundle []byte
}

// Component is one participant's store. Install must be idempotent: after a crash it is called again with the same activation
// and must converge on the same state, preserving every decision it already holds. Verify returns nil only if the store holds
// exactly this activation, and an error for a missing or conflicting artifact.
type Component interface {
	Install(context.Context, Activation) error
	Verify(context.Context, Activation) error
}

// Restorer is implemented by a component whose installed state is volatile (the published snapshot): Recover calls Restore for
// every activation whose completion marker is durable, before it verifies the stores, so a restart rebuilds what a process loses.
// An unfinished activation is not restored: its install step runs when the installation resumes. Restore must be idempotent.
type Restorer interface {
	Restore(context.Context, Activation) error
}

// BundleVerifier authenticates a staged bundle against the committed claim, under the verified history's authority. A nil
// verifier is a configuration error: an unauthenticated bundle is never journaled or resumed.
type BundleVerifier func(bundle []byte, committed q3format.Claim) error

// Config wires a journal. Components must hold exactly the five steps.
type Config struct {
	DB         keyvaluedb.KeyValueDB
	Components map[Step]Component
	Bundles    BundleVerifier
}

// MaxBundle bounds a staged bundle, as the proof envelope is bounded.
const MaxBundle = q3format.MaxEnvelopeBytes

const (
	prefix     = "q3install/"
	idDomain   = "UNICITY_Q3_INSTALL_JOURNAL_V1"
	epochWidth = 16
)

// stageDisk is the single record that makes an activation durable. It is written once, atomically, before any install step.
type stageDisk struct {
	Epoch, Start     uint64
	BodyID, CommitID []byte
	PriorVersion     uint64
	PriorID          []byte
	ID               []byte
	Bundle           []byte
}

// ActivationID binds the committed claim to the exact staged bundle.
func ActivationID(c q3format.Claim, bundle []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(idDomain))
	b, _ := bfttypes.Cbor.Marshal([]any{c.Epoch, c.Start, c.BodyID[:], c.CommitID[:], c.PriorVersion, c.PriorID[:], sha256.Sum256(bundle)})
	h.Write(b)
	var id [32]byte
	copy(id[:], h.Sum(nil))
	return id
}

type state struct {
	stage *stageDisk
	steps [numSteps]bool
	done  bool
}

// Journal is the durable installation journal. It is safe for concurrent use.
type Journal struct {
	mu  sync.Mutex
	cfg Config
}

func key(epoch uint64, suffix string) []byte {
	return []byte(prefix + fmt.Sprintf("%0*x", epochWidth, epoch) + "/" + suffix)
}

// Open validates the configuration and the whole stored journal. A damaged journal refuses here, before anything can be
// installed or signed.
func Open(cfg Config) (*Journal, error) {
	if cfg.DB == nil || cfg.Bundles == nil || len(cfg.Components) != numSteps {
		return nil, ErrComponents
	}
	for _, s := range Steps {
		if cfg.Components[s] == nil {
			return nil, fmt.Errorf("%w: no component for %s", ErrComponents, s)
		}
	}
	j := &Journal{cfg: cfg}
	if _, err := j.load(); err != nil {
		return nil, err
	}
	return j, nil
}

func parseKey(k []byte) (epoch uint64, suffix string, ok bool) {
	s := string(k)
	if !strings.HasPrefix(s, prefix) {
		return 0, "", false
	}
	rest := s[len(prefix):]
	if len(rest) <= epochWidth || rest[epochWidth] != '/' {
		return 0, "", false
	}
	e, err := strconv.ParseUint(rest[:epochWidth], 16, 64)
	if err != nil || fmt.Sprintf("%0*x", epochWidth, e) != rest[:epochWidth] {
		return 0, "", false
	}
	return e, rest[epochWidth+1:], true
}

func decodeStage(raw []byte) (*stageDisk, error) {
	var d stageDisk
	if err := bfttypes.Cbor.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJournal, err)
	}
	again, err := bfttypes.Cbor.Marshal(d)
	if err != nil || !bytes.Equal(again, raw) {
		return nil, fmt.Errorf("%w: stage is not canonical", ErrJournal)
	}
	if len(d.BodyID) != 32 || len(d.CommitID) != 32 || len(d.PriorID) != 32 || len(d.ID) != 32 || len(d.Bundle) == 0 || len(d.Bundle) > MaxBundle {
		return nil, fmt.Errorf("%w: stage has malformed fields", ErrJournal)
	}
	return &d, nil
}

func (d *stageDisk) claim() q3format.Claim {
	c := q3format.Claim{Epoch: d.Epoch, Start: d.Start, PriorVersion: d.PriorVersion}
	copy(c.BodyID[:], d.BodyID)
	copy(c.CommitID[:], d.CommitID)
	copy(c.PriorID[:], d.PriorID)
	return c
}

func (d *stageDisk) activation() Activation {
	a := Activation{Claim: d.claim(), Bundle: bytes.Clone(d.Bundle)}
	copy(a.ID[:], d.ID)
	return a
}

// load reads and checks every stored key. The checks are structural and need no committed record: a stage must be canonical and
// its identity must be the hash of its own claim and bundle; each marker must carry that identity and follow every earlier step;
// the completion marker requires all steps; at most one activation may be unfinished.
func (j *Journal) load() (map[uint64]*state, error) {
	it := j.cfg.DB.First()
	type kv struct {
		epoch  uint64
		suffix string
		value  []byte
	}
	var all []kv
	for ; it.Valid(); it.Next() {
		epoch, suffix, ok := parseKey(it.Key())
		if !ok {
			_ = it.Close()
			return nil, fmt.Errorf("%w: unrecognized key", ErrJournal)
		}
		var v []byte
		if err := it.Value(&v); err != nil {
			_ = it.Close()
			return nil, fmt.Errorf("%w: %v", ErrJournal, err)
		}
		all = append(all, kv{epoch, suffix, bytes.Clone(v)})
	}
	if err := it.Close(); err != nil {
		return nil, err
	}
	out := make(map[uint64]*state)
	get := func(e uint64) *state {
		if out[e] == nil {
			out[e] = &state{}
		}
		return out[e]
	}
	for _, e := range all {
		if e.suffix == "stage" {
			d, err := decodeStage(e.value)
			if err != nil {
				return nil, err
			}
			if d.Epoch != e.epoch {
				return nil, fmt.Errorf("%w: stage under epoch %d names epoch %d", ErrJournal, e.epoch, d.Epoch)
			}
			if id := ActivationID(d.claim(), d.Bundle); !bytes.Equal(id[:], d.ID) {
				return nil, fmt.Errorf("%w: stage identity does not match its contents", ErrJournal)
			}
			get(e.epoch).stage = d
		}
	}
	for _, e := range all {
		st := get(e.epoch)
		if e.suffix == "stage" {
			continue
		}
		if st.stage == nil {
			return nil, fmt.Errorf("%w: marker %q without a stage", ErrJournal, e.suffix)
		}
		if !bytes.Equal(e.value, st.stage.ID) {
			return nil, fmt.Errorf("%w: marker %q belongs to another activation", ErrJournal, e.suffix)
		}
		switch {
		case e.suffix == "done":
			st.done = true
		case strings.HasPrefix(e.suffix, "step/"):
			n, err := strconv.Atoi(e.suffix[len("step/"):])
			if err != nil || n < 1 || n > numSteps || strconv.Itoa(n) != e.suffix[len("step/"):] {
				return nil, fmt.Errorf("%w: unknown step %q", ErrJournal, e.suffix)
			}
			st.steps[n-1] = true
		default:
			return nil, fmt.Errorf("%w: unknown marker %q", ErrJournal, e.suffix)
		}
	}
	var open []uint64
	for e, st := range out {
		for i := 1; i < numSteps; i++ {
			if st.steps[i] && !st.steps[i-1] {
				return nil, fmt.Errorf("%w: epoch %d records %s without %s", ErrJournal, e, Steps[i], Steps[i-1])
			}
		}
		if st.done {
			for _, s := range st.steps {
				if !s {
					return nil, fmt.Errorf("%w: epoch %d is complete with a step missing", ErrJournal, e)
				}
			}
		} else {
			open = append(open, e)
		}
	}
	if len(open) > 1 {
		return nil, fmt.Errorf("%w: %d epochs are all unfinished", ErrJournal, len(open))
	}
	return out, nil
}

// check compares a stored stage with the committed record and re-authenticates its bundle.
func (j *Journal) check(d *stageDisk, committed q3format.Claim) error {
	if d.claim() != committed {
		return fmt.Errorf("%w: epoch %d", ErrRecordMismatch, committed.Epoch)
	}
	if err := j.cfg.Bundles(bytes.Clone(d.Bundle), committed); err != nil {
		return errors.Join(ErrBundle, err)
	}
	return nil
}

// Install stages the committed record durably (once) and then carries every step through to the completion marker. It is the
// only way an activation begins. Calling it again for the same record and bundle resumes; for any other bundle or record of an
// epoch already journaled it refuses. The returned error is nil only after the completion marker is durable.
func (j *Journal) Install(ctx context.Context, committed q3format.Claim, bundle []byte) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(bundle) == 0 || len(bundle) > MaxBundle {
		return fmt.Errorf("%w: bundle of %d bytes", ErrBundle, len(bundle))
	}
	if err := j.cfg.Bundles(bytes.Clone(bundle), committed); err != nil {
		return errors.Join(ErrBundle, err)
	}
	states, err := j.load()
	if err != nil {
		return err
	}
	id := ActivationID(committed, bundle)
	if st := states[committed.Epoch]; st != nil {
		if !bytes.Equal(st.stage.ID, id[:]) {
			return fmt.Errorf("%w: epoch %d is journaled with another record or bundle", ErrRecordMismatch, committed.Epoch)
		}
		return j.finish(ctx, st)
	}
	for _, st := range states {
		if !st.done {
			return fmt.Errorf("%w: epoch %d", ErrBusy, st.stage.Epoch)
		}
	}
	d := stageDisk{Epoch: committed.Epoch, Start: committed.Start, BodyID: committed.BodyID[:], CommitID: committed.CommitID[:],
		PriorVersion: committed.PriorVersion, PriorID: committed.PriorID[:], ID: id[:], Bundle: bytes.Clone(bundle)}
	raw, err := bfttypes.Cbor.Marshal(d)
	if err != nil {
		return err
	}
	if err := j.cfg.DB.Write(key(committed.Epoch, "stage"), raw); err != nil {
		return err
	}
	return j.finish(ctx, &state{stage: &d})
}

// finish runs the steps not yet marked, in order, then verifies every store and writes the completion marker. A step is marked
// only after its Install returned, so a crash in between re-runs that one idempotent install.
func (j *Journal) finish(ctx context.Context, st *state) error {
	a := st.stage.activation()
	if st.done {
		return j.verifyAll(ctx, a)
	}
	for i, s := range Steps {
		if st.steps[i] {
			continue
		}
		if err := j.cfg.Components[s].Install(ctx, a); err != nil {
			return fmt.Errorf("q3install: install %s: %w", s, err)
		}
		if err := j.cfg.DB.Write(key(a.Claim.Epoch, "step/"+strconv.Itoa(int(s))), bytes.Clone(a.ID[:])); err != nil {
			return err
		}
		st.steps[i] = true
	}
	if err := j.verifyAll(ctx, a); err != nil {
		return err
	}
	if err := j.cfg.DB.Write(key(a.Claim.Epoch, "done"), bytes.Clone(a.ID[:])); err != nil {
		return err
	}
	st.done = true
	return nil
}

func (j *Journal) verifyAll(ctx context.Context, a Activation) error {
	for _, s := range Steps {
		if err := j.cfg.Components[s].Verify(ctx, a); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrStoreConflict, s, err)
		}
	}
	return nil
}

// Staged returns every journaled activation in epoch order, finished or not, exactly as stored. Its bundles are bytes the
// journal has already checked for shape and identity; they are authenticated only by the verified history that replays them, which
// is how a restart rebuilds that history from the retained proof bytes (the journal is the durable retention of the V3 lineage).
func (j *Journal) Staged() ([]Activation, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	states, err := j.load()
	if err != nil {
		return nil, err
	}
	epochs := make([]uint64, 0, len(states))
	for e := range states {
		epochs = append(epochs, e)
	}
	sort.Slice(epochs, func(a, b int) bool { return epochs[a] < epochs[b] })
	out := make([]Activation, 0, len(epochs))
	for _, e := range epochs {
		out = append(out, states[e].stage.activation())
	}
	return out, nil
}

// Recover is the startup pass. committed returns the verified history's record for an epoch. Every journaled epoch must be
// one the history holds with exactly the journaled record and a bundle that still authenticates; an unfinished installation is
// completed, a finished one must agree with every store. Any other outcome refuses startup. Nothing is erased on refusal.
func (j *Journal) Recover(ctx context.Context, committed func(epoch uint64) (q3format.Claim, bool)) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	states, err := j.load()
	if err != nil {
		return err
	}
	epochs := make([]uint64, 0, len(states))
	for e := range states {
		epochs = append(epochs, e)
	}
	sort.Slice(epochs, func(a, b int) bool { return epochs[a] < epochs[b] })
	for _, e := range epochs {
		st := states[e]
		c, ok := committed(e)
		if !ok {
			return fmt.Errorf("%w: epoch %d is not in the committed history", ErrRecordMismatch, e)
		}
		if err := j.check(st.stage, c); err != nil {
			return err
		}
		for i, s := range Steps { // a marked step is restored whether or not the completion marker was written: a crash between them loses only volatile state
			if r, ok := j.cfg.Components[s].(Restorer); ok && st.steps[i] {
				if err := r.Restore(ctx, st.stage.activation()); err != nil {
					return fmt.Errorf("q3install: restore %s: %w", s, err)
				}
			}
		}
		if err := j.finish(ctx, st); err != nil {
			return err
		}
	}
	return nil
}

// Gate is the signer admission check: nil only when the committed record's installation is journaled complete, with the same
// record, and every store still agrees. Signers and the successor's work must not start before it passes.
func (j *Journal) Gate(ctx context.Context, committed q3format.Claim) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	states, err := j.load()
	if err != nil {
		return err
	}
	st := states[committed.Epoch]
	if st == nil || !st.done {
		return fmt.Errorf("%w: epoch %d", ErrIncomplete, committed.Epoch)
	}
	if err := j.check(st.stage, committed); err != nil {
		return err
	}
	return j.verifyAll(ctx, st.stage.activation())
}
