package vrschedule

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// SourceEntry is stage 0 of one result as committed history fixes it: the first EVM block certified in the committed root chain at which
// R is VR's open Published output, the round and committed UC time of the committed root block whose commit first certified it.
type SourceEntry struct {
	vrhandoff.Source
	CertUCTime uint64
}

// sourcesFileV3 is the persisted form: versioned, verified heights only. Version 3 records only an EVM block number that was verified
// against its certified header. Files of earlier builds (version 1, a bare array of shard rounds; version 2, which could carry an unverified
// fetched height) are REFUSED at startup, never discarded, backed up or migrated: the VT-07 build requires a fresh generation.
type sourcesFileV3 struct {
	Version int          `json:"version"`
	Sources []sourceFile `json:"sources"`
}

type sourceFile struct {
	ResultID       hex.Bytes `json:"resultId"`
	EVMBlockHash   hex.Bytes `json:"evmBlockHash"`
	EVMBlockNumber uint64    `json:"evmBlockNumber"`
	CertRootRound  uint64    `json:"certRootRound"`
	OutputCommit   hex.Bytes `json:"outputCommit"`
	CertUCTime     uint64    `json:"certUcTime"`
}

// sourcesVersion is the on-disk version this build writes and reads.
const sourcesVersion = 3

// ErrLegacySources is the refusal to start over a sources file of a pre-VT-07 build.
var ErrLegacySources = errors.New("vr-sources.json was written by a pre-VT-07 build; this build requires a fresh generation (upgrading a running generation is unsupported: regenerate)")

// maxSources bounds the retained sources: VR has at most one open output, so a few suffice for the current and the previous intents.
const maxSources = 8

// Sources is the committed source of every result this root observed being published, first observation wins; persisted to a file so a
// restarted root keeps what it learned (a source the root never observed stays unavailable). The file is trusted as this root's own record:
// an entry cannot be re-validated on load (that needs the EVM state of every certified block before it). Since the observer only records
// from an unbroken run, a wrong entry needs a tampered or foreign file; removing the file (or the entry) makes the result unavailable here,
// never wrong. The order and the map change together, under one lock, in one helper (insertLocked).
type Sources struct {
	mu    sync.RWMutex
	path  string
	order []vrschema.Word
	by    map[vrschema.Word]SourceEntry
}

// NewSources reads path (if it exists); an empty path keeps the sources in memory. A file of version 1 or 2 makes it fail with
// ErrLegacySources: no file at all is fine, as on a fresh generation.
func NewSources(path string) (*Sources, error) {
	s := &Sources{path: path, by: map[vrschema.Word]SourceEntry{}}
	if path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- the root's own state file
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if t := bytes.TrimSpace(raw); len(t) > 0 && t[0] == '[' {
		return nil, fmt.Errorf("vrschedule: %s: %w", path, ErrLegacySources) // version 1: a bare array
	}
	var head struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, fmt.Errorf("vrschedule: %s: %w", path, err)
	}
	if head.Version != sourcesVersion {
		return nil, fmt.Errorf("vrschedule: %s: version %d: %w", path, head.Version, ErrLegacySources)
	}
	var v3 sourcesFileV3
	if err := json.Unmarshal(raw, &v3); err != nil {
		return nil, fmt.Errorf("vrschedule: %s: %w", path, err)
	}
	for _, f := range v3.Sources {
		if len(f.ResultID) != 32 || len(f.EVMBlockHash) != 32 || len(f.OutputCommit) != 32 || f.CertRootRound == 0 {
			return nil, fmt.Errorf("vrschedule: %s: a malformed source", path)
		}
		r := vrschema.Word(f.ResultID)
		s.order = append(s.order, r)
		s.by[r] = SourceEntry{Source: vrhandoff.Source{ResultID: f.ResultID, EVMBlockHash: f.EVMBlockHash, EVMBlockNumber: f.EVMBlockNumber,
			CertRootRound: f.CertRootRound, OutputCommit: f.OutputCommit}, CertUCTime: f.CertUCTime}
	}
	return s, nil
}

func mustSourcesJSON(fs []sourceFile) []byte {
	if fs == nil {
		fs = []sourceFile{}
	}
	raw, err := json.MarshalIndent(sourcesFileV3{Version: sourcesVersion, Sources: fs}, "", " ")
	if err != nil {
		panic(err) // plain structs: cannot fail
	}
	return raw
}

// Get is R's committed source.
func (s *Sources) Get(r vrschema.Word) (SourceEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.by[r]
	return e, ok
}

// Record keeps the first source of R; a later observation never replaces it. The source is kept only once it is durable: a failed write
// changes nothing (sol's review of #1185), so the caller's retry of the same transition records it.
func (s *Sources) Record(e SourceEntry) (bool, error) {
	if len(e.ResultID) != 32 || e.CertRootRound == 0 {
		return false, errors.New("vrschedule: a source without a result id or a certifying round")
	}
	r := vrschema.Word(e.ResultID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.by[r]; ok {
		return false, nil
	}
	if err := s.insertLocked(r, e); err != nil {
		return false, err // nothing was added
	}
	return true, nil
}

// insertLocked adds e as the newest source, evicts the oldest beyond maxSources, writes the file, and only then updates the order and the
// map together: a failed write changes nothing, and memory and disk never disagree. The caller holds s.mu for writing.
func (s *Sources) insertLocked(r vrschema.Word, e SourceEntry) error {
	order := append(append([]vrschema.Word(nil), s.order...), r)
	evicted := map[vrschema.Word]bool{}
	for len(order) > maxSources {
		evicted[order[0]] = true
		order = order[1:]
	}
	if err := s.persist(order, func(x vrschema.Word) SourceEntry {
		if x == r {
			return e
		}
		return s.by[x]
	}); err != nil {
		return err
	}
	s.by[r] = e
	for x := range evicted {
		delete(s.by, x)
	}
	s.order = order
	return nil
}

func (s *Sources) persist(order []vrschema.Word, by func(vrschema.Word) SourceEntry) error {
	if s.path == "" {
		return nil
	}
	fs := make([]sourceFile, 0, len(order))
	for _, r := range order {
		e := by(r)
		fs = append(fs, sourceFile{ResultID: e.ResultID, EVMBlockHash: e.EVMBlockHash, EVMBlockNumber: e.EVMBlockNumber, CertRootRound: e.CertRootRound,
			OutputCommit: e.OutputCommit, CertUCTime: e.CertUCTime})
	}
	return writeDurable(s.path, mustSourcesJSON(fs))
}

// writeDurable replaces path with data atomically and durably: the data is synced in a temporary file, renamed over path, and the directory
// is synced, so a crash leaves the old file or the new one, never a torn one.
func writeDurable(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- the root's own state file
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- the root's own home
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

// maxOutputs bounds the cached outputs by certified state root.
const maxOutputs = 64

// Outputs caches VR's open output at certified EVM state roots: a verified output, or nil where VR has no open Published output.
type Outputs struct {
	mu    sync.RWMutex
	order [][32]byte
	by    map[[32]byte]*vrhandoff.Output
}

func NewOutputs() *Outputs { return &Outputs{by: map[[32]byte]*vrhandoff.Output{}} }

// At is the cached output at a certified state root; ok is false when that root was never observed.
func (o *Outputs) At(root [32]byte) (*vrhandoff.Output, bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	v, ok := o.by[root]
	return v, ok
}

func (o *Outputs) Put(root [32]byte, v *vrhandoff.Output) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.by[root]; !ok {
		o.order = append(o.order, root)
	}
	o.by[root] = v
	for len(o.order) > maxOutputs {
		delete(o.by, o.order[0])
		o.order = o.order[1:]
	}
}

// CertifiedEVM is the designated EVM shard's certified block in one committed root block (RootRound, its parent ParentRound, its UC
// time RootUCTime).
type CertifiedEVM struct {
	RootRound, ParentRound, RootUCTime uint64
	BlockHash, StateRoot               [32]byte
	// ShardRound is the certified block's shard round (IR.RoundNumber). It is NOT an EVM block height (a skipped shard round makes the two
	// differ): it is a label for logs. Source.EVMBlockNumber is the true height, resolved by BlockHash (HeaderReader). Every read is by BlockHash.
	ShardRound uint64
}

// Reader reads VR at one certified EVM block: the output state proven against its state root and the served preimages of the open
// output, or nil when VR has no open Published output there.
type Reader interface {
	OpenOutput(ctx context.Context, blockHash, stateRoot [32]byte) (*vrhandoff.Output, error)
}

// HeaderReader is the read of a certified block's true EVM number by its hash (RPC implements it, verifying the header's hash). A reader
// without it records no source: the shard round is never recorded as a block number.
type HeaderReader interface {
	HeaderNumber(ctx context.Context, blockHash [32]byte) (uint64, error)
}

// QueuedReader is the optional read of the ScheduleActivation changes VR still holds at a certified block, bound into an output or not
// (RPC implements it): the warning's source before any binding.
type QueuedReader interface {
	QueuedSchedules(ctx context.Context, blockHash [32]byte) ([]vrschema.Activation, error)
}

// QueuedEvery is the least time between two reads of VR's queued changes (they change at governance speed, never per round).
const QueuedEvery = 10 * time.Second

// Observer is stage 0: for every committed root block, in commit order, the designated EVM shard's certified block is read and VR's open
// output there is cached. A result's committed source is the first certified block at which it is the open Published output, so it is
// recorded only from an unbroken run of observations: each observed committed block must be the child of the previously observed one
// (ParentRound), and the block before the recording one must have been observed without R. Any gap (a read the worker gave up on, a batch
// the queue dropped, a recovery that jumped to a peer's head, a restart, an epoch boundary) breaks the run, so a first publication that
// fell into a gap leaves R without a source here (unavailable), never with a later, wrong one.
type Observer struct {
	Reader  Reader
	Sources *Sources
	Outputs *Outputs
	Log     *slog.Logger
	// OnPending, when set, receives the ScheduleActivation changes bound into the open output of every observed block (as activations in
	// state Active, E and T as queued; none when there is no open output): the root's early warning (design section 7.4). It is telemetry
	// only: nothing is enforced from it, and a change not yet bound into an output is not visible to a root.
	OnPending func([]vrschema.Activation)
	// SyncQueued reads the queued changes inside Observe (tests); production reads them in the background, never delaying the run.
	SyncQueued bool
	queuedAt   time.Time
	queuedBusy bool
	boundNow   []vrschema.Activation
	queuedNow  []vrschema.Activation // the last read of VR's queued changes: reported with every observation until the next read

	mu        sync.Mutex
	primed    bool
	lastRound uint64        // the round of the last committed block observed in the current run
	prev      vrschema.Word // the open Published output at the last observed block, zero when none
}

// Observe reads one committed root block's certified EVM block. A failed read observes nothing: retrying the same block continues the
// run, and giving it up breaks the run at the next block (whose parent was not observed).
func (o *Observer) Observe(ctx context.Context, c CertifiedEVM) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	primed, lastRound := o.primed, o.lastRound
	continuous := primed && c.RootRound > 0 && c.ParentRound == lastRound
	out, cached := o.Outputs.At(c.StateRoot)
	if !cached {
		var err error
		if out, err = o.Reader.OpenOutput(ctx, c.BlockHash, c.StateRoot); err != nil {
			// nothing is observed: the worker retries this very block (its execution client may not hold it yet); a block it gives up on is
			// a gap the next block's parent round shows
			return err
		}
		o.Outputs.Put(c.StateRoot, out)
	}
	prev := o.prev
	o.primed, o.lastRound, o.prev = true, c.RootRound, vrschema.Word{}
	if o.OnPending != nil {
		o.boundNow = PendingSchedules(out)
		o.OnPending(o.merged())
		o.observeQueued(ctx, c.BlockHash)
	}
	if out == nil {
		return nil
	}
	r := out.State.ResultID
	o.prev = r
	if !continuous && prev != r && o.Log != nil {
		o.Log.Info("VR output published outside an unbroken observation run: no source recorded", "result", fmt.Sprintf("%x", r[:8]),
			"shardRound", c.ShardRound, "rootRound", c.RootRound, "parentRound", c.ParentRound, "lastRound", lastRound, "primed", primed)
	}
	if !continuous || prev == r {
		return nil
	}
	// the true EVM block number of the first certified block publishing R, from its header by hash. An unavailable header observes nothing:
	// the run is restored and the worker retries this very block, exactly as for a source that is not durable
	hr, ok := o.Reader.(HeaderReader)
	if !ok {
		o.primed, o.lastRound, o.prev = primed, lastRound, prev
		return errors.New("vrschedule: the reader cannot resolve a certified block's number: no source is recorded with a shard round")
	}
	number, herr := hr.HeaderNumber(ctx, c.BlockHash)
	if herr != nil {
		o.primed, o.lastRound, o.prev = primed, lastRound, prev
		return herr
	}
	recorded, err := o.Sources.Record(SourceEntry{Source: vrhandoff.Source{ResultID: bytes.Clone(r[:]), EVMBlockHash: bytes.Clone(c.BlockHash[:]),
		EVMBlockNumber: number, CertRootRound: c.RootRound, OutputCommit: bytes.Clone(out.State.Output.OutputCommit[:])}, CertUCTime: c.RootUCTime})
	if err != nil {
		// not durable: this block is not observed (the store kept nothing), so the worker's retry of it records the same first source
		o.primed, o.lastRound, o.prev = primed, lastRound, prev
		return err
	}
	if recorded && o.Log != nil {
		o.Log.Info("VR output published: source recorded", "result", fmt.Sprintf("%x", r[:8]), "shardRound", c.ShardRound, "certRootRound", c.RootRound)
	}
	return nil
}

// PendingSchedules are the ScheduleActivation changes bound into an output, as Active entries (the warning's view of what the next
// handoff may commit); nil for no output. Verdicts are not known yet, so a change the fold will reject is included: telemetry only.
func PendingSchedules(out *vrhandoff.Output) []vrschema.Activation {
	if out == nil {
		return nil
	}
	var res []vrschema.Activation
	for _, c := range out.Changes {
		if uint8(c.Kind) != vrschema.KindScheduleActivation {
			continue
		}
		s, err := vrschema.DecodeSchedule(c.Payload)
		if err != nil {
			continue
		}
		res = append(res, vrschema.Activation{RuleID: s.RuleID, ReleaseDigest: s.ReleaseDigest, RootEpoch: s.RootEpoch, NotBeforeUcTime: s.NotBeforeUcTime,
			State: vrschema.ActActive, ChangeID: c.ID})
	}
	return res
}

// observeQueued reads VR's queued ScheduleActivation changes at the certified block (at most once per QueuedEvery, one read at a time) and
// reports them with the changes bound into the open output: a change still Queued, with no open output at all, is warned of (design 7.4).
// Telemetry only: a failed read changes nothing.
func (o *Observer) observeQueued(ctx context.Context, blockHash [32]byte) {
	qr, ok := o.Reader.(QueuedReader)
	if !ok || o.queuedBusy || time.Since(o.queuedAt) < QueuedEvery {
		return
	}
	o.queuedAt, o.queuedBusy = time.Now(), true
	read := func(ctx context.Context) {
		qs, err := qr.QueuedSchedules(ctx, blockHash)
		o.mu.Lock()
		o.queuedBusy = false
		if err == nil {
			o.queuedNow = qs
		}
		merged := o.merged()
		o.mu.Unlock()
		if err != nil {
			if o.Log != nil {
				o.Log.Debug("VR queued schedules not read", "error", err)
			}
			return
		}
		o.OnPending(merged)
	}
	if o.SyncQueued {
		o.mu.Unlock()
		read(ctx)
		o.mu.Lock()
		return
	}
	go read(context.WithoutCancel(ctx))
}

// merged is the changes bound into the open output and the queued ones, each change once (by id). The caller holds o.mu.
func (o *Observer) merged() []vrschema.Activation {
	seen := map[uint64]bool{}
	var out []vrschema.Activation
	for _, a := range append(append([]vrschema.Activation(nil), o.boundNow...), o.queuedNow...) {
		if !seen[a.ChangeID] {
			seen[a.ChangeID] = true
			out = append(out, a)
		}
	}
	return out
}
