// Package posretire is the proposer's side of the PoS exit: it finds the identities whose owner requested a Retirement (custody's
// RetirementRequested event), collects the EVM storage-proof witness of each against the EVM state a candidate proposal parent certified,
// and hands the leader the controls that are ready for exactly its parent (storage.RetirementProposer). The acceptance rules are not
// touched: every voter verifies the retained witness against the same parent tuple (storage/pos_control.go, certifiedState and
// VerifyRetirement). Logs are scheduling hints only; nothing here authorizes anything.
//
// Nothing blocks the consensus loop: Prepare starts bounded background work, Ready only reads the cache.
package posretire

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate"
)

// Bounds. Every one of them is a cap on work or memory, never a correctness rule.
const (
	MaxPending       = 256 // requests remembered
	MaxDone          = 1024
	MaxCache         = 64 // prepared controls retained
	MaxInflight      = 4  // proofs being collected at once
	MaxPerPrepare    = 4  // proofs started per candidate parent
	ProofBudget      = 5 * time.Second
	MaxScanRange     = 2000 // blocks per eth_getLogs
	Confirmations    = 8    // blocks behind the EVM head a log must be
	maxRootBlocks    = 256  // state root -> block hash memory (for quiet parents)
	MaxNegative      = 1024 // (parent, request) outcomes remembered as "not retirable at this parent"
	stateFileVersion = 1
)

// RequestedTopic is the topic of custody's RetirementRequested(uint64 indexed id, uint64 generation).
var RequestedTopic = [32]byte(crypto.Keccak256Hash([]byte("RetirementRequested(uint64,uint64)")))

// Key identifies one request: work is always keyed by (id, generation).
type Key = storage.RetirementKey

func less(k, o Key) bool { return k.ID < o.ID || k.ID == o.ID && k.Generation < o.Generation }

// Request is one RetirementRequested log.
type Request struct {
	Key
	Block uint64
}

// Chain is the execution client's side of the discovery: the head and the requests in a block range.
type Chain interface {
	Head(ctx context.Context) (uint64, error)
	Requests(ctx context.Context, from, to uint64) ([]Request, error)
}

// Proofs returns the eth_getProof source for one EVM block.
type Proofs func(blockHash [32]byte) evmstate.ProofSource

// Config wires a Service.
type Config struct {
	Deployment storage.PosDeployment
	Pins       evmstate.Pins
	Chain      Chain
	Proofs     Proofs
	// Build collects a witness (default evmstate.BuildRetirementWitness); a seam for tests.
	Build     func(ctx context.Context, src evmstate.ProofSource, pins evmstate.Pins, id, generation uint64) ([]byte, storage.RetirementFacts, error)
	StatePath string // the persisted cursor and request set
	Poll      time.Duration
	Log       *slog.Logger
	Now       func() time.Time
}

type entry struct {
	parent  storage.EVMParent
	key     Key
	control rctypes.PosControl
	witness []byte
	at      uint64 // insertion counter, for eviction
}

type pendingItem struct{ Key }

type persisted struct {
	Version int           `json:"version"`
	Cursor  uint64        `json:"cursor"`
	Pending []pendingItem `json:"pending"`
	Done    []Key         `json:"done"`
}

// Service implements storage.RetirementProposer.
type Service struct {
	cfg Config
	log *slog.Logger

	mu         sync.Mutex
	cursor     uint64
	pending    []pendingItem
	done       []Key
	cache      []*entry
	negative   []cacheKey // outcomes "not retirable at this parent", oldest first
	snap       []byte     // the newest state not yet written
	writing    bool
	flushWG    sync.WaitGroup
	inflight   map[cacheKey]struct{}
	roots      map[[32]byte][32]byte // state root -> the block hash that certified it
	rootsOrd   [][32]byte
	rotate     int // fairness: where the next Prepare starts
	lastServed Key // fairness: the request Ready served last
	counter    uint64
	slots      chan struct{}
	wg         sync.WaitGroup
}

type cacheKey struct {
	parent storage.EVMParent
	key    Key
}

var _ storage.RetirementProposer = (*Service)(nil)

// New opens the service, restoring the persisted cursor and requests. A state file that cannot be read is an error: starting from nothing
// would silently forget the requests.
func New(cfg Config) (*Service, error) {
	if cfg.Chain == nil || cfg.Proofs == nil || cfg.StatePath == "" {
		return nil, errors.New("posretire: a chain, a proof source and a state path are required")
	}
	if cfg.Build == nil {
		cfg.Build = evmstate.BuildRetirementWitness
	}
	if cfg.Poll <= 0 {
		cfg.Poll = 2 * time.Second
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Service{cfg: cfg, log: cfg.Log.With("component", "posretire"), inflight: map[cacheKey]struct{}{}, roots: map[[32]byte][32]byte{},
		slots: make(chan struct{}, MaxInflight)}
	raw, err := os.ReadFile(cfg.StatePath)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("posretire: reading %s: %w", cfg.StatePath, err)
	default:
		var p persisted
		if err := json.Unmarshal(raw, &p); err != nil || p.Version != stateFileVersion {
			return nil, fmt.Errorf("posretire: %s is not a version %d state file: %w", cfg.StatePath, stateFileVersion, err)
		}
		s.cursor, s.pending, s.done = p.Cursor, p.Pending, p.Done
	}
	return s, nil
}

// persistLocked snapshots the state for the single background writer; the caller holds s.mu and never waits for the disk (Ordered is called on
// the consensus loop). A write that fails, or a crash before it, only costs a rediscovery: the cursor on disk is older than the log, a
// request that was ended comes back and is ended again by the next committed observation (a repeated Retirement is a no-op in the executor).
func (s *Service) persistLocked() {
	raw, err := json.Marshal(persisted{Version: stateFileVersion, Cursor: s.cursor, Pending: s.pending, Done: s.done})
	if err != nil {
		s.log.Error("cannot encode the retirement requests", "error", err)
		return
	}
	s.snap = raw
	if s.writing {
		return
	}
	s.writing = true
	s.flushWG.Add(1)
	go s.writeLoop()
}

func (s *Service) writeLoop() {
	defer s.flushWG.Done()
	for {
		s.mu.Lock()
		raw := s.snap
		s.snap = nil
		if raw == nil {
			s.writing = false
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
		if err := writeFileAtomic(s.cfg.StatePath, raw); err != nil {
			s.log.Error("cannot persist the retirement requests; they are rediscovered from the log after a restart", "error", err)
		}
	}
}

// Flush waits until everything handed to the writer is on disk.
func (s *Service) Flush() { s.flushWG.Wait() }

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Pending implements storage.RetirementProposer: the requests waiting, oldest first.
func (s *Service) Pending() []Key {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Key, len(s.pending))
	for i, p := range s.pending {
		out[i] = p.Key
	}
	return out
}

func (s *Service) knownLocked(k Key) bool {
	return slices.ContainsFunc(s.pending, func(p pendingItem) bool { return p.Key == k }) || slices.Contains(s.done, k)
}

// Add remembers a request (idempotent). It reports false when the set is full.
func (s *Service) Add(k Key) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.knownLocked(k) {
		return true
	}
	if len(s.pending) >= MaxPending {
		return false
	}
	s.pending = append(s.pending, pendingItem{Key: k})
	s.persistLocked()
	return true
}

func (s *Service) removeLocked(k Key, markDone bool) {
	s.pending = slices.DeleteFunc(s.pending, func(p pendingItem) bool { return p.Key == k })
	s.cache = slices.DeleteFunc(s.cache, func(e *entry) bool { return e.key == k })
	if markDone && !slices.Contains(s.done, k) {
		s.done = append(s.done, k)
		if len(s.done) > MaxDone {
			s.done = s.done[len(s.done)-MaxDone:]
		}
	}
	s.persistLocked()
}

// Ordered implements storage.RetirementProposer: a committed Retirement ends the request.
func (s *Service) Ordered(id, generation uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := Key{ID: id, Generation: generation}
	if s.knownLocked(k) || slices.ContainsFunc(s.cache, func(e *entry) bool { return e.key == k }) {
		s.removeLocked(k, true)
	}
}

// Run polls the execution client for new requests until ctx ends. A failing poll is retried at the next tick and never stops the service.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(s.cfg.Poll)
	defer t.Stop()
	for {
		if err := s.Poll(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("retirement request discovery failed; retrying", "error", err)
		}
		select {
		case <-ctx.Done():
			s.wg.Wait()
			s.Flush()
			return
		case <-t.C:
		}
	}
}

// Poll scans the confirmed blocks after the cursor once.
func (s *Service) Poll(ctx context.Context) error {
	head, err := s.cfg.Chain.Head(ctx)
	if err != nil {
		return err
	}
	if head < Confirmations {
		return nil
	}
	to := head - Confirmations
	s.mu.Lock()
	from := s.cursor + 1
	s.mu.Unlock()
	if to < from {
		return nil
	}
	to = min(to, from+MaxScanRange-1)
	reqs, err := s.cfg.Chain.Requests(ctx, from, to)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	slices.SortFunc(reqs, func(a, b Request) int {
		switch {
		case a.Block != b.Block:
			return cmpU(a.Block, b.Block)
		case less(a.Key, b.Key):
			return -1
		case less(b.Key, a.Key):
			return 1
		}
		return 0
	})
	for _, r := range reqs {
		if s.knownLocked(r.Key) {
			continue
		}
		if len(s.pending) >= MaxPending {
			// the cursor stops before the first request that did not fit: it is scanned again once there is room
			s.cursor = max(s.cursor, r.Block-1)
			s.persistLocked()
			return fmt.Errorf("posretire: %d requests pending, the set is full", len(s.pending))
		}
		s.pending = append(s.pending, pendingItem{Key: r.Key})
		s.log.Info("retirement requested", "id", r.ID, "generation", r.Generation, "evmBlock", r.Block)
	}
	s.cursor = to
	s.persistLocked()
	return nil
}

func cmpU(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// blockHashFor returns the EVM block hash proofs for the parent are fetched at: the certified block's, or for a quiet parent (no block hash
// in the input record) the block that certified the same state root earlier. The control still names the parent's own (zero) hash.
func (s *Service) blockHashFor(parent storage.EVMParent) ([32]byte, bool) {
	if parent.BlockHash != ([32]byte{}) {
		if _, known := s.roots[parent.StateRoot]; !known {
			if len(s.rootsOrd) >= maxRootBlocks {
				delete(s.roots, s.rootsOrd[0])
				s.rootsOrd = s.rootsOrd[1:]
			}
			s.roots[parent.StateRoot] = parent.BlockHash
			s.rootsOrd = append(s.rootsOrd, parent.StateRoot)
		}
		return parent.BlockHash, true
	}
	h, ok := s.roots[parent.StateRoot]
	return h, ok
}

// Prepare implements storage.RetirementProposer.
func (s *Service) Prepare(parent storage.EVMParent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// always learn the root -> block mapping, even with nothing pending: a later quiet parent carries the same root
	fetchAt, ok := s.blockHashFor(parent)
	if len(s.pending) == 0 || !ok {
		return
	}
	started := 0
	n := len(s.pending)
	for i := 0; i < n && started < MaxPerPrepare; i++ {
		item := s.pending[(s.rotate+i)%n]
		ck := cacheKey{parent, item.Key}
		if _, busy := s.inflight[ck]; busy || s.cachedLocked(ck) || slices.Contains(s.negative, ck) {
			continue
		}
		select {
		case s.slots <- struct{}{}:
		default:
			return // MaxInflight proofs are being collected: the rest waits for a later parent
		}
		s.inflight[ck] = struct{}{}
		started++
		s.wg.Add(1)
		go s.collect(ck, fetchAt)
	}
	s.rotate = (s.rotate + started) % max(n, 1)
}

func (s *Service) cachedLocked(ck cacheKey) bool {
	return slices.ContainsFunc(s.cache, func(e *entry) bool { return e.parent == ck.parent && e.key == ck.key })
}

// collect builds the witness of one request against one parent, off the consensus loop.
func (s *Service) collect(ck cacheKey, fetchAt [32]byte) {
	defer s.wg.Done()
	started := s.cfg.Now()
	ctx, cancel := context.WithTimeout(context.Background(), ProofBudget)
	defer cancel()
	witness, facts, err := s.cfg.Build(ctx, s.cfg.Proofs(fetchAt), s.cfg.Pins, ck.key.ID, ck.key.Generation)

	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inflight, ck)
	<-s.slots
	if err != nil {
		s.log.Warn("retirement proof not collected", "id", ck.key.ID, "generation", ck.key.Generation, "parentRoot", fmt.Sprintf("%x", ck.parent.StateRoot), "error", err)
		return
	}
	idx := slices.IndexFunc(s.pending, func(p pendingItem) bool { return p.Key == ck.key })
	if idx < 0 {
		return // ended while the proof was collected
	}
	switch {
	case !facts.NotImported:
		// the registry retired the generation: complete (a generation only advances after its predecessor was retired, so a superseded
		// request ends here too)
		s.log.Info("retirement request complete (the generation is retired in the registry)", "id", ck.key.ID, "generation", ck.key.Generation)
		s.removeLocked(ck.key, true)
		return
	case !facts.Requested || !facts.NoLiveExposures || !facts.NoLotReferences || !facts.RecordsCaughtUp:
		// Not retirable at this parent. "Not requested" is expected whenever the certified parent lags the log (a stalled EVM certification
		// keeps the same old root for any number of rounds): the request stays pending however long that lasts, and the outcome is remembered
		// for this parent so it is not collected again for it.
		s.negative = append(s.negative, ck)
		if len(s.negative) > MaxNegative {
			s.negative = s.negative[len(s.negative)-MaxNegative:]
		}
		return
	case len(witness) > evmstate.MaxWitnessBytes:
		return
	}
	var data [96]byte
	binary.BigEndian.PutUint64(data[24:32], ck.key.ID)
	binary.BigEndian.PutUint64(data[56:64], ck.key.Generation)
	copy(data[64:], facts.RefDigest[:])
	c := rctypes.PosControl{
		Network: s.cfg.Deployment.RootNetwork, ChainID: s.cfg.Deployment.ChainID, Custody: s.cfg.Deployment.Custody,
		Op: rctypes.OpRetirement, Data: data[:], WitnessHash: sha256.Sum256(witness),
		Retire: &rctypes.RetireContext{EVMBlockHash: ck.parent.BlockHash, EVMStateRoot: ck.parent.StateRoot},
	}
	if err := c.Validate(); err != nil {
		s.log.Error("a prepared retirement is not a valid control", "id", ck.key.ID, "generation", ck.key.Generation, "error", err)
		return
	}
	s.counter++
	s.cache = append(s.cache, &entry{parent: ck.parent, key: ck.key, control: c, witness: witness, at: s.counter})
	if len(s.cache) > MaxCache {
		slices.SortFunc(s.cache, func(a, b *entry) int { return cmpU(a.at, b.at) })
		s.cache = s.cache[len(s.cache)-MaxCache:]
	}
	s.log.Info("retirement proof ready", "id", ck.key.ID, "generation", ck.key.Generation, "latencyMs", s.cfg.Now().Sub(started).Milliseconds(),
		"parentRoot", fmt.Sprintf("%x", ck.parent.StateRoot), "parentBlock", fmt.Sprintf("%x", ck.parent.BlockHash), "witnessBytes", len(witness))
}

// Ready implements storage.RetirementProposer.
func (s *Service) Ready(parent storage.EVMParent, max int) []storage.PreparedRetirement {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ready []*entry
	for _, e := range s.cache {
		if e.parent == parent {
			ready = append(ready, e)
		}
	}
	if len(ready) == 0 || max <= 0 {
		return nil
	}
	slices.SortFunc(ready, func(a, b *entry) int {
		if less(a.key, b.key) {
			return -1
		}
		if less(b.key, a.key) {
			return 1
		}
		return 0
	})
	// fairness: start after the identity served last, so a request that is always first does not starve the others when only max fit
	start := slices.IndexFunc(ready, func(e *entry) bool { return less(s.lastServed, e.key) })
	if start < 0 {
		start = 0
	}
	var out []storage.PreparedRetirement
	for i := 0; i < len(ready) && len(out) < max; i++ {
		e := ready[(start+i)%len(ready)]
		out = append(out, storage.PreparedRetirement{ID: e.key.ID, Generation: e.key.Generation, Control: e.control, Witness: e.witness})
		s.lastServed = e.key
	}
	return out
}
