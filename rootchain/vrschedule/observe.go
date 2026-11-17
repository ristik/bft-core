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

type sourceFile struct {
	ResultID       hex.Bytes `json:"resultId"`
	EVMBlockHash   hex.Bytes `json:"evmBlockHash"`
	EVMBlockNumber uint64    `json:"evmBlockNumber"`
	CertRootRound  uint64    `json:"certRootRound"`
	OutputCommit   hex.Bytes `json:"outputCommit"`
	CertUCTime     uint64    `json:"certUcTime"`
}

// maxSources bounds the retained sources: VR has at most one open output, so a few suffice for the current and the previous intents.
const maxSources = 8

// Sources is the committed source of every result this root observed being published, first observation wins; persisted to a file so a
// restarted root keeps what it learned (a source the root never observed stays unavailable).
type Sources struct {
	mu    sync.RWMutex
	path  string
	order []vrschema.Word
	by    map[vrschema.Word]SourceEntry
}

// NewSources reads path (if it exists); an empty path keeps the sources in memory.
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
	var fs []sourceFile
	if err := json.Unmarshal(raw, &fs); err != nil {
		return nil, fmt.Errorf("vrschedule: %s: %w", path, err)
	}
	for _, f := range fs {
		if len(f.ResultID) != 32 || len(f.EVMBlockHash) != 32 || len(f.OutputCommit) != 32 {
			return nil, fmt.Errorf("vrschedule: %s: a malformed source", path)
		}
		r := vrschema.Word(f.ResultID)
		s.order = append(s.order, r)
		s.by[r] = SourceEntry{Source: vrhandoff.Source{ResultID: f.ResultID, EVMBlockHash: f.EVMBlockHash, EVMBlockNumber: f.EVMBlockNumber,
			CertRootRound: f.CertRootRound, OutputCommit: f.OutputCommit}, CertUCTime: f.CertUCTime}
	}
	return s, nil
}

// Get is R's committed source.
func (s *Sources) Get(r vrschema.Word) (SourceEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.by[r]
	return e, ok
}

// Record keeps the first source of R; a later observation never replaces it.
func (s *Sources) Record(e SourceEntry) (bool, error) {
	if len(e.ResultID) != 32 {
		return false, errors.New("vrschedule: a source without a result id")
	}
	r := vrschema.Word(e.ResultID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.by[r]; ok {
		return false, nil
	}
	s.by[r] = e
	s.order = append(s.order, r)
	for len(s.order) > maxSources {
		delete(s.by, s.order[0])
		s.order = s.order[1:]
	}
	return true, s.persist()
}

func (s *Sources) persist() error {
	if s.path == "" {
		return nil
	}
	fs := make([]sourceFile, 0, len(s.order))
	for _, r := range s.order {
		e := s.by[r]
		fs = append(fs, sourceFile{ResultID: e.ResultID, EVMBlockHash: e.EVMBlockHash, EVMBlockNumber: e.EVMBlockNumber, CertRootRound: e.CertRootRound,
			OutputCommit: e.OutputCommit, CertUCTime: e.CertUCTime})
	}
	raw, err := json.MarshalIndent(fs, "", " ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
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

// CertifiedEVM is the designated EVM shard's certified block in one committed root block.
type CertifiedEVM struct {
	RootRound, RootUCTime uint64
	BlockHash, StateRoot  [32]byte
	BlockNumber           uint64
}

// Reader reads VR at one certified EVM block: the output state proven against its state root and the served preimages of the open
// output, or nil when VR has no open Published output there.
type Reader interface {
	OpenOutput(ctx context.Context, blockHash, stateRoot [32]byte) (*vrhandoff.Output, error)
}

// Observer is stage 0: for every committed root block, in commit order, the designated EVM shard's certified block is read once (a
// block it already observed is skipped) and VR's open output there is cached. A result's committed source is the first certified block
// at which it is the open Published output, so it is recorded only when this process also observed the certified block before it, where
// R was not: a root that starts while R is already published never guesses its source (it keeps a persisted one, or has none and the
// intent stays unavailable to it).
type Observer struct {
	Reader  Reader
	Sources *Sources
	Outputs *Outputs
	Log     *slog.Logger

	mu     sync.Mutex
	last   [32]byte
	primed bool
	prev   vrschema.Word // the open Published output at the last observed block, zero when none
}

// Observe reads one committed root block's certified EVM block.
func (o *Observer) Observe(ctx context.Context, c CertifiedEVM) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if bytes.Equal(o.last[:], c.BlockHash[:]) {
		return nil
	}
	out, cached := o.Outputs.At(c.StateRoot)
	if !cached {
		var err error
		if out, err = o.Reader.OpenOutput(ctx, c.BlockHash, c.StateRoot); err != nil {
			return err
		}
		o.Outputs.Put(c.StateRoot, out)
	}
	o.last = c.BlockHash
	primed, prev := o.primed, o.prev
	o.primed, o.prev = true, vrschema.Word{}
	if out == nil {
		return nil
	}
	r := out.State.ResultID
	o.prev = r
	if !primed || prev == r {
		return nil
	}
	recorded, err := o.Sources.Record(SourceEntry{Source: vrhandoff.Source{ResultID: bytes.Clone(r[:]), EVMBlockHash: bytes.Clone(c.BlockHash[:]),
		EVMBlockNumber: c.BlockNumber, CertRootRound: c.RootRound, OutputCommit: bytes.Clone(out.State.Output.OutputCommit[:])}, CertUCTime: c.RootUCTime})
	if recorded && o.Log != nil {
		o.Log.Info("VR output published: source recorded", "result", fmt.Sprintf("%x", r[:8]), "evmBlock", c.BlockNumber, "certRootRound", c.RootRound)
	}
	return err
}
