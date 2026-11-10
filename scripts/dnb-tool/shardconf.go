package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/unicitynetwork/bft-go-base/types"
)

// Resource bounds of the shard-configuration set (#996). They bound memory and the work a miss can cause; they are not protocol limits.
const (
	maxConfFileBytes   = 1 << 20  // one configuration file
	maxConfRetained    = 32 << 20 // CBOR held in memory, the explicit configurations included
	maxConfScanBytes   = 64 << 20 // bytes read by one scan
	maxConfDirEntries  = 4096     // directory entries one scan examines, matching or not
	confDirChunk       = 256      // entries listed per ReadDir call
	confRescanEvery    = 10 * time.Second
	maxConfDiagnostics = 8 // decode failures logged per scan
)

// confFileName is a published shard epoch's configuration (rehearse.py writes it to a temporary name first and renames it into place).
var confFileName = regexp.MustCompile(`^shard-conf-[0-9]+\.json$`)

// errConfLimit marks a scan stopped by a resource bound: the directory holds more than the endpoint is configured to examine or keep.
var errConfLimit = errors.New("shard configuration resource limit")

// confSet holds the EVM shard configurations the endpoint proves under, each as its CBOR encoding keyed by that encoding's SHA-256 (the hash
// a UC's ShardConfHash names), never by file name or epoch. The explicit configurations are read at start; a directory (optional) is read at
// start and, when a lookup misses, again: at most once per rescanEvery, single-flight, bounded (count, per-file, per-scan and retained bytes).
// A hit never waits for a scan. Entries are never dropped: an old lock still needs its epoch's configuration.
type confSet struct {
	dir         string
	rescanEvery time.Duration
	now         func() time.Time
	maxEntries  int
	maxScan     int64
	maxRetained int64

	mu       sync.RWMutex
	pdrs     map[[32]byte][]byte
	retained int64
	loaded   map[string]struct{} // directory names accepted (published names are immutable)

	scanMu   sync.Mutex
	inFlight *confScan
	lastScan time.Time
	lastErr  error
	scans    int    // scans started (tests)
	hook     func() // runs at the start of each scan (tests hold a scan open with it)
}

type confScan struct {
	done chan struct{}
	err  error
}

func newConfSet(explicit []string, dir string) (*confSet, error) {
	s := &confSet{dir: dir, rescanEvery: confRescanEvery, now: time.Now, maxEntries: maxConfDirEntries, maxScan: maxConfScanBytes, maxRetained: maxConfRetained,
		pdrs: map[[32]byte][]byte{}, loaded: map[string]struct{}{}}
	pdrs, err := loadPDRs(explicit, dir != "")
	if err != nil {
		return nil, err
	}
	for h, pdr := range pdrs {
		if err := s.add(h, pdr); err != nil {
			return nil, err
		}
	}
	if dir != "" {
		// the first scan at start: a failure here (other than an absent directory) is a startup failure
		if err := s.rescan(context.Background()); err != nil {
			return nil, fmt.Errorf("--shard-conf-dir %s: %w", dir, err)
		}
	}
	return s, nil
}

// add keeps pdr under h unless held already; it refuses past the retained-bytes budget.
func (s *confSet) add(h [32]byte, pdr []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.pdrs[h]; ok {
		return nil
	}
	if s.retained+int64(len(pdr)) > s.maxRetained {
		return fmt.Errorf("%w: retaining %d more bytes would exceed %d", errConfLimit, len(pdr), s.maxRetained)
	}
	s.pdrs[h], s.retained = pdr, s.retained+int64(len(pdr))
	return nil
}

func (s *confSet) get(h [32]byte) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pdr, ok := s.pdrs[h]
	return pdr, ok
}

func (s *confSet) size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.pdrs)
}

// lookup is the configuration a certificate commits to. A malformed hash is an error (corruption, not a miss). A well-formed hash held by
// nothing after a successful (or throttled) rescan is errNotFound; a scan that failed, hit a resource bound or was cancelled is that error.
func (s *confSet) lookup(ctx context.Context, shardConfHash []byte) ([]byte, error) {
	var h [32]byte
	if len(shardConfHash) != len(h) {
		return nil, fmt.Errorf("the block's certificate names a malformed shard configuration hash (%d bytes)", len(shardConfHash))
	}
	copy(h[:], shardConfHash)
	if pdr, ok := s.get(h); ok {
		return pdr, nil
	}
	if s.dir != "" {
		err := s.rescan(ctx)
		if pdr, ok := s.get(h); ok {
			return pdr, nil
		}
		if err != nil {
			return nil, fmt.Errorf("looking for shard configuration %x: %w", h, err)
		}
	}
	return nil, fmt.Errorf("%w: none of the %d shard configurations held is the one the block's certificate commits to (%x)", errNotFound, s.size(), h)
}

// rescan runs one scan of the directory unless one ended less than rescanEvery ago (then that scan's error is returned again, so a failing
// directory is not scanned per request); a scan in flight is shared. Every caller, the one that started it included, waits on its own ctx;
// a cancelled caller returns ctx.Err() and the scan runs to its (bounded) end for the others.
func (s *confSet) rescan(ctx context.Context) error {
	s.scanMu.Lock()
	c := s.inFlight
	if c == nil {
		if !s.lastScan.IsZero() && s.now().Sub(s.lastScan) < s.rescanEvery {
			err := s.lastErr
			s.scanMu.Unlock()
			return err
		}
		c = &confScan{done: make(chan struct{})}
		s.inFlight = c
		s.scans++
		if !s.lastScan.IsZero() {
			log.Printf("shard configuration not held: rescanning %s", s.dir) // at most once per rescanEvery
		}
		hook := s.hook
		go func() {
			if hook != nil {
				hook()
			}
			err := s.scan()
			s.scanMu.Lock()
			c.err, s.inFlight, s.lastScan, s.lastErr = err, nil, s.now(), err
			s.scanMu.Unlock()
			close(c.done)
		}()
	}
	s.scanMu.Unlock()
	select {
	case <-c.done:
		return c.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// scan reads the configuration files not accepted before, one at a time. An absent directory is empty (before the first handoff). A file
// that does not read or decode is not marked, so the next scan tries it again; at most maxConfDiagnostics of them are logged per scan.
func (s *confSet) scan() error {
	d, err := os.Open(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer d.Close()
	examined, diagnostics := 0, 0
	var read int64
	for {
		entries, err := d.ReadDir(confDirChunk)
		for _, e := range entries {
			if examined++; examined > s.maxEntries {
				return fmt.Errorf("%w: the directory holds more than %d entries", errConfLimit, s.maxEntries)
			}
			name := e.Name()
			if !confFileName.MatchString(name) {
				continue
			}
			s.mu.RLock()
			_, done := s.loaded[name]
			s.mu.RUnlock()
			if done {
				continue
			}
			pdr, n, ferr := readConfFile(filepath.Join(s.dir, name), e)
			if read += n; read > s.maxScan {
				return fmt.Errorf("%w: one scan would read more than %d bytes", errConfLimit, s.maxScan)
			}
			if ferr != nil {
				if diagnostics++; diagnostics <= maxConfDiagnostics {
					log.Printf("shard configuration %s: %v (retried at the next scan)", name, ferr)
				}
				continue
			}
			h := sha256.Sum256(pdr)
			if err := s.add(h, pdr); err != nil {
				return err
			}
			log.Printf("shard configuration %s loaded: %x", name, h) // once per published file
			s.mu.Lock()
			s.loaded[name] = struct{}{}
			s.mu.Unlock()
		}
		if errors.Is(err, io.EOF) || (err == nil && len(entries) == 0) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// readConfFile reads one regular file (no symlink) of at most maxConfFileBytes, enforced while reading, and returns its configuration's
// CBOR encoding and the bytes read.
func readConfFile(path string, e os.DirEntry) ([]byte, int64, error) {
	if !e.Type().IsRegular() {
		return nil, 0, fmt.Errorf("not a regular file (%v)", e.Type())
	}
	// O_NOFOLLOW: a name replaced by a symlink between the listing and the open is refused, not followed
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- a name in the operator's configuration directory, matched by confFileName
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("not a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxConfFileBytes+1))
	n := int64(len(raw))
	if err != nil {
		return nil, n, err
	}
	if n > maxConfFileBytes {
		return nil, n, fmt.Errorf("larger than %d bytes", maxConfFileBytes)
	}
	pdr, err := encodeConf(raw)
	return pdr, n, err
}

// encodeConf decodes a full shard configuration (JSON) and returns its CBOR encoding, whose SHA-256 a UC's ShardConfHash names.
func encodeConf(raw []byte) ([]byte, error) {
	var conf types.PartitionDescriptionRecord
	if err := json.Unmarshal(raw, &conf); err != nil {
		return nil, err
	}
	return types.Cbor.Marshal(&conf)
}
