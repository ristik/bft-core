// Package executortest provides a deterministic in-memory shardnode.Executor
// (for exercising the framework with no real execution layer behind it) and
// a conformance suite every Executor implementation should pass.
package executortest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/unicitynetwork/bft-core/shardnode"
)

// Fake is a deterministic, in-memory shardnode.Executor. Its block is
// H(parent ‖ number ‖ entries): no gas, no reorg, no persistence. Two
// independent Fake instances given the same head and the same entries
// produce byte-identical blocks — that determinism is the entire point, it
// is what lets the framework be proven correct without a real execution
// layer.
//
// Quiet rounds are first-class: Build with no queued entries returns a
// Block whose StateRoot and Hash are literally unchanged from head, not a
// re-hash of it, because docs/shard-protocol.md requires the framework be
// able to observe "state did not move" and produce a nil block hash — a
// value that merely happens to differ each round would defeat that.
//
// Entries queued with AddEntries are consumed by the next Build/Seal pair
// (leader side); a Fake driven only through Verify/Commit (follower side)
// never needs entries queued locally.
type Fake struct {
	mu sync.Mutex
	// genesis is fixed at construction and never moves, so GenesisBlock answers from
	// configuration the way a real client does rather than from anything that has happened.
	genesis shardnode.BlockRef
	head    shardnode.BlockRef

	// committed indexes blocks Verify has accepted but Commit has not yet
	// finalized, keyed by hash, so Commit (follower path) can find them.
	committed map[string]shardnode.Block

	pending [][]byte // entries queued for the next Build

	builds map[shardnode.BuildID]shardnode.Block
	nextID uint64
}

// New returns a Fake whose genesis state root is the all-zero hash — every
// instance constructed with New agrees on genesis without coordination.
func New() *Fake {
	genesisRoot := make(shardnode.Hash, 32)
	genesis := shardnode.BlockRef{Number: 0, Hash: nil, StateRoot: genesisRoot}
	return &Fake{
		genesis:   genesis,
		head:      genesis,
		committed: make(map[string]shardnode.Block),
		builds:    make(map[shardnode.BuildID]shardnode.Block),
	}
}

// AddEntries queues opaque entries to be included in the next block this
// instance builds.
func (f *Fake) AddEntries(entries ...[]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending = append(f.pending, entries...)
}

func (f *Fake) Head(_ context.Context) (shardnode.BlockRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.head, nil
}

func (f *Fake) GenesisBlock(_ context.Context) (shardnode.BlockRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.genesis, nil
}

func (f *Fake) Build(_ context.Context, p shardnode.RoundParams) (shardnode.BuildID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !sameHash(p.Parent.StateRoot, f.head.StateRoot) {
		return "", fmt.Errorf("fake executor: build on stale head %x, current head is %x", p.Parent.StateRoot, f.head.StateRoot)
	}

	entries := f.pending
	f.pending = nil

	var b shardnode.Block
	if len(entries) == 0 {
		// Quiet round: literally the same head, wrapped so the round driver
		// can tell the difference between "nothing to certify" and "genesis".
		b = shardnode.Block{
			Number:     f.head.Number,
			Hash:       f.head.Hash,
			StateRoot:  f.head.StateRoot,
			ParentHash: f.head.Hash,
			Raw:        nil,
			BlockSize:  0,
			StateSize:  0,
		}
	} else {
		number := f.head.Number + 1
		stateRoot, blockHash := computeRoots(f.head.StateRoot, number, entries)
		raw := encodeEntries(entries)
		b = shardnode.Block{
			Number:     number,
			Hash:       blockHash,
			StateRoot:  stateRoot,
			ParentHash: f.head.Hash,
			Raw:        raw,
			BlockSize:  uint64(len(raw)), // #nosec G115 -- test fixture, entries are small
			StateSize:  0,                // Fake does not model cumulative state size
		}
	}

	f.nextID++
	id := shardnode.BuildID(fmt.Sprintf("build-%d", f.nextID))
	f.builds[id] = b
	return id, nil
}

func (f *Fake) Seal(_ context.Context, id shardnode.BuildID) (shardnode.Block, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.builds[id]
	if !ok {
		return shardnode.Block{}, shardnode.ErrNotFound
	}
	delete(f.builds, id)
	return b, nil
}

// Verify handles both round outcomes. A quiet block — Build's own
// zero-entries output, whether produced by this instance as leader or
// received from another as follower — is recognized structurally (same
// number, same state root, no payload) rather than requiring the caller to
// say so out of band: any Executor's Verify must be able to make this call
// on its own, since round.go treats "quiet" purely as a root-chain-facing
// InputRecord property, not an Executor one.
// Verify ignores p: Fake has no round-derived parameters baked into its
// blocks (no timestamp, no fee recipient) to check against, unlike a real
// Executor such as engineapi, whose Verify recomputes and compares exactly
// those — see engineapi/params.go's Verify for the implementation this
// parameter exists for.
func (f *Fake) Verify(_ context.Context, b shardnode.Block, _ shardnode.RoundParams) (shardnode.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(b.Raw) == 0 && b.Number == f.head.Number && sameHash(b.StateRoot, f.head.StateRoot) {
		return shardnode.StatusValid, nil // quiet: a reaffirmation of head, nothing to commit later
	}

	if !sameHash(b.ParentHash, f.head.Hash) {
		return shardnode.StatusInvalid, nil
	}
	entries := decodeEntries(b.Raw)
	wantRoot, wantHash := computeRoots(f.head.StateRoot, f.head.Number+1, entries)
	if !sameHash(wantRoot, b.StateRoot) || !sameHash(wantHash, b.Hash) {
		return shardnode.StatusInvalid, nil
	}
	f.committed[string(b.Hash)] = b
	return shardnode.StatusValid, nil
}

func (f *Fake) Commit(_ context.Context, hash shardnode.Hash) (shardnode.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// IDEMPOTENT BY CONTRACT. Committing the block that is ALREADY canonical is a no-op that
	// returns VALID, not SYNCING.
	//
	// This fake used to delete the block on commit, so a second Commit of the same hash fell
	// through to the "not found" branch and reported SYNCING — an executor that had the block
	// claiming not to. Both the Executor contract (docs/adr/0001-executor-boundary.md decision 2:
	// "Commit must be idempotent and safe to call speculatively") and the recovery design
	// (docs/design/f6b-quiet-uc-recovery.md §5, "Commit on an already-canonical hash is a no-op
	// returning VALID, so repeating it is safe") require VALID, and a real client agrees:
	// forkchoiceUpdated to the current canonical head returns VALID.
	//
	// It matters because retry is built on it. #92's recovery path re-commits the anchor on every
	// certificate until it succeeds; against the old behaviour the first success made every later
	// attempt look like an unavailable payload. This is the same class of fake-versus-adapter
	// divergence that let #92 itself go unnoticed by a fake-only chaos suite.
	//
	// The len(hash) > 0 guard is load-bearing: sameHash treats two empty hashes as equal, so
	// without it Commit(nil) against a genesis head (whose Hash is nil) would report VALID —
	// turning the exact call #92 is about into an apparent success. An empty hash is never
	// canonical.
	if len(hash) > 0 && sameHash(f.head.Hash, hash) {
		return shardnode.StatusValid, nil
	}
	b, ok := f.committed[string(hash)]
	if !ok {
		return shardnode.StatusSyncing, nil
	}
	f.head = shardnode.BlockRef{Number: b.Number, Hash: b.Hash, StateRoot: b.StateRoot}
	delete(f.committed, string(hash))
	return shardnode.StatusValid, nil
}

// ForgetUncommitted drops every block that was Verified but never Committed, modelling an
// executor that no longer holds a payload it once accepted — a replaced datadir, a pruned
// non-canonical block, or a client that simply never received it. Distinguishing this from
// "the payload is right there, merely not canonical" is what issue #92 stage 1 needs, because
// the two cases have different recovery answers.
func (f *Fake) ForgetUncommitted() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.committed = map[string]shardnode.Block{}
}

// CommitSealed is the leader-side equivalent of Commit: after Seal, the
// leader already holds the Block value and doesn't need the hash-indexed
// lookup that the follower path (Verify, then Commit-by-hash) requires.
func (f *Fake) CommitSealed(b shardnode.Block) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.head = shardnode.BlockRef{Number: b.Number, Hash: b.Hash, StateRoot: b.StateRoot}
}

func sameHash(a, b shardnode.Hash) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return bytes.Equal(a, b)
}

func computeRoots(parentRoot shardnode.Hash, number uint64, entries [][]byte) (stateRoot, blockHash shardnode.Hash) {
	h := sha256.New()
	h.Write(parentRoot)
	var numBuf [8]byte
	binary.BigEndian.PutUint64(numBuf[:], number)
	h.Write(numBuf[:])
	for _, e := range entries {
		h.Write(e)
	}
	stateRoot = h.Sum(nil)

	hb := sha256.New()
	hb.Write([]byte("block"))
	hb.Write(stateRoot)
	blockHash = hb.Sum(nil)
	return stateRoot, blockHash
}

func encodeEntries(entries [][]byte) []byte {
	var buf bytes.Buffer
	for _, e := range entries {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(e))) // #nosec G115 -- test fixture, entries are small
		buf.Write(lenBuf[:])
		buf.Write(e)
	}
	return buf.Bytes()
}

func decodeEntries(raw []byte) [][]byte {
	var entries [][]byte
	for len(raw) >= 4 {
		n := binary.BigEndian.Uint32(raw[:4])
		raw = raw[4:]
		if uint32(len(raw)) < n {
			break
		}
		entries = append(entries, raw[:n])
		raw = raw[n:]
	}
	return entries
}
