package configuredadmission

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// prefixNet is a certified chain of blocks 1..n with the archive's copy of it (a provider journal that holds all of them, standing in for the
// immutable archive), and the node's own journal pruned to the frontier anchor at height base: the blocks up to base are gone from the journal,
// the blocks above it are retained (#843).
type prefixNet struct {
	refs      []shardnode.BlockRef
	uc        []*types.UnicityCertificate
	tr        []*certification.TechnicalRecord
	image     configuredprogress.JournalSnapshot
	served    JournalProvider
	archive   func(context.Context, shardnode.BlockRef, []byte) ([]shardnode.JournalFetchEntry, error)
	fetched   [][2]uint64 // (after, last) of each archive request
	journalCx configuredprogress.Context
}

func newPrefixNet(t *testing.T, n, base int) *prefixNet {
	t.Helper()
	chain, _, journalCtx, _ := adapterFixtureBlocks(t, n)
	limits := configuredprogress.JournalLimits{Candidates: 32, Observations: 32, Bytes: 16 << 20}
	s, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/archive.db", configuredprogress.Settings{Retain: 32})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	_, _, err = s.Initialize(context.Background(), journalCtx)
	require.NoError(t, err)
	require.NoError(t, s.EnableJournal(context.Background(), journalCtx, limits))
	boot, bootTR := journalBootstrap(t, chain)
	admitPeerObservation(t, s, journalCtx, boot, bootTR)
	p := &prefixNet{journalCx: journalCtx, served: JournalProvider{Store: s, Context: journalCtx, Limits: limits}}
	p.uc, p.tr = []*types.UnicityCertificate{boot}, []*certification.TechnicalRecord{bootTR}
	for i := 0; i <= n; i++ {
		b := chain.Blocks[i]
		p.refs = append(p.refs, shardnode.BlockRef{Number: b.Number, Hash: b.Hash.Bytes(), StateRoot: b.StateRoot.Bytes()})
	}
	for i := 1; i <= n; i++ {
		u, r := signPeerBlock(t, chain, i)
		p.uc, p.tr = append(p.uc, u), append(p.tr, r)
		b, prev := chain.Blocks[i], chain.Blocks[i-1]
		c := configuredprogress.JournalCandidate{Round: b.Round, Number: b.Number, ParentNumber: prev.Number, Hash: b.Hash.Bytes(), StateRoot: b.StateRoot.Bytes(), ParentHash: prev.Hash.Bytes(), ParentState: prev.StateRoot.Bytes(), Raw: []byte{byte(i)}, AuthorizingUC: p.uc[i-1], AuthorizingTR: p.tr[i-1]}
		require.NoError(t, s.PutJournalCandidate(context.Background(), journalCtx, limits, c))
		admitPeerObservation(t, s, journalCtx, u, r)
		if i > base {
			p.image.Candidates = append(p.image.Candidates, configuredprogress.JournalEntry{Certified: true, Candidate: c})
		}
	}
	p.image.Frontier = &configuredprogress.FrontierSnapshot{
		Anchor:      &frontier.Record{Height: uint64(base), Round: p.uc[base].GetRootRoundNumber(), Epoch: p.uc[base].GetRootEpoch(), StateRoot: [32]byte(p.refs[base].StateRoot), Subject: archive.Request{BlockHash: [32]byte(p.refs[base].Hash)}},
		ResultingUC: p.uc[base],
	}
	p.image.Observations = []configuredprogress.JournalObservation{{UC: p.uc[n], TargetHash: p.refs[n].Hash}}
	p.archive = func(ctx context.Context, after shardnode.BlockRef, target []byte) ([]shardnode.JournalFetchEntry, error) {
		entries, err := p.served.FetchJournal(ctx, shardnode.JournalFetchRequest{TargetHash: target, AfterHash: after.Hash})
		if err == nil {
			p.fetched = append(p.fetched, [2]uint64{after.Number, entries[len(entries)-1].Block.Number})
		}
		return entries, err
	}
	return p
}

// recovery is a coordinator over the pruned journal and an execution client that survived at height el (head = finalized), which holds the blocks 0..el.
func (p *prefixNet) recovery(el int) (*ExecutionRecovery, *replayExecutor) {
	known := map[string]bool{}
	for i := 0; i <= el; i++ {
		known[string(p.refs[i].Hash)] = true
	}
	e := &replayExecutor{head: p.refs[el], finalized: p.refs[el], refs: p.refs, known: known}
	r := &ExecutionRecovery{Executor: e, Gate: shardnode.NewFinalityGate(), Genesis: p.refs[0], Context: p.journalCx, FetchArchive: p.archive,
		Limits: RecoveryLimits{Blocks: 8, Bytes: 1024, Deadline: 3 * time.Second, Retries: 0}}
	r.snapshot = func(context.Context) (configuredprogress.JournalSnapshot, error) { return p.image, nil }
	return r, e
}

// The execution client came back below the pruned base: block 3 is covered by the frontier and gone from the journal, the client holds only 0..1.
// Recovery must replay 2 and 3 from the archive, execution only, then the retained 4 and 5 (today: finalized-branch conflict before anything is fetched).
func TestRecoveryReplaysPrunedPrefixFromArchive(t *testing.T) {
	p := newPrefixNet(t, 5, 3)
	r, e := p.recovery(1)
	head, err := r.Recover(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, p.refs[5], head)
	require.Equal(t, p.refs[5], e.head)
	require.Equal(t, p.refs[5], e.finalized)
	require.Equal(t, []uint64{2, 3, 4, 5}, e.verify, "the original payloads, parent first")
	require.Equal(t, [][2]uint64{{1, 3}}, p.fetched, "the archive is asked once, from the surviving finalized block up to the base")
	require.Len(t, p.image.Candidates, 2, "the replay writes nothing into the hot journal")
	// idempotent from the surviving state
	n := len(e.verify)
	_, err = r.Recover(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, e.verify, n)
}

// Control: with the client exactly at the base the same image recovers today, so the defect is "execution below the pruned base" and nothing else.
func TestRecoveryAtThePrunedBaseNeedsNoArchive(t *testing.T) {
	p := newPrefixNet(t, 5, 3)
	r, e := p.recovery(3)
	r.FetchArchive = func(context.Context, shardnode.BlockRef, []byte) ([]shardnode.JournalFetchEntry, error) {
		return nil, errors.New("the archive must not be asked")
	}
	head, err := r.Recover(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, p.refs[5], head)
	require.Equal(t, []uint64{4, 5}, e.verify)
}

// Missing history and a proven conflict are different classes: the first is retried with signing off, the second stops (errors.Is, not text).
func TestRecoveryPrefixErrorClasses(t *testing.T) {
	t.Run("archive record unavailable", func(t *testing.T) {
		p := newPrefixNet(t, 5, 3)
		r, e := p.recovery(1)
		r.FetchArchive = func(context.Context, shardnode.BlockRef, []byte) ([]shardnode.JournalFetchEntry, error) {
			return nil, fmt.Errorf("%w: block 3 is in no archive copy", ErrRecoveryUnavailable)
		}
		_, err := r.Recover(context.Background(), nil)
		require.ErrorIs(t, err, ErrRecoveryUnavailable)
		require.NotErrorIs(t, err, ErrRecoveryConflict)
		require.False(t, r.Terminal(err))
		require.Empty(t, e.verify)
		require.Empty(t, e.forkchoice, "nothing moves while history is missing")
		require.Equal(t, p.refs[1], e.finalized)
	})
	t.Run("no archive wired", func(t *testing.T) {
		p := newPrefixNet(t, 5, 3)
		r, e := p.recovery(1)
		r.FetchArchive = nil
		_, err := r.Recover(context.Background(), nil)
		require.ErrorIs(t, err, ErrRecoveryUnavailable)
		require.False(t, r.Terminal(err))
		require.Empty(t, e.verify)
	})
	t.Run("finalized block on another branch", func(t *testing.T) {
		p := newPrefixNet(t, 5, 3)
		r, e := p.recovery(1)
		fork := shardnode.BlockRef{Number: 1, Hash: p.refs[2].Hash, StateRoot: p.refs[1].StateRoot}
		e.head, e.finalized = fork, fork
		r.FetchArchive = func(context.Context, shardnode.BlockRef, []byte) ([]shardnode.JournalFetchEntry, error) {
			return nil, fmt.Errorf("%w: %w: archive chain passes height 1 without reaching it", ErrRecoveryInvalid, shardnode.ErrCertifiedChainForksAnchor)
		}
		_, err := r.Recover(context.Background(), nil)
		require.ErrorIs(t, err, ErrRecoveryConflict)
		require.ErrorIs(t, err, shardnode.ErrCertifiedChainForksAnchor)
		require.True(t, r.Terminal(err))
		require.Empty(t, e.verify)
		require.Empty(t, e.forkchoice, "a proven conflict never moves forkchoice")
		require.Equal(t, fork, e.finalized, "finality never retreats")
	})
	t.Run("archive entry the execution client refuses", func(t *testing.T) {
		p := newPrefixNet(t, 5, 3)
		r, e := p.recovery(1)
		e.invalid = 2
		_, err := r.Recover(context.Background(), nil)
		require.ErrorIs(t, err, ErrRecoveryConflict)
		require.Equal(t, p.refs[1], e.finalized)
	})
}

// The incident's second variant: the newest body is missing locally and a peer has it. Acquisition used to fail while reaching the retained
// ancestor (the same finalized-branch conflict, before any request); it must replay the pruned prefix first, then ask the peer.
func TestRecoveryPrefixThenPeerFetchOfTheMissingBody(t *testing.T) {
	p := newPrefixNet(t, 5, 3)
	p.image.Candidates = p.image.Candidates[:1] // block 4 retained, block 5's body missing
	p.image.Observations = []configuredprogress.JournalObservation{
		{UC: p.uc[4], TargetHash: p.refs[4].Hash},
		{UC: p.uc[5], TargetHash: p.refs[5].Hash, Unresolved: true},
	}
	t.Run("the peer has nothing yet: history is replayed, the rest is unavailable", func(t *testing.T) {
		r, e := p.recovery(1)
		var asked [][2]uint64
		r.Providers = []peer.ID{"peer"}
		inner := r.FetchArchive
		r.FetchArchive = func(ctx context.Context, after shardnode.BlockRef, target []byte) ([]shardnode.JournalFetchEntry, error) {
			if bytes.Equal(target, p.refs[5].Hash) {
				return nil, fmt.Errorf("%w: the newest block is not archived yet", ErrRecoveryUnavailable)
			}
			return inner(ctx, after, target)
		}
		r.fetch = func(_ context.Context, _ peer.ID, req shardnode.JournalFetchRequest) ([]shardnode.JournalFetchEntry, error) {
			asked = append(asked, [2]uint64{uint64(len(e.verify)), 0})
			require.Equal(t, p.refs[4].Hash, shardnode.Hash(req.AfterHash))
			require.Equal(t, p.refs[5].Hash, shardnode.Hash(req.TargetHash))
			return nil, fmt.Errorf("%w: peer holds no block 5", ErrRecoveryUnavailable)
		}
		_, err := r.Recover(context.Background(), nil)
		require.ErrorIs(t, err, ErrRecoveryUnavailable)
		require.NotErrorIs(t, err, ErrRecoveryConflict, "missing history is not a conflict")
		require.False(t, r.Terminal(err))
		require.Equal(t, []uint64{2, 3, 4}, e.verify, "the pruned prefix and the retained block were replayed before the peer was asked")
		require.Equal(t, [][2]uint64{{3, 0}}, asked)
		require.Equal(t, p.refs[4], e.head)
	})
	t.Run("the cause of missing history survives acquisition", func(t *testing.T) {
		r, e := p.recovery(1)
		r.Providers = []peer.ID{"peer"}
		r.fetch = func(context.Context, peer.ID, shardnode.JournalFetchRequest) ([]shardnode.JournalFetchEntry, error) {
			t.Fatal("no peer is asked while the pruned history cannot be replayed")
			return nil, nil
		}
		errReplicaDown := errors.New("every archive replica is down")
		r.FetchArchive = func(context.Context, shardnode.BlockRef, []byte) ([]shardnode.JournalFetchEntry, error) {
			return nil, fmt.Errorf("%w: %w", ErrRecoveryUnavailable, errReplicaDown)
		}
		_, err := r.Recover(context.Background(), nil)
		require.ErrorIs(t, err, ErrRecoveryUnavailable)
		require.ErrorIs(t, err, errReplicaDown, "health and logs must keep what was missing, not only that something was")
		require.False(t, r.Terminal(err))
		require.Empty(t, e.verify)
	})
	t.Run("a proven conflict found on the way is reported as one", func(t *testing.T) {
		r, e := p.recovery(1)
		r.Providers = []peer.ID{"peer"}
		r.fetch = func(context.Context, peer.ID, shardnode.JournalFetchRequest) ([]shardnode.JournalFetchEntry, error) {
			t.Fatal("no peer is asked once the finalized block is proven off the certified chain")
			return nil, nil
		}
		r.FetchArchive = func(context.Context, shardnode.BlockRef, []byte) ([]shardnode.JournalFetchEntry, error) {
			return nil, fmt.Errorf("%w: %w: archive chain misses the anchor", ErrRecoveryInvalid, shardnode.ErrCertifiedChainForksAnchor)
		}
		_, err := r.Recover(context.Background(), nil)
		require.ErrorIs(t, err, ErrRecoveryConflict)
		require.NotErrorIs(t, err, ErrRecoveryUnavailable, "health must be able to tell a proven conflict from missing history")
		require.True(t, r.Terminal(err))
		require.Empty(t, e.verify)
		require.Empty(t, e.forkchoice)
	})
}

// More shapes of the same gap: the surviving block is genesis; the execution head is ahead of its finalized block; the gap is longer than
// one recovery's budget (finality advances page by page and a fresh coordinator resumes); a lost Engine reply in the middle.
func TestRecoveryPrefixShapes(t *testing.T) {
	t.Run("the client came back at genesis", func(t *testing.T) {
		p := newPrefixNet(t, 5, 3)
		r, e := p.recovery(0)
		_, err := r.Recover(context.Background(), nil)
		require.NoError(t, err)
		require.Equal(t, []uint64{1, 2, 3, 4, 5}, e.verify)
		require.Equal(t, p.refs[5], e.finalized)
	})
	t.Run("head ahead of finalized, both below the base", func(t *testing.T) {
		p := newPrefixNet(t, 5, 3)
		r, e := p.recovery(1)
		e.head = p.refs[2]
		e.known[string(p.refs[2].Hash)] = true
		_, err := r.Recover(context.Background(), nil)
		require.NoError(t, err)
		require.Equal(t, p.refs[5], e.head)
		require.Equal(t, p.refs[5], e.finalized)
	})
	t.Run("a gap longer than one call resumes from the committed page, also after a restart", func(t *testing.T) {
		p := newPrefixNet(t, 7, 6)
		r, e := p.recovery(1)
		r.Limits.Blocks = 3
		_, err := r.Recover(context.Background(), nil)
		require.ErrorIs(t, err, ErrRecoveryUnavailable)
		require.False(t, r.Terminal(err), "running out of one call's blocks is progress, not the terminal budget")
		require.NotErrorIs(t, err, ErrRecoveryBudget)
		require.Equal(t, []uint64{2, 3, 4}, e.verify)
		require.Equal(t, p.refs[4], e.finalized, "finality advanced to the page's end")
		// the shard restarts: a fresh coordinator continues from what the client holds
		r2, _ := p.recovery(4)
		r2.Executor = e
		r2.Limits.Blocks = 3
		head, err := r2.Recover(context.Background(), nil)
		require.NoError(t, err)
		require.Equal(t, p.refs[7], head)
		require.Equal(t, []uint64{2, 3, 4, 5, 6, 7}, e.verify)
		require.Equal(t, [][2]uint64{{1, 6}, {4, 6}}, p.fetched)
	})
	t.Run("a lost Engine reply in the middle of the replay", func(t *testing.T) {
		p := newPrefixNet(t, 5, 3)
		r, e := p.recovery(1)
		r.Limits.Retries = 1
		e.lostReply = 3
		_, err := r.Recover(context.Background(), nil)
		require.NoError(t, err)
		require.Equal(t, p.refs[5], e.head)
	})
	t.Run("a gap longer than the archive's single request goes through the catch-up plan", func(t *testing.T) {
		p := newPrefixNet(t, 7, 6)
		r, e := p.recovery(1)
		r.Limits.Blocks = 8
		r.FetchArchive = func(context.Context, shardnode.BlockRef, []byte) ([]shardnode.JournalFetchEntry, error) {
			return nil, fmt.Errorf("%w: suffix longer than one recovery", ErrRecoveryUnavailable)
		}
		cu := &fakeCatchUp{net: p}
		r.ArchiveCatchUp = cu
		head, err := r.Recover(context.Background(), nil)
		require.NoError(t, err)
		require.Equal(t, p.refs[7], head)
		require.Equal(t, []uint64{2, 3, 4, 5, 6, 7}, e.verify)
		require.True(t, cu.dropped, "a consumed plan is dropped")
	})
}

// fakeCatchUp serves the prefix net as a long-catch-up plan: joined at once, one page of up to max entries from the asked block.
type fakeCatchUp struct {
	net     *prefixNet
	dropped bool
}

func (f *fakeCatchUp) Walk(context.Context, shardnode.BlockRef, []byte, time.Time) (bool, int, error) {
	return true, 5, nil
}
func (f *fakeCatchUp) Live(shardnode.BlockRef) bool { return true }
func (f *fakeCatchUp) Page(ctx context.Context, from shardnode.BlockRef, max int) ([]shardnode.JournalFetchEntry, int, error) {
	entries, err := f.net.served.FetchJournal(ctx, shardnode.JournalFetchRequest{TargetHash: f.net.refs[6].Hash, AfterHash: from.Hash})
	if err != nil {
		return nil, 0, err
	}
	above := len(entries)
	if len(entries) > max {
		entries = entries[:max]
	}
	return entries, above, nil
}
func (f *fakeCatchUp) Drop()                                      { f.dropped = true }
func (f *fakeCatchUp) AdvanceFrontier(context.Context, int) error { return nil }
