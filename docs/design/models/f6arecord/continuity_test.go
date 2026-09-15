package f6arecord

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/registryproof"
	bfttypes "github.com/unicitynetwork/bft-go-base/types"
)

/*
Currency: readiness for B's child after the record for B is durable-ready (review of #159).

The record for B is immutable and names B. The certificate this process currently holds need not name B:
a quiet round certifies no block, carries B's state, and advances the partition round, while B stays the
execution parent. Requiring the held certificate to be B's own revoked readiness at the first quiet
successor, which is the quiet-tail stall #92 fixed.

So currency is established by authenticated CONTINUITY from the record's certificate to the held one,
with the accepted #92 rules (shardnode/anchorevidence.go VerifyAnchorEvidence,
docs/design/f6b-quiet-tail-anchor-recovery.md §2):

  - every certificate authenticates, is for this configuration, and is in the source's shard epoch;
  - every technical record is the one its certificate commits to;
  - each certificate is the round its predecessor's technical record ASSIGNED, never round+1;
  - a certificate for the round just accepted is a repeat only with an identical input record and a
    strictly later root round, and supersedes the assignment only;
  - every certificate after the source is quiet at the source's state;
  - the chain ends at the held certificate: same partition round, same input record (root round and
    signatures excluded), and the held certificate passes the same checks;
  - the chain is bounded.

State equality alone is never enough, and no unsigned counter is consulted.

RETAINED OR REACQUIRED. The record does not hold continuity and cannot attest to it: a stored chain replays
exactly as a stored record does. In a running process the chain is the certificates this process observed
(shardnode continuityState). After a restart it is reacquired as #92 anchor evidence ending at the
certificate the restarted process holds. Persisting observed links is outside this contract.

For the configuration-bound genesis record, the same chain rules apply from the genesis certificate
(which names no block), and #153 §7.3 E1 to E4 decide eligibility for the round the held certificate
assigns.
*/

// link is one certificate with the technical record bound to it.
type link struct {
	cert certificate
	tr   technicalRecord
}

// maxContinuityLinks mirrors shardnode.DefaultAnchorEvidenceLimits.MaxCertificates, the source included.
const maxContinuityLinks = 512

var (
	errContinuityGap  = errors.New("continuity: a certificate is not the round its predecessor assigned")
	errNotQuiet       = errors.New("continuity: a certificate after the source is not quiet at the source's state")
	errUnconnected    = errors.New("continuity: the chain does not reach the held certificate's round")
	errConflict       = errors.New("continuity: the chain and the held certificate disagree about the same round")
	errCandidateSplit = errors.New("continuity: two certificates in the chain disagree about the same round")
	errEpochChange    = errors.New("continuity: the chain crosses a shard epoch")
	errExhausted      = errors.New("continuity: the chain exceeds its bound")
)

func (h *harness) issue(c certificate, tr technicalRecord) {
	if h.trByDigest == nil {
		h.trByDigest = map[string]technicalRecord{}
	}
	h.signed[c.digest()] = true
	h.trByDigest[string(tr.digest())] = tr
}

// verifyContinuity checks the chain from source through tail to held.
func (h *harness) verifyContinuity(source link, tail []link, held link) error {
	if len(tail)+1 > maxContinuityLinks {
		return fmt.Errorf("%w: %d certificates, bound %d", errExhausted, len(tail)+1, maxContinuityLinks)
	}
	check := func(l link) error {
		c := l.cert
		if c.NetworkID != h.cfg.context.NetworkID || c.PartitionID != h.cfg.context.PartitionID ||
			!bytes.Equal(c.ShardID, h.cfg.context.ShardID) || !bytes.Equal(c.ShardConfHash, h.cfg.context.FullShardConfHash) {
			return errWrongContext
		}
		if err := h.cfg.authenticate(c); err != nil {
			return fmt.Errorf("%w: %v", errCertificate, err)
		}
		// After authentication, as in #92: only a genuine certificate may say anything about epochs.
		if c.Epoch != source.cert.Epoch {
			return fmt.Errorf("%w: source epoch %d, certificate epoch %d", errEpochChange, source.cert.Epoch, c.Epoch)
		}
		if !bytes.Equal(l.tr.digest(), c.TRHash) {
			return errTechnicalRecord
		}
		return nil
	}
	// The source is the record's own certificate and technical record, already authenticated, checked against
	// configuration and bound by verifyRecord on reload, which readyWith always runs first.
	state := source.cert.StateHash
	expected := source.tr.Round
	last := source.cert
	for i, l := range tail {
		if err := check(l); err != nil {
			return fmt.Errorf("link %d: %w", i, err)
		}
		c := l.cert
		if c.PartitionRound == last.PartitionRound {
			if !bytes.Equal(c.inputRecordIdentity(), last.inputRecordIdentity()) {
				return fmt.Errorf("link %d: %w: round %d", i, errCandidateSplit, c.PartitionRound)
			}
			if c.RootRound <= last.RootRound {
				return fmt.Errorf("link %d: %w: repeat of round %d at root round %d does not follow root round %d",
					i, errContinuityGap, c.PartitionRound, c.RootRound, last.RootRound)
			}
			expected, last = l.tr.Round, c
			continue
		}
		if c.PartitionRound != expected {
			return fmt.Errorf("link %d: %w: round %d arrived where %d was assigned", i, errContinuityGap, c.PartitionRound, expected)
		}
		if len(c.BlockHash) != 0 || !bytes.Equal(c.StateHash, state) || !bytes.Equal(c.PreviousHash, state) {
			return fmt.Errorf("link %d: %w: round %d", i, errNotQuiet, c.PartitionRound)
		}
		expected, last = l.tr.Round, c
	}
	if err := check(held); err != nil {
		return fmt.Errorf("held: %w", err)
	}
	if last.PartitionRound != held.cert.PartitionRound {
		return fmt.Errorf("%w: the chain reaches round %d, the held certificate is for %d", errUnconnected, last.PartitionRound, held.cert.PartitionRound)
	}
	if !bytes.Equal(last.inputRecordIdentity(), held.cert.inputRecordIdentity()) {
		return fmt.Errorf("%w: round %d", errConflict, held.cert.PartitionRound)
	}
	return nil
}

/*
readyWith is readiness for the child of the recorded block, given the chain from the record's certificate
to the held certificate. Durable readiness first (reload), then continuity, then, for the genesis record,
#153 §7.3 E1 to E4 for the round the held certificate assigns. Every refusal is errStale, with the specific
rule in the chain.
*/
func (h *harness) readyWith(tail []link, held link) (registryproof.Snapshot, error) {
	r := h.reload()
	if r.err != nil {
		return registryproof.Snapshot{}, r.err
	}
	keyBytes, _ := h.store.get(headKey)
	raw, _ := h.store.get(string(keyBytes))
	rec, err := decodeRecord(raw) // already verified by reload
	if err != nil {
		return registryproof.Snapshot{}, err
	}
	source := link{cert: rec.Certificate, tr: rec.Technical}
	if err := h.verifyContinuity(source, tail, held); err != nil {
		return registryproof.Snapshot{}, fmt.Errorf("%w: %w", errStale, err)
	}
	if r.block.Number == 0 {
		ir := &bfttypes.InputRecord{
			RoundNumber: held.cert.PartitionRound, Epoch: held.cert.Epoch, PreviousHash: held.cert.PreviousHash,
			Hash: held.cert.StateHash, BlockHash: held.cert.BlockHash, Timestamp: held.cert.Timestamp,
		}
		if err := registryproof.GenesisParentEligible(held.tr.Round, ir, r.block.StateRoot.Bytes(), r.snapshot); err != nil {
			return registryproof.Snapshot{}, fmt.Errorf("%w: %w", errStale, err)
		}
	}
	return r.snapshot, nil
}

func (h *harness) sourceOf(b block) link { return link{cert: h.certs[b.Hash], tr: h.trs[b.Hash]} }

// quiet issues the quiet certificate for partition round `round` at `state`, assigning `assigns` next.
func (h *harness) quiet(state common.Hash, round, rootRound, assigns uint64) link {
	tr := technicalRecord{Round: assigns}
	c := certificate{
		NetworkID: 3, PartitionID: 8, ShardID: modelShard, ShardConfHash: h.d.ctx.FullShardConfHash.Bytes(),
		PartitionRound: round, PreviousHash: state.Bytes(), StateHash: state.Bytes(), TRHash: tr.digest(),
		RootRound: rootRound, Timestamp: 1_700_000_000 + round,
	}
	h.issue(c, tr)
	return link{cert: c, tr: tr}
}

// repeat issues a repeat of l: the same input record at a later root round, with a new assignment.
func (h *harness) repeat(l link, rootRound, assigns uint64) link {
	tr := technicalRecord{Round: assigns, Epoch: l.tr.Epoch}
	c := l.cert
	c.RootRound = rootRound
	c.TRHash = tr.digest()
	h.issue(c, tr)
	return link{cert: c, tr: tr}
}

// certifiedAt returns a harness with records durable through block n and the executor there.
func certifiedAt(t *testing.T, n int) (*harness, block) {
	h := newHarness(t, n)
	for _, b := range h.chain {
		h.certify(b)
	}
	return h, h.chain[n]
}

// TestReview159QuietSuccessorPreservesReadiness is the review's first reproduction. The quiet certificate
// is supplied as the chain it is: the held certificate alone cannot establish continuity.
func TestReview159QuietSuccessorPreservesReadiness(t *testing.T) {
	h, b := certifiedAt(t, 1)
	source := h.sourceOf(b)
	_, err := h.readyWith(nil, source)
	require.NoError(t, err)

	q := h.quiet(b.StateRoot, source.tr.Round, source.cert.RootRound+1, source.tr.Round+2)
	require.NoError(t, h.reload().err, "executor and durable witness remain at B")
	s, err := h.readyWith([]link{q}, q)
	require.NoError(t, err, "a verified quiet successor must not make the unchanged parent unusable")
	require.Equal(t, b.PartitionRound, s.Fields().RoundAuthorized)
}

func TestQuietHistoryKeepsReadiness(t *testing.T) {
	t.Run("a run of quiet rounds at non-consecutive assigned rounds", func(t *testing.T) {
		h, b := certifiedAt(t, 2)
		src := h.sourceOf(b) // round 2 assigns 3
		q1 := h.quiet(b.StateRoot, src.tr.Round, 10, 5)
		q2 := h.quiet(b.StateRoot, 5, 11, 9)
		q3 := h.quiet(b.StateRoot, 9, 12, 10)
		_, err := h.readyWith([]link{q1, q2, q3}, q3)
		require.NoError(t, err)
	})
	t.Run("a repeat that changes the next assignment", func(t *testing.T) {
		h, b := certifiedAt(t, 1)
		src := h.sourceOf(b) // round 1 assigns 2
		q1 := h.quiet(b.StateRoot, 2, 10, 3)
		rep := h.repeat(q1, 11, 6) // round 3 was abandoned: the repeat assigns 6
		q2 := h.quiet(b.StateRoot, 6, 12, 7)
		_, err := h.readyWith([]link{q1, rep, q2}, q2)
		require.NoError(t, err)
		require.Equal(t, src.tr.Round, q1.cert.PartitionRound)

		_, err = h.readyWith([]link{q1, q2}, q2)
		require.ErrorIs(t, err, errContinuityGap, "without the repeat, round 6 is not the assigned round")
	})
	t.Run("holding a repeat of the last round", func(t *testing.T) {
		h, b := certifiedAt(t, 1)
		q1 := h.quiet(b.StateRoot, 2, 10, 3)
		held := h.repeat(q1, 11, 4)
		_, err := h.readyWith([]link{q1}, held)
		require.NoError(t, err, "the terminal identity excludes the root round")
	})
	t.Run("holding the recorded block's own certificate", func(t *testing.T) {
		h, b := certifiedAt(t, 1)
		_, err := h.readyWith(nil, h.sourceOf(b))
		require.NoError(t, err)
	})
}

func TestContinuityRefusals(t *testing.T) {
	cases := map[string]struct {
		build func(h *harness, b block) ([]link, link)
		want  error
	}{
		"a quiet round at another state": {func(h *harness, b block) ([]link, link) {
			q := h.quiet(common.Hash{7}, 2, 10, 3)
			return []link{q}, q
		}, errNotQuiet},
		"a gap: the chain skips the assigned round": {func(h *harness, b block) ([]link, link) {
			q1 := h.quiet(b.StateRoot, 2, 10, 3)
			q2 := h.quiet(b.StateRoot, 4, 11, 5)
			return []link{q1, q2}, q2
		}, errContinuityGap},
		"a repeat that does not follow at a later root round": {func(h *harness, b block) ([]link, link) {
			q1 := h.quiet(b.StateRoot, 2, 10, 3)
			rep := h.repeat(q1, 10, 6)
			return []link{q1, rep}, rep
		}, errContinuityGap},
		"a repeat with a different input record": {func(h *harness, b block) ([]link, link) {
			q1 := h.quiet(b.StateRoot, 2, 10, 3)
			other := h.repeat(q1, 11, 3)
			other.cert.Timestamp++
			h.issue(other.cert, other.tr)
			return []link{q1, other}, other
		}, errCandidateSplit},
		"same state, different block: a block-naming round at B's state": {func(h *harness, b block) ([]link, link) {
			q := h.quiet(b.StateRoot, 2, 10, 3)
			q.cert.BlockHash = h.chain[0].Hash.Bytes()
			h.issue(q.cert, q.tr)
			return []link{q}, q
		}, errNotQuiet},
		"an intervening non-quiet block": {func(h *harness, b block) ([]link, link) {
			next := h.sourceOf(h.chain[2])
			return []link{next}, next
		}, errNotQuiet},
		"the held certificate names a block where the chain is quiet": {func(h *harness, b block) ([]link, link) {
			q := h.quiet(b.StateRoot, 2, 10, 3)
			held := q
			held.cert.BlockHash = h.chain[0].Hash.Bytes()
			h.issue(held.cert, held.tr)
			return []link{q}, held
		}, errConflict},
		"the chain stops short of the held round": {func(h *harness, b block) ([]link, link) {
			q1 := h.quiet(b.StateRoot, 2, 10, 3)
			q2 := h.quiet(b.StateRoot, 3, 11, 4)
			return []link{q1}, q2
		}, errUnconnected},
		"a link the root chain did not issue": {func(h *harness, b block) ([]link, link) {
			q := h.quiet(b.StateRoot, 2, 10, 3)
			q.cert.RootRound = 99
			return []link{q}, q
		}, errCertificate},
		"a link whose technical record is not the committed one": {func(h *harness, b block) ([]link, link) {
			q := h.quiet(b.StateRoot, 2, 10, 3)
			q.tr.Round = 7
			return []link{q}, q
		}, errTechnicalRecord},
		"a link for another network": {func(h *harness, b block) ([]link, link) {
			q := h.quiet(b.StateRoot, 2, 10, 3)
			q.cert.NetworkID = 4
			h.issue(q.cert, q.tr)
			return []link{q}, q
		}, errWrongContext},
		"a link in another shard epoch": {func(h *harness, b block) ([]link, link) {
			q := h.quiet(b.StateRoot, 2, 10, 3)
			q.cert.Epoch = 1
			h.issue(q.cert, q.tr)
			return []link{q}, q
		}, errEpochChange},
		"a chain over the bound": {func(h *harness, b block) ([]link, link) {
			var tail []link
			round := uint64(2)
			for i := 0; i < maxContinuityLinks; i++ {
				tail = append(tail, h.quiet(b.StateRoot, round, 10+round, round+1))
				round++
			}
			return tail, tail[len(tail)-1]
		}, errExhausted},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h, _ := certifiedAt(t, 2)
			b := h.chain[1]
			// Readiness is for the child of block 1: roll the executor and head record back to it, keeping
			// the later block available as intervening history.
			require.True(t, h.store.rollbackTo(1))
			h.executor.head = b
			require.NoError(t, h.reload().err, "premise: block 1 is durable-ready")
			tail, held := tc.build(h, b)
			_, err := h.readyWith(tail, held)
			require.ErrorIs(t, err, tc.want)
			require.ErrorIs(t, err, errStale)
		})
	}
}

// TestReview159GenesisCertificateDoesNotNameABlock is the review's second reproduction: the no-block
// genesis certificate is the one persisted, reloaded and used for eligibility.
func TestReview159GenesisCertificateDoesNotNameABlock(t *testing.T) {
	h := newHarness(t, 0)
	g := h.chain[0]
	c := h.certs[g.Hash]
	require.Nil(t, c.BlockHash, "premise: the genesis certificate names no block")
	snap, err := registryproof.Verify(h.cfg.proofContext, g.Hash, g.Evidence)
	require.NoError(t, err)
	ir := &bfttypes.InputRecord{RoundNumber: 0, PreviousHash: c.PreviousHash, Hash: c.StateHash, BlockHash: c.BlockHash}
	require.NoError(t, registryproof.GenesisParentEligible(2, ir, g.StateRoot.Bytes(), snap), "premise: the accepted initial-timeout genesis rule")
	h.certify(g)
	require.NoError(t, h.reload().err, "the real no-block genesis certificate reloads with the pinned genesis witness")
}

func TestGenesisReadinessUsesTheSameCertificateThroughout(t *testing.T) {
	h, g := certifiedAt(t, 0)
	installed := h.sourceOf(g) // round 0, assigns 1

	t.Run("first payload, round 1", func(t *testing.T) {
		_, err := h.readyWith(nil, installed)
		require.NoError(t, err)
	})
	rep1 := h.repeat(installed, installed.cert.RootRound+1, 2)
	t.Run("one initial timeout: a repeat assigning round 2", func(t *testing.T) {
		_, err := h.readyWith([]link{rep1}, rep1)
		require.NoError(t, err)
	})
	rep2 := h.repeat(rep1, installed.cert.RootRound+2, 4)
	t.Run("three initial timeouts: repeats assigning round 4", func(t *testing.T) {
		_, err := h.readyWith([]link{rep1, rep2}, rep2)
		require.NoError(t, err)
	})
	t.Run("a quiet certified round still at the genesis state", func(t *testing.T) {
		q := h.quiet(g.StateRoot, 2, installed.cert.RootRound+5, 3)
		_, err := h.readyWith([]link{rep1, q}, q)
		require.NoError(t, err)
	})
	t.Run("E1: a held certificate that assigns round 0", func(t *testing.T) {
		held := h.repeat(installed, installed.cert.RootRound+7, 0)
		_, err := h.readyWith([]link{held}, held)
		require.ErrorIs(t, err, registryproof.ErrGenesisInstallation)
		require.ErrorIs(t, err, errStale)
	})
	t.Run("E2: a held certificate that assigns its own round", func(t *testing.T) {
		q := h.quiet(g.StateRoot, 2, installed.cert.RootRound+8, 2)
		_, err := h.readyWith([]link{rep1, q}, q)
		require.ErrorIs(t, err, registryproof.ErrNotGenesisHistory)
		require.ErrorIs(t, err, errStale)
	})
	t.Run("a later block-naming certificate ends genesis readiness", func(t *testing.T) {
		h2, _ := certifiedAt(t, 1)
		require.True(t, h2.store.rollbackTo(0))
		h2.executor.head = h2.chain[0]
		next := h2.sourceOf(h2.chain[1])
		_, err := h2.readyWith([]link{next}, next)
		require.ErrorIs(t, err, errStale)
	})
}

func TestGenesisRecordShapeRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		n      int
		change func(h *harness, r *certifiedRecord)
		want   error
	}{
		"a genesis certificate that names a block": {0, func(h *harness, r *certifiedRecord) {
			r.Certificate.BlockHash = h.chain[0].Hash.Bytes()
			h.signed[r.Certificate.digest()] = true
		}, errWrongBlock},
		"a genesis certificate whose previous state is not genesis": {0, func(h *harness, r *certifiedRecord) {
			r.Certificate.PreviousHash = common.Hash{1}.Bytes()
			h.signed[r.Certificate.digest()] = true
		}, errWrongBlock},
		"a block-0 record for another block hash": {0, func(h *harness, r *certifiedRecord) {
			r.BlockHash = common.Hash{2}.Bytes()
		}, errWrongBlock},
		"an ordinary record with a certificate that names no block": {1, func(h *harness, r *certifiedRecord) {
			r.Certificate.BlockHash = nil
			h.signed[r.Certificate.digest()] = true
		}, errWrongBlock},
	} {
		t.Run(name, func(t *testing.T) {
			h, b := certifiedAt(t, tc.n)
			storedWith(t, h, b, func(r *certifiedRecord) { tc.change(h, r) })
			require.ErrorIs(t, h.reload().err, tc.want)
		})
	}
}
