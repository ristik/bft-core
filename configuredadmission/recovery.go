package configuredadmission

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// RecoveryExecutor is the Engine adapter's recovery surface. The ordinary
// Executor interface stays unchanged for fake and non-journal deployments.
type RecoveryExecutor interface {
	shardnode.Executor
	Finalized(context.Context) (shardnode.BlockRef, error)
	Header(context.Context, shardnode.Hash) (shardnode.BlockRef, shardnode.Hash, error)
	RecoveryForkchoice(context.Context, shardnode.Hash, shardnode.Hash) (shardnode.Status, error)
	CheckParentWitness(context.Context, shardnode.BlockRef) error
	CheckBlockBinding(context.Context, shardnode.Block, shardnode.RoundParams) error
}

type RecoveryLimits struct {
	Blocks   int
	Bytes    int64
	Deadline time.Duration
	Retries  int
}

func DefaultRecoveryLimits() RecoveryLimits {
	return RecoveryLimits{Blocks: 256, Bytes: 64 << 20, Deadline: 30 * time.Second, Retries: 3}
}

// ExecutionRecovery selects authority only from the independently verified
// journal. It never promotes a candidate or an executor head into authority.
type ExecutionRecovery struct {
	mu              sync.Mutex
	Store           *configuredprogress.Store
	Context         configuredprogress.Context
	JournalLimits   configuredprogress.JournalLimits
	Executor        RecoveryExecutor
	Gate            *shardnode.FinalityGate
	Genesis         shardnode.BlockRef
	Limits          RecoveryLimits
	Host            shardnode.EvidenceHost
	Providers       []peer.ID
	TransportLimits shardnode.JournalTransportLimits
	snapshot        func(context.Context) (configuredprogress.JournalSnapshot, error) // deterministic fault fixtures
	fetch           func(context.Context, peer.ID, shardnode.JournalFetchRequest) ([]shardnode.JournalFetchEntry, error)
}

var (
	ErrRecoveryUnavailable = errors.New("execution recovery: certified input unavailable")
	ErrRecoveryConflict    = errors.New("execution recovery: finalized-branch conflict")
	ErrRecoveryBudget      = errors.New("execution recovery: bounded replay budget exhausted")
	ErrRecoveryIdentity    = errors.New("execution recovery: executor identity differs from certified anchor")
)

func (*ExecutionRecovery) Terminal(err error) bool {
	return errors.Is(err, ErrRecoveryConflict) || errors.Is(err, ErrRecoveryBudget) || errors.Is(err, configuredprogress.ErrBounds) || errors.Is(err, configuredprogress.ErrConflict) || errors.Is(err, configuredprogress.ErrUntrusted)
}

type recoveryChain struct {
	anchor shardnode.BlockRef
	blocks []configuredprogress.JournalEntry // ordered from B1 to anchor
	byHash map[string]int
	latest *types.UnicityCertificate
}

func (r *ExecutionRecovery) load(ctx context.Context) (recoveryChain, error) {
	if r.Store == nil && r.snapshot == nil || r.Executor == nil || r.Gate == nil || len(r.Genesis.Hash) != 32 {
		return recoveryChain{}, fmt.Errorf("%w: incomplete coordinator wiring", ErrRecoveryUnavailable)
	}
	var image configuredprogress.JournalSnapshot
	var err error
	if r.snapshot != nil {
		image, err = r.snapshot(ctx)
	} else {
		image, err = r.Store.LoadJournal(ctx, r.Context, r.JournalLimits)
	}
	if err != nil {
		return recoveryChain{}, fmt.Errorf("%w: verifying journal: %w", ErrRecoveryUnavailable, err)
	}
	return r.chainFromImage(image)
}

func (r *ExecutionRecovery) chainFromImage(image configuredprogress.JournalSnapshot) (recoveryChain, error) {
	c := recoveryChain{anchor: r.Genesis, byHash: make(map[string]int)}
	entries := make(map[string]configuredprogress.JournalEntry)
	for _, e := range image.Candidates {
		if e.Certified {
			entries[string(e.Candidate.Hash)] = e
		}
	}
	for _, o := range image.Observations {
		if o.Unresolved {
			return recoveryChain{}, fmt.Errorf("%w: missing certified body %x at round %d", ErrRecoveryUnavailable, o.TargetHash, o.UC.GetRoundNumber())
		}
		c.latest = o.UC
		if len(o.TargetHash) == 0 {
			continue
		}
		e, ok := entries[string(o.TargetHash)]
		if !ok {
			return recoveryChain{}, fmt.Errorf("%w: missing certified body %x", ErrRecoveryUnavailable, o.TargetHash)
		}
		c.anchor = shardnode.BlockRef{Number: e.Candidate.Number, Hash: e.Candidate.Hash, StateRoot: e.Candidate.StateRoot}
	}
	if c.latest != nil && c.anchor.Number > 0 && !bytes.Equal(c.latest.InputRecord.Hash, c.anchor.StateRoot) {
		return recoveryChain{}, fmt.Errorf("%w: quiet tail state differs from retained anchor %x; certified source body may be missing", ErrRecoveryUnavailable, c.anchor.Hash)
	}
	// Walk the target's ancestors, not all candidates. A same-height side
	// branch remains inert even when its payload is present locally.
	cur := c.anchor
	for cur.Number > 0 {
		if len(c.blocks) >= r.limits().Blocks {
			return recoveryChain{}, fmt.Errorf("%w: target %x exceeds %d retained ancestors", ErrRecoveryBudget, c.anchor.Hash, r.limits().Blocks)
		}
		e, ok := entries[string(cur.Hash)]
		if !ok {
			return recoveryChain{}, fmt.Errorf("%w: missing certified ancestor %x at height %d", ErrRecoveryUnavailable, cur.Hash, cur.Number)
		}
		b := e.Candidate
		if b.Number != cur.Number || !bytes.Equal(b.StateRoot, cur.StateRoot) || b.ParentNumber+1 != b.Number {
			return recoveryChain{}, fmt.Errorf("%w: broken certified link at %x", ErrRecoveryConflict, b.Hash)
		}
		c.blocks = append(c.blocks, e)
		cur = shardnode.BlockRef{Number: b.ParentNumber, Hash: b.ParentHash, StateRoot: b.ParentState}
	}
	if !equalRef(cur, r.Genesis) {
		return recoveryChain{}, fmt.Errorf("%w: certified chain does not reach configured genesis from %x", ErrRecoveryConflict, c.anchor.Hash)
	}
	for i, j := 0, len(c.blocks)-1; i < j; i, j = i+1, j-1 {
		c.blocks[i], c.blocks[j] = c.blocks[j], c.blocks[i]
	}
	for i, e := range c.blocks {
		c.byHash[string(e.Candidate.Hash)] = i + 1
	}
	return c, nil
}

func (r *ExecutionRecovery) limits() RecoveryLimits {
	l := r.Limits
	if l.Blocks <= 0 || l.Bytes <= 0 || l.Deadline <= 0 || l.Retries < 0 {
		return DefaultRecoveryLimits()
	}
	return l
}

func equalRef(a, b shardnode.BlockRef) bool {
	return a.Number == b.Number && bytes.Equal(a.Hash, b.Hash) && bytes.Equal(a.StateRoot, b.StateRoot)
}

func (c recoveryChain) index(ref shardnode.BlockRef, genesis shardnode.BlockRef) (int, bool) {
	if equalRef(ref, genesis) {
		return 0, true
	}
	i := c.byHash[string(ref.Hash)]
	if i == 0 {
		return 0, false
	}
	b := c.blocks[i-1].Candidate
	return i, b.Number == ref.Number && bytes.Equal(b.StateRoot, ref.StateRoot)
}

func (r *ExecutionRecovery) ancestry(ctx context.Context, c recoveryChain, head shardnode.BlockRef) (int, error) {
	for n := 0; n <= r.limits().Blocks; n++ {
		if i, ok := c.index(head, r.Genesis); ok {
			return i, nil
		}
		if head.Number == 0 {
			break
		}
		ref, parent, err := r.Executor.Header(ctx, head.Hash)
		if err != nil {
			return 0, fmt.Errorf("%w: missing executor header %x: %w", ErrRecoveryUnavailable, head.Hash, err)
		}
		if !equalRef(ref, head) {
			return 0, fmt.Errorf("%w: executor header identity changed at %x", ErrRecoveryIdentity, head.Hash)
		}
		head, _, err = r.Executor.Header(ctx, parent)
		if err != nil {
			return 0, fmt.Errorf("%w: missing executor parent header %x: %w", ErrRecoveryUnavailable, parent, err)
		}
	}
	return 0, fmt.Errorf("%w: no retained common ancestor with executor head", ErrRecoveryConflict)
}

func (r *ExecutionRecovery) status(ctx context.Context, label string, fn func() (shardnode.Status, error)) error {
	for attempt := 0; attempt <= r.limits().Retries; attempt++ {
		s, err := fn()
		if err == nil && s == shardnode.StatusValid {
			return nil
		}
		if s == shardnode.StatusInvalid {
			return fmt.Errorf("%w: %s returned INVALID: %v", ErrRecoveryConflict, label, err)
		}
		if attempt == r.limits().Retries {
			return fmt.Errorf("%w: %s remains %s after %d retries: %v", ErrRecoveryUnavailable, label, s, attempt, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
	return ErrRecoveryUnavailable
}

func (r *ExecutionRecovery) finality(ctx context.Context, c recoveryChain) (shardnode.BlockRef, error) {
	f, err := r.Executor.Finalized(ctx)
	if err != nil {
		return f, fmt.Errorf("%w: finalized identity unavailable: %w", ErrRecoveryUnavailable, err)
	}
	if _, ok := c.index(f, r.Genesis); !ok {
		return f, fmt.Errorf("%w: finalized %d/%x is outside certified chain to %d/%x", ErrRecoveryConflict, f.Number, f.Hash, c.anchor.Number, c.anchor.Hash)
	}
	return f, nil
}

func (r *ExecutionRecovery) Recover(ctx context.Context, held *types.UnicityCertificate) (shardnode.BlockRef, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, r.limits().Deadline)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return shardnode.BlockRef{}, err
	}
	c, err := r.load(ctx)
	if err != nil {
		if r.Host == nil && r.fetch == nil || len(r.Providers) == 0 || !errors.Is(err, ErrRecoveryUnavailable) {
			return shardnode.BlockRef{}, err
		}
		if fetchErr := r.acquireMissing(ctx); fetchErr != nil {
			return shardnode.BlockRef{}, fmt.Errorf("%w: peer catch-up: %v", err, fetchErr)
		}
		c, err = r.load(ctx)
		if err != nil {
			return shardnode.BlockRef{}, err
		}
	}
	if held != nil && c.latest != nil && held.GetRootRoundNumber() > c.latest.GetRootRoundNumber() {
		return shardnode.BlockRef{}, fmt.Errorf("%w: held certificate is newer than durable journal", ErrRecoveryUnavailable)
	}
	return r.recoverChain(ctx, c, true)
}

func (r *ExecutionRecovery) recoverChain(ctx context.Context, c recoveryChain, checkCurrent bool) (shardnode.BlockRef, error) {
	head, err := r.Executor.Head(ctx)
	if err != nil {
		return head, fmt.Errorf("%w: executor head RPC: %w", ErrRecoveryUnavailable, err)
	}
	f, err := r.finality(ctx, c)
	if err != nil {
		return head, err
	}
	if equalRef(head, c.anchor) {
		if !equalRef(f, c.anchor) {
			if err := r.commit(ctx, c.anchor); err != nil {
				return head, err
			}
		}
		return head, nil
	}
	// A descendant head may be speculative. It is never finalized by this
	// coordinator; the certified target is selected solely from the journal.
	common, err := r.ancestry(ctx, c, head)
	if err != nil {
		return head, err
	}
	if common == len(c.blocks) && head.Number > c.anchor.Number {
		return r.move(ctx, c.anchor, f, false)
	}
	// Try retained payloads first. Commit is legal only when it cannot rewind
	// finality, as established above. A lost reply is settled by exact reread.
	if err = r.commit(ctx, c.anchor); err == nil {
		return c.anchor, nil
	}
	if !errors.Is(err, ErrRecoveryUnavailable) {
		return head, err
	}
	var used int64
	for i := common; i < len(c.blocks); i++ {
		if err := ctx.Err(); err != nil {
			return head, err
		}
		e := c.blocks[i].Candidate
		used += int64(len(e.Raw))
		if used > r.limits().Bytes {
			return head, fmt.Errorf("%w: suffix to %x exceeds %d bytes", ErrRecoveryBudget, c.anchor.Hash, r.limits().Bytes)
		}
		if f.Number > e.Number {
			return head, fmt.Errorf("%w: replay would move below finalized %d/%x", ErrRecoveryConflict, f.Number, f.Hash)
		}
		parent := r.Genesis
		if i > 0 {
			b := c.blocks[i-1].Candidate
			parent = shardnode.BlockRef{Number: b.Number, Hash: b.Hash, StateRoot: b.StateRoot}
		}
		seal, sealErr := shardnode.SealHash(e.AuthorizingUC)
		if sealErr != nil {
			return head, fmt.Errorf("%w: authorizing seal for %x: %w", ErrRecoveryConflict, e.Hash, sealErr)
		}
		p := shardnode.RoundParams{Round: e.Round, Epoch: e.AuthorizingTR.Epoch, Timestamp: e.AuthorizingUC.UnicitySeal.Timestamp, SealHash: seal, Leader: e.AuthorizingTR.Leader, Parent: parent, AuthorizingCertificate: e.AuthorizingUC, AuthorizingTechnicalRecord: e.AuthorizingTR}
		b := shardnode.Block{Number: e.Number, Hash: e.Hash, ParentHash: e.ParentHash, StateRoot: e.StateRoot, Raw: e.Raw, BlockSize: e.BlockSize, StateSize: e.StateSize}
		if err := r.status(ctx, fmt.Sprintf("Verify %d/%x", e.Number, e.Hash), func() (shardnode.Status, error) { return r.Executor.Verify(ctx, b, p) }); err != nil {
			return head, err
		}
		head, err = r.move(ctx, shardnode.BlockRef{Number: e.Number, Hash: e.Hash, StateRoot: e.StateRoot}, f, false)
		if err != nil {
			return head, err
		}
		if checkCurrent {
			next, loadErr := r.load(ctx)
			if loadErr != nil {
				return head, loadErr
			}
			if !equalRef(next.anchor, c.anchor) {
				return head, fmt.Errorf("%w: certified target changed during replay from %x to %x; retry with new target", ErrRecoveryUnavailable, c.anchor.Hash, next.anchor.Hash)
			}
		}
	}
	return r.move(ctx, c.anchor, f, true)
}

// acquireMissing asks configured shard peers for the exact certified suffix.
// A response is only a source of bytes: every link, both UC/TR pairs, the raw
// header hash, and adapter execution are checked before journal backfill.
func (r *ExecutionRecovery) acquireMissing(ctx context.Context) error {
	if r.Store == nil {
		return ErrRecoveryUnavailable
	}
	image, err := r.Store.LoadJournal(ctx, r.Context, r.JournalLimits)
	if err != nil {
		return err
	}
	var target []byte
	for _, o := range image.Observations {
		if len(o.TargetHash) == 32 {
			target = o.TargetHash
		}
	}
	if len(target) != 32 {
		return fmt.Errorf("%w: no certified target hash to request", ErrRecoveryUnavailable)
	}
	var partial recoveryChain
	found := false
	for end := len(image.Observations); end >= 0; end-- {
		prefix := image
		prefix.Observations = image.Observations[:end]
		if p, e := r.chainFromImage(prefix); e == nil {
			partial = p
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("%w: no retained certified ancestor before target %x", ErrRecoveryUnavailable, target)
	}
	var quietHeld *types.UnicityCertificate
	if bytes.Equal(partial.anchor.Hash, target) && len(image.Observations) > 0 {
		latest := image.Observations[len(image.Observations)-1]
		if len(latest.TargetHash) == 0 && !bytes.Equal(latest.UC.InputRecord.Hash, partial.anchor.StateRoot) {
			target = nil
			quietHeld = latest.UC
		}
	}
	if bytes.Equal(partial.anchor.Hash, target) {
		return fmt.Errorf("%w: no retained certified ancestor before target %x", ErrRecoveryUnavailable, target)
	}
	finalized, finalErr := r.Executor.Finalized(ctx)
	if finalErr != nil {
		return fmt.Errorf("%w: reading finality before catch-up: %w", ErrRecoveryUnavailable, finalErr)
	}
	if finalized.Number <= partial.anchor.Number {
		if _, err = r.recoverChain(ctx, partial, false); err != nil {
			return fmt.Errorf("%w: reaching retained ancestor %x: %w", ErrRecoveryUnavailable, partial.anchor.Hash, err)
		}
	}
	return r.fetchFromPeers(ctx, partial.anchor, target, false, quietHeld)
}

// AcquireForCertificate fills a gap before the newer root certificate is
// admitted. It is invoked only after the normal root observation check has
// authenticated that certificate and found the stored predecessor missing.
func (r *ExecutionRecovery) AcquireForCertificate(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, r.limits().Deadline)
	defer cancel()
	if _, err := rootinput.AuthenticateObservationV2(ctx, r.Context.Observation, uc, tr); err != nil {
		return err
	}
	if uc.InputRecord == nil || len(uc.InputRecord.BlockHash) != 0 && len(uc.InputRecord.BlockHash) != 32 {
		return fmt.Errorf("%w: gap target has invalid block hash", ErrRecoveryUnavailable)
	}
	c, err := r.load(ctx)
	if err != nil {
		if !errors.Is(err, ErrRecoveryUnavailable) {
			return err
		}
		if fetchErr := r.acquireMissing(ctx); fetchErr != nil {
			return fetchErr
		}
		return nil
	}
	finalized, finalErr := r.Executor.Finalized(ctx)
	if finalErr != nil {
		return fmt.Errorf("%w: reading finality before catch-up: %w", ErrRecoveryUnavailable, finalErr)
	}
	if finalized.Number <= c.anchor.Number {
		if _, err = r.recoverChain(ctx, c, true); err != nil {
			return err
		}
	}
	return r.fetchFromPeers(ctx, c.anchor, uc.InputRecord.BlockHash, true, uc)
}

func (r *ExecutionRecovery) fetchFromPeers(ctx context.Context, after shardnode.BlockRef, target []byte, advance bool, expected *types.UnicityCertificate) error {
	limits := r.TransportLimits
	if limits.MaxBlocks == 0 {
		limits = shardnode.DefaultJournalTransportLimits()
	}
	var last error
	var spent int64
	for index, provider := range r.Providers {
		if index >= 4 {
			break
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		req := shardnode.JournalFetchRequest{TargetHash: target, AfterHash: after.Hash}
		if len(target) == 0 && expected != nil {
			req.HeldRound = expected.GetRoundNumber()
			req.HeldIdentity, _ = expected.InputRecord.Bytes()
		}
		var entries []shardnode.JournalFetchEntry
		var fetchErr error
		if r.fetch != nil {
			entries, fetchErr = r.fetch(ctx, provider, req)
		} else {
			entries, fetchErr = shardnode.RequestJournalEntries(ctx, r.Host, provider, req, limits)
		}
		if fetchErr != nil {
			last = fetchErr
			continue
		}
		for _, entry := range entries {
			spent += int64(len(entry.Block.Raw))
		}
		if spent > 2*r.limits().Bytes {
			return fmt.Errorf("%w: total peer fetch bytes exceed %d", ErrRecoveryBudget, 2*r.limits().Bytes)
		}
		if expected != nil {
			if len(entries) == 0 || entries[len(entries)-1].ResultingUC == nil {
				last = fmt.Errorf("provider %s omitted terminal certificate", provider)
				continue
			}
			want, _ := types.Cbor.Marshal(expected)
			got, _ := types.Cbor.Marshal(entries[len(entries)-1].ResultingUC)
			if len(target) != 0 && !bytes.Equal(want, got) {
				last = fmt.Errorf("provider %s returned another terminal certificate", provider)
				continue
			}
			if len(target) == 0 && (!bytes.Equal(entries[len(entries)-1].Block.StateRoot, expected.InputRecord.Hash) || types.CheckNonEquivocatingCertificates(entries[len(entries)-1].ResultingUC, expected) != nil) {
				last = fmt.Errorf("provider %s returned a source incompatible with held quiet certificate", provider)
				continue
			}
		}
		actualTarget := target
		if len(actualTarget) == 0 && len(entries) > 0 {
			actualTarget = entries[len(entries)-1].Block.Hash
		}
		if err := r.admitFetched(ctx, after, actualTarget, entries, advance); err == nil {
			return nil
		} else {
			last = fmt.Errorf("provider %s: %w", provider, err)
		}
	}
	if last != nil {
		return fmt.Errorf("%w: target %x unavailable from %d peers: %w", ErrRecoveryUnavailable, target, len(r.Providers), last)
	}
	return fmt.Errorf("%w: target %x unavailable from %d peers", ErrRecoveryUnavailable, target, len(r.Providers))
}

func (r *ExecutionRecovery) admitFetched(ctx context.Context, after shardnode.BlockRef, target []byte, entries []shardnode.JournalFetchEntry, advance bool) error {
	if len(entries) == 0 || len(entries) > r.limits().Blocks {
		return fmt.Errorf("%w: peer suffix block count", ErrRecoveryBudget)
	}
	if !bytes.Equal(entries[len(entries)-1].Block.Hash, target) {
		return fmt.Errorf("%w: peer suffix ends at %x, requested %x", ErrRecoveryConflict, entries[len(entries)-1].Block.Hash, target)
	}
	parent := after
	f, err := r.Executor.Finalized(ctx)
	if err != nil {
		return fmt.Errorf("%w: finalized identity: %w", ErrRecoveryUnavailable, err)
	}
	var total int64
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := e.Block
		total += int64(len(b.Raw))
		if total > r.limits().Bytes {
			return fmt.Errorf("%w: peer suffix exceeds byte limit", ErrRecoveryBudget)
		}
		if b.Number != parent.Number+1 || !bytes.Equal(b.ParentHash, parent.Hash) || !bytes.Equal(e.ParentState, parent.StateRoot) {
			return fmt.Errorf("%w: peer suffix broken at %d/%x", ErrRecoveryConflict, b.Number, b.Hash)
		}
		if e.AuthorizingUC == nil || e.AuthorizingTR == nil || e.ResultingUC == nil || e.ResultingTR == nil {
			return fmt.Errorf("%w: missing original or resulting UC/TR for %x", ErrRecoveryUnavailable, b.Hash)
		}
		if _, err := rootinput.AuthenticateObservationV2(ctx, r.Context.Observation, e.AuthorizingUC, e.AuthorizingTR); err != nil {
			return fmt.Errorf("%w: original authorization for %x: %w", ErrRecoveryConflict, b.Hash, err)
		}
		if _, err := rootinput.AuthenticateObservationV2(ctx, r.Context.Observation, e.ResultingUC, e.ResultingTR); err != nil {
			return fmt.Errorf("%w: resulting certificate for %x: %w", ErrRecoveryConflict, b.Hash, err)
		}
		ir := e.ResultingUC.InputRecord
		if e.Round != e.AuthorizingTR.Round || ir == nil || ir.RoundNumber != e.Round || !bytes.Equal(ir.BlockHash, b.Hash) || !bytes.Equal(ir.Hash, b.StateRoot) {
			return fmt.Errorf("%w: certificate/body association for %x", ErrRecoveryConflict, b.Hash)
		}
		if !bytes.Equal(e.AuthorizingUC.InputRecord.Hash, parent.StateRoot) && parent.Number > 0 {
			return fmt.Errorf("%w: authorizing state differs from parent %x", ErrRecoveryConflict, parent.Hash)
		}
		seal, err := shardnode.SealHash(e.AuthorizingUC)
		if err != nil {
			return err
		}
		p := shardnode.RoundParams{Round: e.Round, Epoch: e.AuthorizingTR.Epoch, Timestamp: e.AuthorizingUC.UnicitySeal.Timestamp, SealHash: seal, Leader: e.AuthorizingTR.Leader, Parent: parent, AuthorizingCertificate: e.AuthorizingUC, AuthorizingTechnicalRecord: e.AuthorizingTR}
		if err := r.Executor.CheckBlockBinding(ctx, b, p); err != nil {
			return fmt.Errorf("%w: fetched raw hash for %x: %w", ErrRecoveryConflict, b.Hash, err)
		}
		if err := r.status(ctx, fmt.Sprintf("fetched Verify %d/%x", b.Number, b.Hash), func() (shardnode.Status, error) { return r.Executor.Verify(ctx, b, p) }); err != nil {
			return err
		}
		candidate := configuredprogress.JournalCandidate{Round: e.Round, Number: b.Number, ParentNumber: parent.Number, Hash: b.Hash, StateRoot: b.StateRoot, ParentHash: b.ParentHash, ParentState: e.ParentState, Raw: b.Raw, BlockSize: b.BlockSize, StateSize: b.StateSize, AuthorizingUC: e.AuthorizingUC, AuthorizingTR: e.AuthorizingTR}
		if err := r.Store.PutJournalCandidate(ctx, r.Context, r.JournalLimits, candidate); err != nil {
			return fmt.Errorf("%w: retaining fetched body %x: %w", ErrRecoveryUnavailable, b.Hash, err)
		}
		if advance {
			o, authErr := rootinput.AuthenticateObservationV2(ctx, r.Context.Observation, e.ResultingUC, e.ResultingTR)
			if authErr != nil {
				return authErr
			}
			p, _, prepareErr := r.Store.PrepareObservation(ctx, r.Context, o)
			if prepareErr != nil {
				return fmt.Errorf("%w: preparing fetched certificate %x: %w", ErrRecoveryUnavailable, b.Hash, prepareErr)
			}
			release, gateErr := r.Gate.Hold(ctx, "journal-peer-admission")
			if gateErr != nil {
				return gateErr
			}
			_, _, gateErr = r.Store.CommitObservation(p)
			release()
			if gateErr != nil {
				return fmt.Errorf("%w: admitting fetched certificate %x: %w", ErrRecoveryUnavailable, b.Hash, gateErr)
			}
		} else if err := r.Store.BackfillJournalObservation(ctx, r.Context, r.JournalLimits, e.ResultingUC, e.ResultingTR); err != nil {
			return fmt.Errorf("%w: backfilling fetched certificate %x: %w", ErrRecoveryUnavailable, b.Hash, err)
		}
		ref := shardnode.BlockRef{Number: b.Number, Hash: b.Hash, StateRoot: b.StateRoot}
		if b.Number <= f.Number {
			known, _, headerErr := r.Executor.Header(ctx, b.Hash)
			if headerErr != nil || !equalRef(known, ref) {
				return fmt.Errorf("%w: fetched block %d/%x lies below finalized %d/%x but its exact header is unavailable: %v", ErrRecoveryConflict, b.Number, b.Hash, f.Number, f.Hash, headerErr)
			}
			parent = ref
			continue
		}
		parent, err = r.move(ctx, ref, f, false)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *ExecutionRecovery) commit(ctx context.Context, target shardnode.BlockRef) error {
	release, err := r.Gate.Hold(ctx, "journal-recovery-commit")
	if err != nil {
		return err
	}
	defer release()
	err = r.status(ctx, fmt.Sprintf("Commit %x", target.Hash), func() (shardnode.Status, error) { return r.Executor.Commit(ctx, target.Hash) })
	if err != nil && !errors.Is(err, ErrRecoveryUnavailable) {
		return err
	}
	head, readErr := r.Executor.Head(ctx)
	f, finalErr := r.Executor.Finalized(ctx)
	if readErr == nil && finalErr == nil && equalRef(head, target) && equalRef(f, target) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: Commit returned VALID but head is %d/%x and finalized is %d/%x (read errors %v, %v), target %d/%x", ErrRecoveryIdentity, head.Number, head.Hash, f.Number, f.Hash, readErr, finalErr, target.Number, target.Hash)
}

func (r *ExecutionRecovery) move(ctx context.Context, target, finalized shardnode.BlockRef, commit bool) (shardnode.BlockRef, error) {
	if commit {
		if err := r.commit(ctx, target); err != nil {
			return shardnode.BlockRef{}, err
		}
		return target, nil
	}
	release, err := r.Gate.Hold(ctx, "journal-recovery-forkchoice")
	if err != nil {
		return shardnode.BlockRef{}, err
	}
	defer release()
	err = r.status(ctx, fmt.Sprintf("forkchoice %x", target.Hash), func() (shardnode.Status, error) {
		return r.Executor.RecoveryForkchoice(ctx, target.Hash, finalized.Hash)
	})
	if err != nil && !errors.Is(err, ErrRecoveryUnavailable) {
		return shardnode.BlockRef{}, err
	}
	head, readErr := r.Executor.Head(ctx)
	f, finalErr := r.Executor.Finalized(ctx)
	if readErr == nil && finalErr == nil && equalRef(head, target) && equalRef(f, finalized) {
		return head, nil
	}
	if err != nil {
		return head, err
	}
	return head, fmt.Errorf("%w: forkchoice returned VALID but head is %d/%x and finalized is %d/%x, target %d/%x: %v, %v", ErrRecoveryIdentity, head.Number, head.Hash, f.Number, f.Hash, target.Number, target.Hash, readErr, finalErr)
}

type recoveryTicket struct {
	anchor    shardnode.BlockRef
	rootRound uint64
	sealHash  []byte
}

func (t recoveryTicket) Valid() bool { return len(t.anchor.Hash) == 32 }

func (r *ExecutionRecovery) Prepare(ctx context.Context, held *types.UnicityCertificate) (shardnode.ReadinessTicket, error) {
	c, err := r.load(ctx)
	if err != nil {
		return nil, err
	}
	if c.latest != nil && (held == nil || held.GetRootRoundNumber() != c.latest.GetRootRoundNumber() || held.UnicitySeal == nil || !bytes.Equal(held.UnicitySeal.Hash, c.latest.UnicitySeal.Hash)) {
		return nil, fmt.Errorf("%w: held certificate differs from latest durable journal observation", ErrRecoveryUnavailable)
	}
	head, err := r.Executor.Head(ctx)
	if err != nil {
		return nil, err
	}
	if !equalRef(head, c.anchor) {
		return nil, fmt.Errorf("%w: head %d/%x, certified %d/%x", ErrRecoveryIdentity, head.Number, head.Hash, c.anchor.Number, c.anchor.Hash)
	}
	if _, err = r.finality(ctx, c); err != nil {
		return nil, err
	}
	if err = r.Executor.CheckParentWitness(ctx, c.anchor); err != nil {
		return nil, fmt.Errorf("%w: parent witness for %d/%x: %w", ErrRecoveryUnavailable, c.anchor.Number, c.anchor.Hash, err)
	}
	var round uint64
	if c.latest != nil {
		round = c.latest.GetRootRoundNumber()
	}
	var seal []byte
	if c.latest != nil {
		seal = bytes.Clone(c.latest.UnicitySeal.Hash)
	}
	return recoveryTicket{anchor: c.anchor, rootRound: round, sealHash: seal}, nil
}

func (r *ExecutionRecovery) Revalidate(ctx context.Context, ticket shardnode.ReadinessTicket, held *types.UnicityCertificate) error {
	t, ok := ticket.(recoveryTicket)
	if !ok || !t.Valid() {
		return ErrRecoveryIdentity
	}
	c, err := r.load(ctx)
	if err != nil {
		return err
	}
	if !equalRef(t.anchor, c.anchor) || c.latest != nil && (t.rootRound != c.latest.GetRootRoundNumber() || held == nil || held.GetRootRoundNumber() != t.rootRound || held.UnicitySeal == nil || !bytes.Equal(held.UnicitySeal.Hash, t.sealHash) || !bytes.Equal(c.latest.UnicitySeal.Hash, t.sealHash)) {
		return fmt.Errorf("%w: certified target changed", ErrRecoveryIdentity)
	}
	head, err := r.Executor.Head(ctx)
	if err != nil {
		return fmt.Errorf("%w: executor head RPC: %w", ErrRecoveryUnavailable, err)
	}
	if !equalRef(head, c.anchor) {
		return fmt.Errorf("%w: head %d/%x, certified %d/%x", ErrRecoveryIdentity, head.Number, head.Hash, c.anchor.Number, c.anchor.Hash)
	}
	_, err = r.finality(ctx, c)
	return err
}

var _ shardnode.JournalRecovery = (*ExecutionRecovery)(nil)
var _ shardnode.ChildReadiness = (*ExecutionRecovery)(nil)
