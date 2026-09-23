package engineapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/parentwitness"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/registrywitness"
	"github.com/unicitynetwork/bft-core/shardnode"
)

var (
	ErrParentWitnessInvalid    = errors.New("engineapi: parent registry witness invalid")
	ErrParentWitnessBudget     = errors.New("engineapi: parent registry witness budget exhausted")
	ErrParentWitnessStopped    = errors.New("engineapi: parent registry witness stopped")
	ErrParentWitnessSuperseded = errors.New("engineapi: parent registry witness target superseded")
	ErrParentWitnessMismatch   = errors.New("engineapi: parent registry witness differs from certified block")
)

// DefaultParentWitnessBudget keeps a local proof attempt well inside a normal one-second root
// round. The round's own context may shorten these bounds further. A failed episode backs off
// before another attempt; there is no peer fallback or replenished byte budget within an episode.
func DefaultParentWitnessBudget() parentwitness.RequesterBudget {
	return parentwitness.RequesterBudget{
		MaxAttempts: 1, MaxProviders: 1,
		Overall: 500 * time.Millisecond, PerAttempt: 400 * time.Millisecond,
		MaxDownloadedBytes: 2 * registrywitness.MaxResponseBytes,
		Backoff:            100 * time.Millisecond,
	}
}

// ParentWitnessPins are fixed by the node's configured genesis and shard configuration. A caller
// supplies only the already certified parent BlockRef, never a context, RPC head, or block number
// chosen by the execution client.
type ParentWitnessPins struct {
	NetworkID         types.NetworkID
	PartitionID       types.PartitionID
	ShardID           types.ShardID
	FullShardConfHash common.Hash
	Registry          registryproof.Context
}

type ParentWitnessSource struct {
	pins      ParentWitnessPins
	requester *parentwitness.Requester
	mu        sync.Mutex
	last      registryproof.Snapshot // one immutable, verified parent; never a failed acquisition
	closed    bool
}

// NewParentWitnessSource activates only the local execution RPC. All proof acquisition and
// verification, including exact-hash selectors and body metering, belongs to the requester.
func NewParentWitnessSource(ctx context.Context, pins ParentWitnessPins, rpc registrywitness.MeteredCaller, budget parentwitness.RequesterBudget) (*ParentWitnessSource, error) {
	if rpc == nil || pins.FullShardConfHash == (common.Hash{}) || pins.FullShardConfHash != pins.Registry.FullShardConfHash {
		return nil, fmt.Errorf("%w: local RPC and matching full shard configuration are required", ErrParentWitnessInvalid)
	}
	r, err := parentwitness.NewRequester(ctx, parentwitness.RequesterConfig{LocalRPC: rpc, Budget: budget})
	if err != nil {
		return nil, fmt.Errorf("engineapi: creating local parent witness requester: %w", err)
	}
	return &ParentWitnessSource{pins: pins, requester: r}, nil
}

// Acquire checks a proof of the exact consensus-pinned parent and then compares the verified
// header number and state root with that same BlockRef. A different valid proof encoding is fine;
// a different subject or state is not. Genesis uses the configured B0 snapshot, not this source.
func (s *ParentWitnessSource) Acquire(ctx context.Context, parent shardnode.BlockRef) (registryproof.Snapshot, error) {
	if s == nil || s.requester == nil || parent.Number == 0 || len(parent.Hash) != common.HashLength || len(parent.StateRoot) != common.HashLength {
		return registryproof.Snapshot{}, fmt.Errorf("%w: expected non-genesis parent with 32-byte hash and state root", ErrParentWitnessMismatch)
	}
	hash := common.BytesToHash(parent.Hash)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return registryproof.Snapshot{}, ErrParentWitnessStopped
	}
	cached := s.last
	s.mu.Unlock()
	if cached.Valid() && cached.ParentHash() == hash {
		if cached.Number() != parent.Number || !bytes.Equal(cached.StateRoot().Bytes(), parent.StateRoot) {
			return registryproof.Snapshot{}, fmt.Errorf("%w: cached parent %d/%s has state %s", ErrParentWitnessMismatch, cached.Number(), hash, cached.StateRoot())
		}
		if err := ctx.Err(); err != nil {
			return registryproof.Snapshot{}, err
		}
		return cached, nil
	}
	target, err := parentwitness.NewTarget(parentwitness.TargetConfig{
		NetworkID: s.pins.NetworkID, PartitionID: s.pins.PartitionID, ShardID: s.pins.ShardID,
		FullShardConfHash: s.pins.FullShardConfHash, Registry: s.pins.Registry, BlockHash: hash,
	})
	if err != nil {
		return registryproof.Snapshot{}, fmt.Errorf("%w: constructing exact parent target: %w", ErrParentWitnessInvalid, err)
	}
	result, requestErr := s.requester.Request(ctx, target)
	if errors.Is(requestErr, parentwitness.ErrRequesterBackoff) {
		return registryproof.Snapshot{}, fmt.Errorf("%w: requester backoff", ErrParentWitnessUnavailable)
	}
	if requestErr != nil && result.Outcome == parentwitness.RequesterStopped {
		return registryproof.Snapshot{}, fmt.Errorf("%w: %w", ErrParentWitnessStopped, requestErr)
	}
	if requestErr != nil {
		return registryproof.Snapshot{}, fmt.Errorf("%w: %w", ErrParentWitnessInvalid, requestErr)
	}
	switch result.Outcome {
	case parentwitness.RequesterVerified:
		snapshot := result.Response.Snapshot()
		if !result.Response.Found() || !snapshot.Valid() || snapshot.ParentHash() != hash || snapshot.Number() != parent.Number || !bytes.Equal(snapshot.StateRoot().Bytes(), parent.StateRoot) {
			return registryproof.Snapshot{}, fmt.Errorf("%w: parent %d/%s has verified proof %d/%s with state %s", ErrParentWitnessMismatch, parent.Number, hash, snapshot.Number(), snapshot.ParentHash(), snapshot.StateRoot())
		}
		s.mu.Lock()
		if !s.closed {
			s.last = snapshot
		}
		s.mu.Unlock()
		return snapshot, nil
	case parentwitness.RequesterUnavailable:
		return registryproof.Snapshot{}, fmt.Errorf("%w: %s", ErrParentWitnessUnavailable, result.Detail)
	case parentwitness.RequesterInvalid:
		return registryproof.Snapshot{}, fmt.Errorf("%w: %s", ErrParentWitnessInvalid, result.Detail)
	case parentwitness.RequesterBudgetExhausted:
		return registryproof.Snapshot{}, fmt.Errorf("%w: %s", ErrParentWitnessBudget, result.Detail)
	case parentwitness.RequesterSuperseded:
		return registryproof.Snapshot{}, fmt.Errorf("%w: %s", ErrParentWitnessSuperseded, result.Detail)
	default:
		return registryproof.Snapshot{}, fmt.Errorf("%w: %s", ErrParentWitnessStopped, result.Detail)
	}
}

func (s *ParentWitnessSource) Close() {
	if s != nil && s.requester != nil {
		s.mu.Lock()
		s.closed = true
		s.last = registryproof.Snapshot{}
		s.mu.Unlock()
		s.requester.Close()
	}
}

// EnableParentWitness binds acquisition to the checked genesis and the verifier's own identity.
// The source is owned by Adapter and is closed when the node exits.
func (a *Adapter) EnableParentWitness(ctx context.Context, budget parentwitness.RequesterBudget) error {
	if a == nil || a.verifier == nil || !a.verifier.GenesisOrigin.Valid() || len(a.verifier.ShardConfHash) != common.HashLength {
		return fmt.Errorf("%w: checked genesis and verifier configuration required", ErrParentWitnessInvalid)
	}
	full := common.BytesToHash(a.verifier.ShardConfHash)
	if full != a.verifier.GenesisOrigin.FullShardConfHash() {
		return fmt.Errorf("%w: verifier configuration differs from genesis", ErrParentWitnessInvalid)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.witnessClosed || a.parentWitness != nil {
		return fmt.Errorf("%w: adapter source already enabled or closed", ErrParentWitnessInvalid)
	}
	caller := registrywitness.NewHTTPCaller(a.eth.url, budget.PerAttempt)
	source, err := NewParentWitnessSource(ctx, ParentWitnessPins{
		NetworkID: a.verifier.NetworkID, PartitionID: a.verifier.PartitionID, ShardID: a.verifier.ShardID,
		FullShardConfHash: full, Registry: a.verifier.GenesisOrigin.ProofContext(),
	}, caller, budget)
	if err != nil {
		return err
	}
	a.parentWitness = source
	return nil
}

// Close cancels any in-flight parent acquisition and waits for it to finish.
func (a *Adapter) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.witnessClosed = true
	source := a.parentWitness
	a.parentWitness = nil
	a.mu.Unlock()
	source.Close()
}

func isParentWitnessAcquisitionError(err error) bool {
	return errors.Is(err, ErrParentWitnessUnavailable) || errors.Is(err, ErrParentWitnessInvalid) ||
		errors.Is(err, ErrParentWitnessBudget) || errors.Is(err, ErrParentWitnessStopped) ||
		errors.Is(err, ErrParentWitnessSuperseded) || errors.Is(err, ErrParentWitnessMismatch)
}

// TransientVerify lets the round retry only a transport/absence failure. The wrapper preserves
// errors.Is for diagnostics while avoiding an engineapi import from shardnode.
type transientParentWitnessError struct{ error }

func (e transientParentWitnessError) Unwrap() error         { return e.error }
func (e transientParentWitnessError) TransientVerify() bool { return true }
