package storage

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/unicitynetwork/bft-core/continuity"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ErrLifecycle refuses a candidate whose lifecycle context (incumbent baseline, committed head, recovery allowance) cannot be
// reconstructed from committed history.
var ErrLifecycle = errors.New("candidate lifecycle context unavailable or inconsistent")

// Continuity policy parameters live in the committed EVM configuration (they are hashed with it), so every root validator judges the
// same budget. Absent parameters take the DEV-DEFAULT values M<=4, D<=1/4.
const (
	ParamContinuityMaxM    = "continuity_max_m"
	ParamContinuityMaxDist = "continuity_max_distance" // "num/den"
)

// DevPolicy is the DEV-DEFAULT continuity policy.
var DevPolicy = continuity.Policy{MaxM: 4, MaxDistNum: 1, MaxDistDen: 4}

// ContinuityPolicy reads the policy committed in the installed EVM configuration.
func ContinuityPolicy(installed *types.PartitionDescriptionRecord) (continuity.Policy, error) {
	p := DevPolicy
	if installed == nil {
		return p, ErrLifecycle
	}
	if v, ok := installed.PartitionParams[ParamContinuityMaxM]; ok {
		m, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return p, fmt.Errorf("%w: %s", ErrLifecycle, ParamContinuityMaxM)
		}
		p.MaxM = m
	}
	if v, ok := installed.PartitionParams[ParamContinuityMaxDist]; ok {
		num, den, found := strings.Cut(v, "/")
		n, err1 := strconv.ParseUint(num, 10, 64)
		d, err2 := strconv.ParseUint(den, 10, 64)
		if !found || err1 != nil || err2 != nil || d == 0 {
			return p, fmt.Errorf("%w: %s", ErrLifecycle, ParamContinuityMaxDist)
		}
		p.MaxDistNum, p.MaxDistDen = n, d
	}
	return p, nil
}

// identityHistory is the orchestration's retained incumbent baseline.
type identityHistory interface {
	AcknowledgedIdentities(partition types.PartitionID, shard types.ShardID, epoch uint64) ([]evmassign.Identity, [32]byte, error)
}

// LifecycleFor reconstructs the kind-rule context of the shard from committed history alone: the identities and assignment hash of
// the acknowledged assignment, the continuity policy, the latest committed unacknowledged primary and the committed recoveries of
// the pending chain. Nothing is read from a local flag, so a restart or a new attempt cannot reset the recovery allowance.
func LifecycleFor(orchestration Orchestration, partition types.PartitionID, shard types.ShardID, acknowledged uint64, installed *types.PartitionDescriptionRecord) (evmassign.LifecycleContext, error) {
	var ctx evmassign.LifecycleContext
	history, ok := orchestration.(identityHistory)
	if !ok {
		return ctx, fmt.Errorf("%w: orchestration keeps no incumbent baseline", ErrLifecycle)
	}
	policy, err := ContinuityPolicy(installed)
	if err != nil {
		return ctx, err
	}
	ids, hash, err := history.AcknowledgedIdentities(partition, shard, acknowledged)
	if err != nil {
		return ctx, errors.Join(ErrLifecycle, err)
	}
	chain, err := CommittedChain(orchestration, partition, shard, acknowledged)
	if err != nil {
		return ctx, errors.Join(ErrLifecycle, err)
	}
	ctx = evmassign.LifecycleContext{Incumbent: ids, IncumbentAssignment: hash, Policy: policy, Pending: len(chain.Steps)}
	for _, step := range chain.Steps {
		if step.Kind == evmassign.KindRecovery {
			ctx.CommittedRecoveries++
		}
	}
	if n := len(chain.Steps); n > 0 {
		c, err := evmassign.DecodeCandidate(chain.Steps[n-1].Preimage)
		if err != nil {
			return ctx, errors.Join(ErrLifecycle, err)
		}
		succ, err := c.Successor()
		if err != nil {
			return ctx, errors.Join(ErrLifecycle, err)
		}
		ctx.Head = &evmassign.Head{Candidate: c, Successor: succ}
	}
	return ctx, nil
}
