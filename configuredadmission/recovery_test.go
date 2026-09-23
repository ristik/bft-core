package configuredadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
	abhex "github.com/unicitynetwork/bft-go-base/types/hex"
)

func TestRecoveryChainWalkCoversJournalCapacityBeyondReplayBudget(t *testing.T) {
	const height = 300
	genesisHash := sha256.Sum256([]byte("genesis"))
	genesisState := sha256.Sum256([]byte("genesis state"))
	genesis := shardnode.BlockRef{Number: 0, Hash: genesisHash[:], StateRoot: genesisState[:]}
	r := &ExecutionRecovery{Genesis: genesis, JournalLimits: configuredprogress.JournalLimits{Candidates: 400}, Limits: RecoveryLimits{Blocks: 2, Bytes: 1024, Deadline: time.Second, Retries: 0}}
	image := configuredprogress.JournalSnapshot{}
	parent := genesis
	refs := []shardnode.BlockRef{genesis}
	for n := 1; n <= height; n++ {
		hash := sha256.Sum256([]byte(fmt.Sprintf("block %d", n)))
		state := sha256.Sum256([]byte(fmt.Sprintf("state %d", n)))
		entry := configuredprogress.JournalEntry{Candidate: configuredprogress.JournalCandidate{Number: uint64(n), ParentNumber: parent.Number, Hash: hash[:], StateRoot: state[:], ParentHash: parent.Hash, ParentState: parent.StateRoot}, Certified: true}
		image.Candidates = append(image.Candidates, entry)
		parent = shardnode.BlockRef{Number: uint64(n), Hash: hash[:], StateRoot: state[:]}
		refs = append(refs, parent)
	}
	image.Observations = []configuredprogress.JournalObservation{{TargetHash: parent.Hash, UC: &types.UnicityCertificate{InputRecord: &types.InputRecord{Hash: abhex.Bytes(parent.StateRoot)}}}}
	chain, err := r.chainFromImage(image)
	require.NoError(t, err)
	require.Equal(t, height, len(chain.blocks))
	require.Equal(t, parent, chain.anchor)
	r.snapshot = func(context.Context) (configuredprogress.JournalSnapshot, error) { return image, nil }
	r.Executor = &replayExecutor{head: parent, finalized: parent, refs: refs}
	r.Gate = shardnode.NewFinalityGate()
	got, err := r.Recover(context.Background(), nil)
	require.NoError(t, err, "a synced B300 node must not spend its two-block replay budget walking retained ancestry")
	require.Equal(t, parent, got)
}

type replayExecutor struct {
	head, finalized shardnode.BlockRef
	refs            []shardnode.BlockRef
	forks           map[string]struct {
		ref    shardnode.BlockRef
		parent shardnode.Hash
	}
	known      map[string]bool
	verify     []uint64
	forkchoice []uint64
	invalid    uint64
	lostReply  uint64
	witnessErr error
	headErr    error
}

func (e *replayExecutor) Head(context.Context) (shardnode.BlockRef, error) {
	if e.headErr != nil {
		return shardnode.BlockRef{}, e.headErr
	}
	return e.head, nil
}
func (e *replayExecutor) GenesisBlock(context.Context) (shardnode.BlockRef, error) {
	return e.refs[0], nil
}
func (e *replayExecutor) Finalized(context.Context) (shardnode.BlockRef, error) {
	return e.finalized, nil
}
func (e *replayExecutor) Header(_ context.Context, h shardnode.Hash) (shardnode.BlockRef, shardnode.Hash, error) {
	if f, ok := e.forks[string(h)]; ok {
		return f.ref, f.parent, nil
	}
	for i, ref := range e.refs {
		if bytes.Equal(ref.Hash, h) {
			if i == 0 {
				return ref, nil, nil
			}
			return ref, e.refs[i-1].Hash, nil
		}
	}
	return shardnode.BlockRef{}, nil, fmt.Errorf("missing header %x", h)
}
func (e *replayExecutor) Commit(_ context.Context, h shardnode.Hash) (shardnode.Status, error) {
	if !e.known[string(h)] {
		return shardnode.StatusSyncing, nil
	}
	for _, ref := range e.refs {
		if bytes.Equal(ref.Hash, h) {
			e.head = ref
			e.finalized = ref
			return shardnode.StatusValid, nil
		}
	}
	return shardnode.StatusInvalid, nil
}
func (e *replayExecutor) RecoveryForkchoice(_ context.Context, h, finalized shardnode.Hash) (shardnode.Status, error) {
	if !bytes.Equal(finalized, e.finalized.Hash) {
		return shardnode.StatusInvalid, nil
	}
	if !e.known[string(h)] {
		return shardnode.StatusSyncing, nil
	}
	for _, ref := range e.refs {
		if bytes.Equal(ref.Hash, h) {
			e.head = ref
			e.forkchoice = append(e.forkchoice, ref.Number)
			return shardnode.StatusValid, nil
		}
	}
	return shardnode.StatusInvalid, nil
}
func (e *replayExecutor) CheckParentWitness(context.Context, shardnode.BlockRef) error {
	return e.witnessErr
}
func (e *replayExecutor) CheckBlockBinding(context.Context, shardnode.Block, shardnode.RoundParams) error {
	return nil
}
func (e *replayExecutor) Build(context.Context, shardnode.RoundParams) (shardnode.BuildID, error) {
	panic("Build before readiness")
}
func (e *replayExecutor) Seal(context.Context, shardnode.BuildID) (shardnode.Block, error) {
	panic("Seal before readiness")
}
func (e *replayExecutor) Verify(_ context.Context, b shardnode.Block, p shardnode.RoundParams) (shardnode.Status, error) {
	e.verify = append(e.verify, b.Number)
	if b.Number == e.invalid {
		return shardnode.StatusInvalid, nil
	}
	if !bytes.Equal(p.Parent.Hash, e.refs[b.Number-1].Hash) || !bytes.Equal(b.Raw, []byte{byte(b.Number)}) {
		return shardnode.StatusInvalid, nil
	}
	e.known[string(b.Hash)] = true
	if b.Number == e.lostReply {
		e.lostReply = 0
		return shardnode.StatusSyncing, errors.New("lost Engine reply")
	}
	return shardnode.StatusValid, nil
}

func replayFixture() (*ExecutionRecovery, *replayExecutor, *configuredprogress.JournalSnapshot) {
	refs := make([]shardnode.BlockRef, 7)
	for i := range refs {
		refs[i] = shardnode.BlockRef{Number: uint64(i), Hash: bytes.Repeat([]byte{byte(i + 1)}, 32), StateRoot: bytes.Repeat([]byte{byte(i + 20)}, 32)}
	}
	e := &replayExecutor{head: refs[0], finalized: refs[0], refs: refs, known: map[string]bool{string(refs[0].Hash): true}}
	image := &configuredprogress.JournalSnapshot{}
	for i := 1; i <= 6; i++ {
		uc := &types.UnicityCertificate{UnicitySeal: &types.UnicitySeal{Hash: bytes.Repeat([]byte{byte(i)}, 32), Timestamp: 100}}
		tr := &certification.TechnicalRecord{Round: uint64(i), Epoch: 1, Leader: "leader"}
		image.Candidates = append(image.Candidates, configuredprogress.JournalEntry{Certified: true, Candidate: configuredprogress.JournalCandidate{Round: uint64(i), Number: uint64(i), ParentNumber: uint64(i - 1), Hash: refs[i].Hash, StateRoot: refs[i].StateRoot, ParentHash: refs[i-1].Hash, ParentState: refs[i-1].StateRoot, Raw: []byte{byte(i)}, AuthorizingUC: uc, AuthorizingTR: tr}})
	}
	image.Candidates = image.Candidates[:5]
	image.Observations = []configuredprogress.JournalObservation{{UC: &types.UnicityCertificate{InputRecord: &types.InputRecord{Hash: abhex.Bytes(refs[5].StateRoot)}, UnicitySeal: &types.UnicitySeal{RootChainRoundNumber: 5}}, TargetHash: refs[5].Hash}}
	r := &ExecutionRecovery{Executor: e, Gate: shardnode.NewFinalityGate(), Genesis: refs[0], Limits: RecoveryLimits{Blocks: 8, Bytes: 100, Deadline: 2 * time.Second, Retries: 0}}
	r.snapshot = func(context.Context) (configuredprogress.JournalSnapshot, error) { return *image, nil }
	return r, e, image
}

func TestExecutionRecoveryHeadsAndIdempotence(t *testing.T) {
	for _, height := range []int{0, 3, 5, 6} {
		t.Run(fmt.Sprint(height), func(t *testing.T) {
			r, e, _ := replayFixture()
			e.head = e.refs[height]
			e.finalized = e.refs[min(height, 5)]
			for i := 0; i <= height; i++ {
				e.known[string(e.refs[i].Hash)] = true
			}
			if height == 6 {
				e.finalized = e.refs[5]
			}
			head, err := r.Recover(context.Background(), nil)
			require.NoError(t, err)
			require.Equal(t, e.refs[5], head)
			n := len(e.verify)
			_, err = r.Recover(context.Background(), nil)
			require.NoError(t, err)
			require.Len(t, e.verify, n)
			if height == 6 {
				require.Equal(t, []uint64{5}, e.forkchoice)
				require.Equal(t, e.refs[5], e.finalized)
			}
		})
	}
}

func TestExecutionRecoveryMissingCorruptAndFinality(t *testing.T) {
	r, e, image := replayFixture()
	image.Observations[0].Unresolved = true
	_, err := r.Recover(context.Background(), nil)
	require.ErrorIs(t, err, ErrRecoveryUnavailable)
	require.Empty(t, e.verify)
	image.Observations[0].Unresolved = false
	image.Candidates = image.Candidates[:4]
	_, err = r.Recover(context.Background(), nil)
	require.ErrorContains(t, err, "missing certified body")
	r, e, _ = replayFixture()
	e.invalid = 1
	_, err = r.Recover(context.Background(), nil)
	require.ErrorIs(t, err, ErrRecoveryConflict)
	require.Equal(t, e.refs[0], e.head)
	r, e, _ = replayFixture()
	e.finalized = e.refs[6]
	_, err = r.Recover(context.Background(), nil)
	require.ErrorIs(t, err, ErrRecoveryConflict)
	require.Empty(t, e.verify)
}

func TestExecutionRecoveryLostReplyAndReadinessInvalidation(t *testing.T) {
	r, e, image := replayFixture()
	r.Limits.Retries = 1
	e.lostReply = 2
	_, err := r.Recover(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, e.refs[5], e.head)
	held := image.Observations[0].UC
	ticket, err := r.Prepare(context.Background(), held)
	require.NoError(t, err)
	require.True(t, ticket.Valid())
	require.NoError(t, r.Revalidate(context.Background(), ticket, held))
	e.head = e.refs[3]
	require.ErrorIs(t, r.Revalidate(context.Background(), ticket, held), ErrRecoveryIdentity)
	e.head = e.refs[5]
	e.headErr = errors.New("RPC loss")
	require.ErrorIs(t, r.Revalidate(context.Background(), ticket, held), ErrRecoveryUnavailable)
	e.headErr = nil
	e.witnessErr = errors.New("missing parent proof")
	_, err = r.Prepare(context.Background(), held)
	require.ErrorContains(t, err, "parent witness")
}

func TestExecutionRecoveryForkAndRuntimeExecutorRestart(t *testing.T) {
	r, e, _ := replayFixture()
	fork := shardnode.BlockRef{Number: 3, Hash: bytes.Repeat([]byte{0xfa}, 32), StateRoot: e.refs[3].StateRoot}
	e.head = fork
	e.finalized = e.refs[2]
	e.forks = map[string]struct {
		ref    shardnode.BlockRef
		parent shardnode.Hash
	}{string(fork.Hash): {fork, e.refs[2].Hash}}
	for i := 0; i <= 2; i++ {
		e.known[string(e.refs[i].Hash)] = true
	}
	_, err := r.Recover(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, []uint64{3, 4, 5}, e.verify)
	// The shard stays alive while the executor returns with an older durable head.
	e.head = e.refs[3]
	e.finalized = e.refs[3]
	delete(e.known, string(e.refs[4].Hash))
	delete(e.known, string(e.refs[5].Hash))
	e.verify = nil
	_, err = r.Recover(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, []uint64{4, 5}, e.verify)
	require.Equal(t, e.refs[5], e.head)
}

func TestExecutionRecoveryCancellationAndNewTarget(t *testing.T) {
	r, e, image := replayFixture()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := r.Recover(ctx, nil)
	require.Error(t, err)
	// A newer admitted certificate invalidates the in-flight target. The next
	// attempt reselects the new one rather than continuing with stale B5.
	r, e, image = replayFixture()
	base := r.snapshot
	calls := 0
	r.snapshot = func(ctx context.Context) (configuredprogress.JournalSnapshot, error) {
		calls++
		if calls == 3 {
			b := e.refs[6]
			image.Candidates = append(image.Candidates, configuredprogress.JournalEntry{Certified: true, Candidate: configuredprogress.JournalCandidate{Round: 6, Number: 6, ParentNumber: 5, Hash: b.Hash, StateRoot: b.StateRoot, ParentHash: e.refs[5].Hash, ParentState: e.refs[5].StateRoot, Raw: []byte{6}, AuthorizingUC: &types.UnicityCertificate{UnicitySeal: &types.UnicitySeal{Hash: abhex.Bytes(b.Hash)}}, AuthorizingTR: &certification.TechnicalRecord{Round: 6}}})
			image.Observations = append(image.Observations, configuredprogress.JournalObservation{UC: &types.UnicityCertificate{InputRecord: &types.InputRecord{Hash: abhex.Bytes(b.StateRoot)}, UnicitySeal: &types.UnicitySeal{RootChainRoundNumber: 6}}, TargetHash: b.Hash})
		}
		return base(ctx)
	}
	_, err = r.Recover(context.Background(), nil)
	require.ErrorContains(t, err, "target changed")
	_, err = r.Recover(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, e.refs[6], e.head)
}
