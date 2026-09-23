package shardnode_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

type refusingJournal struct{ calls int }

func (j *refusingJournal) RetainCandidate(context.Context, shardnode.Block, shardnode.RoundParams, bool) error {
	j.calls++
	return errors.New("journal fsync failed")
}

type conflictingFollowerJournal struct{}

func (conflictingFollowerJournal) RetainCandidate(context.Context, shardnode.Block, shardnode.RoundParams, bool) error {
	return shardnode.ErrProposalRejected
}

type followerBindingExecutor struct{ shardnode.Executor }

func (followerBindingExecutor) CheckBlockBinding(context.Context, shardnode.Block, shardnode.RoundParams) error {
	return nil
}

type followerProposal struct{ block shardnode.Block }

func (d followerProposal) Publish(context.Context, uint64, shardnode.Block) error { return nil }
func (d followerProposal) Await(context.Context, uint64) (shardnode.Block, error) {
	return d.block, nil
}

func TestFollowerProposalConflictDeclinesSignWithoutStopping(t *testing.T) {
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	fake := executortest.New()
	genesis, err := fake.GenesisBlock(context.Background())
	require.NoError(t, err)
	block := shardnode.Block{Number: 1, Hash: []byte("block hash"), ParentHash: genesis.Hash, StateRoot: []byte("state root"), Raw: []byte("payload")}
	spy := &journalSignerSpy{}
	r := shardnode.NewRound("follower", 8, types.ShardID{}, followerBindingExecutor{fake}, followerProposal{block}, signer, &recordingSubmitter{}, nil)
	health := shardnode.NewHealth()
	r.SetHealth(health)
	r.SetProposalJournal(conflictingFollowerJournal{})
	r.SetCertificationSigner(spy)
	err = r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, "leader"))
	require.ErrorIs(t, err, shardnode.ErrProposalRejected)
	require.Zero(t, spy.calls)
	require.Equal(t, "unready", health.Snapshot().ExecutionRecovery)
}

func TestFollowerJournalRefusesExecutorWithoutRawBinding(t *testing.T) {
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	fake := executortest.New()
	genesis, err := fake.GenesisBlock(context.Background())
	require.NoError(t, err)
	block := shardnode.Block{Number: 1, Hash: []byte("block hash"), ParentHash: genesis.Hash, StateRoot: []byte("state root"), Raw: []byte("payload")}
	journal := &refusingJournal{}
	spy := &journalSignerSpy{}
	r := shardnode.NewRound("follower", 8, types.ShardID{}, fake, followerProposal{block}, signer, &recordingSubmitter{}, nil)
	r.SetHealth(shardnode.NewHealth())
	r.SetProposalJournal(journal)
	r.SetCertificationSigner(spy)
	err = r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, "leader"))
	require.ErrorContains(t, err, "lacks raw block binding support")
	require.Zero(t, journal.calls)
	require.Zero(t, spy.calls)
}

type journalDisseminator struct{ published int }

func (d *journalDisseminator) Publish(context.Context, uint64, shardnode.Block) error {
	d.published++
	return nil
}
func (d *journalDisseminator) Await(context.Context, uint64) (shardnode.Block, error) {
	return shardnode.Block{}, errors.New("unexpected Await")
}

type journalSignerSpy struct{ calls int }

func (s *journalSignerSpy) Sign(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord, *certification.BlockCertificationRequest) (*certification.BlockCertificationRequest, error) {
	s.calls++
	return nil, errors.New("unexpected signing")
}

func TestJournalFailurePreventsLeaderPublicationAndSignature(t *testing.T) {
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	d := &journalDisseminator{}
	j := &refusingJournal{}
	spy := &journalSignerSpy{}
	sub := &recordingSubmitter{}
	exec := executortest.New()
	exec.AddEntries([]byte("block payload"))
	r := shardnode.NewRound("journal-leader", 8, types.ShardID{}, exec, d, signer, sub, nil)
	health := shardnode.NewHealth()
	r.SetHealth(health)
	r.SetProposalJournal(j)
	r.SetCertificationSigner(spy)
	err = r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, "journal-leader"))
	require.ErrorContains(t, err, "journal fsync failed")
	require.Equal(t, 1, j.calls)
	require.Zero(t, d.published, "a proposal cannot escape before its body is durable")
	require.Zero(t, spy.calls, "the signer cannot authorize an unretained proposal")
	require.Empty(t, sub.got)
	require.Equal(t, "stopped", health.Snapshot().ExecutionRecovery)
}
