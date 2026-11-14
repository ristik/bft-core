package shardnode_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestRound_ReplayedRequestKeepsItsOriginatingRoleToken(t *testing.T) {
	sub := &recordingSubmitter{}
	r, id := newTestRound(t, executortest.New(), sub)
	role := &leaseRole{}
	role.token.Store(7)
	role.active.Store(true)
	r.SetRole(role)
	uc, tr := genesisUC(1000), tr(1, 0, id)
	require.NoError(t, r.HandleCertificate(context.Background(), uc, tr))
	require.Len(t, sub.got, 1)
	role.active.Store(false)
	role.token.Store(9)
	role.active.Store(true)
	_ = r.HandleCertificate(context.Background(), uc, tr)
	require.Len(t, sub.got, 1, "request signed under token 7 must not be sent under token 9")
}

type retireDuringBinding struct {
	shardnode.Executor
	role *leaseRole
}

func (e retireDuringBinding) CheckBlockBinding(context.Context, shardnode.Block, shardnode.RoundParams) error {
	e.role.active.Store(false)
	return nil
}

func TestRound_RetirementDuringBindingStopsTheFollowerCandidateWrite(t *testing.T) {
	role := &leaseRole{}
	role.active.Store(true)
	role.token.Store(7)
	fake := executortest.New()
	genesis, err := fake.GenesisBlock(context.Background())
	require.NoError(t, err)
	block := shardnode.Block{Number: 1, Hash: []byte("block hash"), ParentHash: genesis.Hash, StateRoot: []byte("state root"), Raw: []byte("payload")}
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	journal := &refusingJournal{}
	r := shardnode.NewRound("follower", 8, types.ShardID{}, retireDuringBinding{Executor: fake, role: role}, followerProposal{block}, signer, &recordingSubmitter{}, nil)
	r.SetRole(role)
	r.SetProposalJournal(journal)
	_ = r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, "leader"))
	require.Zero(t, journal.calls, "retirement during binding must prevent a new speculative journal write")
}

type retireDuringAwait struct {
	followerProposal
	role *leaseRole
}

func (d retireDuringAwait) Await(ctx context.Context, round uint64) (shardnode.Block, error) {
	d.role.active.Store(false) // retired while this follower waited for the leader's block
	return d.followerProposal.Await(ctx, round)
}

func TestRound_RetirementDuringAwaitStopsTheFollowerCandidateWrite(t *testing.T) {
	role := &leaseRole{}
	role.active.Store(true)
	fake := executortest.New()
	genesis, err := fake.GenesisBlock(context.Background())
	require.NoError(t, err)
	block := shardnode.Block{Number: 1, Hash: []byte("block hash"), ParentHash: genesis.Hash, StateRoot: []byte("state root"), Raw: []byte("payload")}
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	journal := &refusingJournal{}
	r := shardnode.NewRound("follower", 8, types.ShardID{}, followerBindingExecutor{Executor: fake}, retireDuringAwait{followerProposal{block}, role}, signer, &recordingSubmitter{}, nil)
	r.SetRole(role)
	r.SetProposalJournal(journal)
	_ = r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, "leader"))
	require.Zero(t, journal.calls, "retirement during the wait for the leader must prevent a new speculative journal write")
}
