package shardnode

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

type internalReadiness struct{}

func (internalReadiness) Prepare(context.Context, *types.UnicityCertificate) (ReadinessTicket, error) {
	return nil, nil
}

func (internalReadiness) Revalidate(context.Context, ReadinessTicket, *types.UnicityCertificate) error {
	return nil
}

type internalObserver struct{}

func (internalObserver) ObserveCertificate(*types.UnicityCertificate, *certification.TechnicalRecord) error {
	return nil
}

func internalGenesisUC(timestamp uint64) *types.UnicityCertificate {
	return &types.UnicityCertificate{
		Version:     1,
		InputRecord: &types.InputRecord{Version: 1},
		UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 1, Timestamp: timestamp},
	}
}

func internalTR(round uint64, leader string) *certification.TechnicalRecord {
	return &certification.TechnicalRecord{Round: round, Epoch: 0, Leader: leader, StatHash: []byte{0x01}, FeeHash: []byte{0x01}}
}

func TestJournalActivationRefusesExecutorWithoutRawBinding(t *testing.T) {
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	round := NewRound("node", 8, types.ShardID{}, newSeqExecutor(), NewLoopbackDisseminator(), signer, &staleTestSubmitter{}, nil)
	node := &Node{round: round, recoveryDeps: RecoveryDeps{Gate: NewFinalityGate()}}
	require.ErrorContains(t, node.SetJournalAdmission(nil), "requires an executor with raw block binding support")
}

// TestRecordGateIsOffWithoutTheFlag: the record gate is an explicit opt-in, so a node wired without
// it carries no ChildReadiness and no CertificateObserver and its voting is unchanged. The store the
// CLI consults is a command-layer concern; what this pins is that the Node and Round defaults stay
// off until the setters are called, which is what the command does only behind
// --certified-record-gate.
func TestRecordGateIsOffWithoutTheFlag(t *testing.T) {
	ctx := context.Background()
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	exec := newSeqExecutor()
	sub := &staleTestSubmitter{}
	const nodeID = "ungated-node"
	round := NewRound(nodeID, types.PartitionID(8), types.ShardID{}, exec, NewLoopbackDisseminator(), signer, sub, nil)
	health := NewHealth()
	round.SetHealth(health)
	node := &Node{round: round, health: health, recoveryDeps: RecoveryDeps{Gate: NewFinalityGate()}}

	require.Nil(t, round.childReadiness, "no gate is installed by default")
	require.Nil(t, round.certificateObserver, "and no observer is fed by default")

	require.NoError(t, round.HandleCertificate(ctx, internalGenesisUC(1000), internalTR(1, nodeID)))
	require.Equal(t, 1, sub.count(), "an ungated node votes exactly as before")
	require.True(t, health.Snapshot().Voting)

	node.SetChildReadiness(internalReadiness{})
	node.SetCertificateObserver(internalObserver{})
	require.NotNil(t, round.childReadiness, "the setter installs the gate")
	require.NotNil(t, round.certificateObserver, "the setter installs the observer")
}
