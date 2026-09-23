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
	r := shardnode.NewRound("journal-leader", 8, types.ShardID{}, executortest.New(), d, signer, sub, nil)
	r.SetProposalJournal(j)
	r.SetCertificationSigner(spy)
	err = r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, "journal-leader"))
	require.ErrorContains(t, err, "journal fsync failed")
	require.Equal(t, 1, j.calls)
	require.Zero(t, d.published, "a proposal cannot escape before its body is durable")
	require.Zero(t, spy.calls, "the signer cannot authorize an unretained proposal")
	require.Empty(t, sub.got)
}
