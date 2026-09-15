package shardnode_test

import (
	"context"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
)

type recordingObserver struct {
	mu  sync.Mutex
	got []shardnode.CertifiedCommit
}

func (o *recordingObserver) ObserveCommit(c shardnode.CertifiedCommit) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.got = append(o.got, c)
}

func (o *recordingObserver) commits() []shardnode.CertifiedCommit {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]shardnode.CertifiedCommit(nil), o.got...)
}

// observedRound is a single-validator round led by nodeID, with a commit observer attached. It does not use
// newTestRound, whose node id is built from raw key bytes: that id becomes the technical record's leader, and
// such a string is usually not UTF-8, so the record cannot be copied through canonical CBOR.
func observedRound(t *testing.T, nodeID string) (*shardnode.Round, *executortest.Fake, *recordingSubmitter, *recordingObserver) {
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	fake, sub, obs := executortest.New(), &recordingSubmitter{}, &recordingObserver{}
	r := shardnode.NewRound(nodeID, types.PartitionID(8), types.ShardID{}, fake, shardnode.NewLoopbackDisseminator(), signer, sub, nil)
	r.SetCommitObserver(obs)
	return r, fake, sub, obs
}

// TestRound_ReportsOnlyCertifiedCommits: the observer hears about exactly the blocks commitPrevious commits
// on a certificate's authority, with copies, and about nothing else: not the genesis round the executor did
// not move for, not a quiet round, not a re-delivery (#14 W2).
func TestRound_ReportsOnlyCertifiedCommits(t *testing.T) {
	ctx := context.Background()
	const nodeID = "node"
	r, fake, sub, obs := observedRound(t, nodeID)

	require.NoError(t, r.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID)))
	req1 := sub.last(t)

	fake.AddEntries([]byte("a transaction"))
	require.NoError(t, r.HandleCertificate(ctx, certifyFrom(req1, 2, 1000), tr(2, 0, nodeID)))
	require.Empty(t, obs.commits(), "the genesis round moved nothing, so nothing was committed")
	req2 := sub.last(t)
	require.NotEmpty(t, req2.InputRecord.BlockHash, "premise: round 2 carries a block")

	uc2 := certifyFrom(req2, 3, 1000)
	tr3 := tr(3, 0, nodeID)
	require.NoError(t, r.HandleCertificate(ctx, uc2, tr3))
	got := obs.commits()
	require.Len(t, got, 1)
	require.Equal(t, []byte(req2.InputRecord.BlockHash), []byte(got[0].BlockHash))
	require.Equal(t, uc2.InputRecord, got[0].Certificate.InputRecord)
	require.Equal(t, tr3, got[0].Technical)
	require.NotSame(t, uc2, got[0].Certificate, "the observer receives a copy")
	require.NotSame(t, tr3, got[0].Technical, "the observer receives a copy")

	require.NoError(t, r.HandleCertificate(ctx, uc2, tr3))
	require.Len(t, obs.commits(), 1, "a re-delivery commits nothing and reports nothing")

	req3 := sub.last(t)
	require.Empty(t, req3.InputRecord.BlockHash, "premise: round 3 is quiet")
	require.NoError(t, r.HandleCertificate(ctx, certifyFrom(req3, 4, 1000), tr(4, 0, nodeID)))
	require.Len(t, obs.commits(), 1, "a quiet round commits nothing and reports nothing")
}

// TestRound_AnUncopyableCommitIsNotReportedAndDoesNotFailTheRound: a certificate the round cannot copy for the
// observer is not reported, and the round still commits and continues. Being told is never a precondition of
// the round's own work.
func TestRound_AnUncopyableCommitIsNotReportedAndDoesNotFailTheRound(t *testing.T) {
	ctx := context.Background()
	nodeID := "node\xff"
	require.False(t, utf8.ValidString(nodeID), "premise: the leader id, and so the technical record, cannot be encoded as CBOR text")
	r, fake, sub, obs := observedRound(t, nodeID)

	require.NoError(t, r.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID)))
	fake.AddEntries([]byte("a transaction"))
	require.NoError(t, r.HandleCertificate(ctx, certifyFrom(sub.last(t), 2, 1000), tr(2, 0, nodeID)))
	req2 := sub.last(t)

	require.NoError(t, r.HandleCertificate(ctx, certifyFrom(req2, 3, 1000), tr(3, 0, nodeID)), "the round is not failed")
	head, err := fake.Head(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte(req2.InputRecord.BlockHash), []byte(head.Hash), "the certified block is still committed")
	require.Empty(t, obs.commits(), "a commit that cannot be copied is not reported")
}
