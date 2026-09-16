package consensus

import (
	"bytes"
	"context"
	"crypto"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontierclient"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/internal/frontiercodec"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	rctest "github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-go-base/types"
)

func encodeFrontierCut(t *testing.T, snapshot *storage.FrontierCutSnapshot, binding [32]byte) []byte {
	t.Helper()
	raw, err := frontiercodec.EncodeCutProof(binding, snapshot.RootRound, snapshot.RootEpoch, snapshot.RootHash, snapshot.CommitQC, frontiercodec.Pair{UC: &snapshot.LastCR.UC, TR: &snapshot.LastCR.Technical}, snapshot.ShardTreeCertificate, snapshot.UnicityTreeCertificate)
	require.NoError(t, err)
	return raw
}

func TestFrontierCommittedCutFromRealLoopVerifiesAgainstLiveCandidate(t *testing.T) {
	shardNodes, shardInfos := rctest.CreateTestNodes(t, 1)
	cms, _ := createConsensusManagersWithOptions(t, 4, shardInfos, func(tb *types.RootTrustBaseV1) []Option {
		return []Option{WithFrontierSampler(FrontierSamplerConfig{TrustBase: tb, QueueSize: 2, MaxPending: 4}), WithFrontierSigning()}
	}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	var running atomic.Int32
	for _, cm := range cms {
		running.Add(1)
		go func() { defer running.Add(-1); _ = cm.Run(ctx) }()
	}
	t.Cleanup(func() {
		cancel()
		require.Eventually(t, func() bool { return running.Load() == 0 }, 3*time.Second, 20*time.Millisecond)
	})
	require.Eventually(t, func() bool { return cms[0].pacemaker.GetCurrentRound() >= 5 }, 5*time.Second, 20*time.Millisecond)
	pdr, err := cms[0].orchestration.ShardConfig(partitionID, shardID, 1)
	require.NoError(t, err)
	conf, err := pdr.Hash(crypto.SHA256)
	require.NoError(t, err)
	origin, nonce := bytes.Repeat([]byte{0xa4}, 32), bytes.Repeat([]byte{0xb5}, 32)
	request := SignedFrontierRequest{FrontierRequest: FrontierRequest{NetworkID: pdr.NetworkID, PartitionID: pdr.PartitionID, ShardID: pdr.ShardID, FullShardConfHash: conf}, RootEpoch: cms[0].frontier.trust.Epoch, GenesisOriginIdentity: origin, Nonce: nonce}
	collector, err := frontierclient.NewCollector(frontierclient.Profile{TrustBase: cms[0].frontier.trust, NetworkID: pdr.NetworkID, PartitionID: pdr.PartitionID, ShardID: pdr.ShardID, FullShardConfHash: conf, RootEpoch: request.RootEpoch, GenesisOriginIdentity: origin, Nonce: nonce})
	require.NoError(t, err)
	var lastResponse *SignedFrontierResponse
	for _, cm := range cms {
		var response *SignedFrontierResponse
		require.Eventually(t, func() bool { response, err = cm.SampleSignedFrontier(context.Background(), request); return err == nil }, 3*time.Second, 20*time.Millisecond)
		require.NoError(t, collector.Add(response.CanonicalBytes()).Err)
		lastResponse = response
	}
	candidate := collector.Snapshot().Candidate()
	require.True(t, candidate.Valid())

	var cut *storage.FrontierCutSnapshot
	require.Eventually(t, func() bool {
		cut, err = cms[0].blockStore.ReadFrontierCutSnapshot(partitionID, shardID)
		return err == nil && cut.RootRound >= candidate.Floor()
	}, 5*time.Second, 20*time.Millisecond)
	require.Less(t, cut.LastCR.UC.UnicitySeal.RootChainRoundNumber, cut.RootRound)
	raw := encodeFrontierCut(t, cut, collector.AcquisitionBinding())
	verified, err := collector.AddCut(raw)
	require.NoError(t, err)
	require.True(t, verified.Valid())
	require.Equal(t, cut.RootRound, verified.CommittedRound())
	require.Equal(t, candidate.PairIdentity(), verified.PairIdentity())
	require.Equal(t, cut.RootHash, verified.RootHash())
	verifiedBytes := verified.CanonicalBytes()
	verifiedBytes[0] ^= 1
	require.Equal(t, raw, verified.CanonicalBytes())

	var proof frontiercodec.CutProof
	require.NoError(t, types.Cbor.Unmarshal(raw, &proof))
	// The genuine frontier QC votes at F but commits F-1. Even with a valid
	// membership path for the unchanged leaf, its committed round is too low.
	var lowerQC drctypes.QuorumCert
	require.NoError(t, types.Cbor.Unmarshal(candidate.CanonicalQC(), &lowerQC))
	require.Equal(t, candidate.Floor(), lowerQC.VoteInfo.RoundNumber)
	require.Equal(t, candidate.Floor()-1, lowerQC.LedgerCommitInfo.RootChainRoundNumber)
	lower := proof
	lower.RootRound = lowerQC.LedgerCommitInfo.RootChainRoundNumber
	lower.RootHash = bytes.Clone(lowerQC.LedgerCommitInfo.Hash)
	lower.CommitQC = candidate.CanonicalQC()
	lowerRaw, err := types.Cbor.Marshal(lower)
	require.NoError(t, err)
	_, err = collector.AddCut(lowerRaw)
	require.ErrorIs(t, err, frontierclient.ErrUnauthentic)

	mutations := []struct {
		name string
		fn   func(*frontiercodec.CutProof)
	}{
		{"binding", func(p *frontiercodec.CutProof) { p.AcquisitionBinding[0] ^= 1 }},
		{"root", func(p *frontiercodec.CutProof) { p.RootHash[0] ^= 1 }},
		{"round", func(p *frontiercodec.CutProof) { p.RootRound++ }},
		{"epoch", func(p *frontiercodec.CutProof) { p.RootEpoch++ }},
		{"membership", func(p *frontiercodec.CutProof) { p.ShardCertificate[len(p.ShardCertificate)-1] ^= 1 }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			cloneBytes, cloneErr := types.Cbor.Marshal(proof)
			require.NoError(t, cloneErr)
			var changed frontiercodec.CutProof
			require.NoError(t, types.Cbor.Unmarshal(cloneBytes, &changed))
			tc.fn(&changed)
			changedRaw, cloneErr := types.Cbor.Marshal(changed)
			require.NoError(t, cloneErr)
			_, cloneErr = collector.AddCut(changedRaw)
			require.Error(t, cloneErr)
		})
	}

	t.Run("null path item", func(t *testing.T) {
		changed := proof
		var cert types.UnicityTreeCertificate
		require.NoError(t, types.Cbor.Unmarshal(changed.UnicityCertificate, &cert))
		cert.HashSteps = append(cert.HashSteps, nil)
		changed.UnicityCertificate, err = types.Cbor.Marshal(&cert)
		require.NoError(t, err)
		changedRaw, marshalErr := types.Cbor.Marshal(changed)
		require.NoError(t, marshalErr)
		require.NotPanics(t, func() {
			_, marshalErr = collector.AddCut(changedRaw)
		})
		require.Error(t, marshalErr)
	})

	t.Run("later seal substitution", func(t *testing.T) {
		changed := proof
		var pair frontiercodec.Pair
		require.NoError(t, types.Cbor.Unmarshal(changed.Pair, &pair))
		pair.UC.UnicitySeal.Timestamp++
		pair.UC.UnicitySeal.Signatures = nil
		for _, cm := range cms {
			require.NoError(t, pair.UC.UnicitySeal.Sign(cm.frontier.author, cm.frontier.signer))
		}
		changed.Pair, err = types.Cbor.Marshal(pair)
		require.NoError(t, err)
		changedRaw, marshalErr := types.Cbor.Marshal(changed)
		require.NoError(t, marshalErr)
		_, marshalErr = collector.AddCut(changedRaw)
		require.ErrorIs(t, marshalErr, frontierclient.ErrUnauthentic)
	})

	t.Run("signed cut for wrong shard configuration", func(t *testing.T) {
		changed := proof
		var pair frontiercodec.Pair
		require.NoError(t, types.Cbor.Unmarshal(changed.Pair, &pair))
		wrongConf := bytes.Repeat([]byte{0x91}, 32)
		trHash, hashErr := pair.TR.Hash()
		require.NoError(t, hashErr)
		shardTree, hashErr := types.CreateShardTree(types.ShardingScheme{}, []types.ShardTreeInput{{Shard: shardID, IR: pair.UC.InputRecord, TRHash: trHash, ShardConfHash: wrongConf}}, crypto.SHA256)
		require.NoError(t, hashErr)
		shardCert, hashErr := shardTree.Certificate(shardID)
		require.NoError(t, hashErr)
		ut, hashErr := types.NewUnicityTree(crypto.SHA256, []*types.UnicityTreeData{{Partition: partitionID, ShardTreeRoot: shardTree.RootHash()}})
		require.NoError(t, hashErr)
		unicityCert, hashErr := ut.Certificate(partitionID)
		require.NoError(t, hashErr)
		var qc drctypes.QuorumCert
		require.NoError(t, types.Cbor.Unmarshal(changed.CommitQC, &qc))
		qc.LedgerCommitInfo.Hash = ut.RootHash()
		qc.LedgerCommitInfo.Signatures = nil
		qc.Signatures = nil
		for _, cm := range cms {
			require.NoError(t, qc.LedgerCommitInfo.Sign(cm.frontier.author, cm.frontier.signer))
		}
		qc.Signatures = qc.LedgerCommitInfo.Signatures
		changed.RootHash = ut.RootHash()
		changed.CommitQC, err = types.Cbor.Marshal(qc)
		require.NoError(t, err)
		changed.ShardCertificate, err = types.Cbor.Marshal(shardCert)
		require.NoError(t, err)
		changed.UnicityCertificate, err = types.Cbor.Marshal(unicityCert)
		require.NoError(t, err)
		changedRaw, marshalErr := types.Cbor.Marshal(changed)
		require.NoError(t, marshalErr)
		_, marshalErr = collector.AddCut(changedRaw)
		require.ErrorIs(t, marshalErr, frontierclient.ErrUnauthentic)
	})

	t.Run("invalid and genesis commit QC", func(t *testing.T) {
		var qc drctypes.QuorumCert
		require.NoError(t, types.Cbor.Unmarshal(proof.CommitQC, &qc))
		for author := range qc.Signatures {
			qc.Signatures[author][0] ^= 1
			break
		}
		changed := proof
		changed.CommitQC, err = types.Cbor.Marshal(qc)
		require.NoError(t, err)
		changedRaw, marshalErr := types.Cbor.Marshal(changed)
		require.NoError(t, marshalErr)
		_, marshalErr = collector.AddCut(changedRaw)
		require.ErrorIs(t, marshalErr, frontierclient.ErrUnauthentic)

		qc.VoteInfo.RoundNumber = drctypes.GenesisRootRound
		qc.VoteInfo.ParentRoundNumber = 0
		qc.LedgerCommitInfo.RootChainRoundNumber = 0
		qc.Signatures = nil
		changed.CommitQC, err = types.Cbor.Marshal(qc)
		require.NoError(t, err)
		changedRaw, marshalErr = types.Cbor.Marshal(changed)
		require.NoError(t, marshalErr)
		_, marshalErr = collector.AddCut(changedRaw)
		require.ErrorIs(t, marshalErr, frontierclient.ErrUnauthentic)
	})

	t.Run("pair null path item", func(t *testing.T) {
		var wire frontiercodec.Reply
		require.NoError(t, types.Cbor.Unmarshal(lastResponse.CanonicalBytes(), &wire))
		var pair frontiercodec.Pair
		require.NoError(t, types.Cbor.Unmarshal(wire.Pair, &pair))
		pair.UC.UnicityTreeCertificate.HashSteps = append(pair.UC.UnicityTreeCertificate.HashSteps, nil)
		wire.Pair, err = types.Cbor.Marshal(pair)
		require.NoError(t, err)
		changedRaw, marshalErr := types.Cbor.Marshal(wire)
		require.NoError(t, marshalErr)
		var add frontierclient.AddResult
		require.NotPanics(t, func() { add = collector.Add(changedRaw) })
		require.ErrorIs(t, add.Err, frontierclient.ErrUnauthentic)
	})

	// A later genuine ordinary assignment invalidates the live cut, including
	// when its response author was already counted in the initial quorum.
	si, err := cms[0].ShardInfo(partitionID, shardID)
	require.NoError(t, err)
	require.NoError(t, cms[0].RequestCertification(context.Background(), IRChangeRequest{Partition: partitionID, Shard: shardID, Reason: Quorum, Requests: buildBlockCertificationRequest(t, shardNodes, si.LastCR)}))
	var ordinary *SignedFrontierResponse
	require.Eventually(t, func() bool {
		ordinary, err = cms[0].SampleSignedFrontier(context.Background(), request)
		if err != nil {
			return false
		}
		var wire frontiercodec.Reply
		var pair frontiercodec.Pair
		return types.Cbor.Unmarshal(ordinary.CanonicalBytes(), &wire) == nil && types.Cbor.Unmarshal(wire.Pair, &pair) == nil && pair.UC.InputRecord.RoundNumber > 0
	}, 5*time.Second, 20*time.Millisecond)
	var ordinaryWire frontiercodec.Reply
	require.NoError(t, types.Cbor.Unmarshal(ordinary.CanonicalBytes(), &ordinaryWire))
	negativeRaw, err := types.Cbor.Marshal(frontiercodec.CutProof{Version: 99, AcquisitionBinding: []byte{1}, Pair: ordinaryWire.Pair})
	require.NoError(t, err)
	preCandidate, err := frontierclient.NewCollector(frontierclient.Profile{TrustBase: cms[0].frontier.trust, NetworkID: pdr.NetworkID, PartitionID: pdr.PartitionID, ShardID: pdr.ShardID, FullShardConfHash: conf, RootEpoch: request.RootEpoch, GenesisOriginIdentity: origin, Nonce: nonce})
	require.NoError(t, err)
	_, err = preCandidate.AddCut(negativeRaw)
	require.ErrorIs(t, err, frontierclient.ErrUnsupported)
	require.True(t, preCandidate.Snapshot().Ordinary())
	_, err = collector.AddCut(negativeRaw)
	require.ErrorIs(t, err, frontierclient.ErrUnsupported)
	firstOrdinary := collector.Snapshot().FirstOrdinary().CanonicalPair()
	_, err = collector.AddCut(negativeRaw)
	require.ErrorIs(t, err, frontierclient.ErrUnsupported)
	require.False(t, collector.Snapshot().VerifiedCut().Valid())
	require.Equal(t, firstOrdinary, collector.Snapshot().LatestOrdinaryArrival().CanonicalPair())
	require.True(t, verified.Valid()) // prior output is diagnostic, not live authority
}
