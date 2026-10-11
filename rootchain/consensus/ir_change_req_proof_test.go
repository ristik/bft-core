package consensus

import (
	"bytes"
	"crypto"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	abtypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier/rsmt"
	testpartition "github.com/unicitynetwork/bft-core/rootchain/partitions/testutils"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

// Roots that vote on an IR change they did not receive from the shard (the leader that was forwarded it, every follower that validates the proposal,
// a root that replays the block) judge the configured consistency proof of every carried request themselves: a Byzantine receiving root that skipped
// its own check, or a shard quorum signing a request whose proof does not hold, does not get an invalid transition certified. The requests below are
// correctly shard-signed; only their proof differs.

var rsmtParams = map[string]string{"proof_type": "aggregator_rsmt_v1"}

// proofTransition is the insertion of one new leaf next to a stored one, with the proof envelope built under the reference time tau.
type proofTransition struct {
	prev, next [32]byte
	envelope   []byte
}

func newProofTransition(t *testing.T, tau uint64) proofTransition {
	return newProofTransitionOf(t, tau, 0x80)
}

// newProofTransitionOf inserts the leaf of key first byte newKey: another key is another transition from the same previous root.
func newProofTransitionOf(t *testing.T, tau uint64, newKey byte) proofTransition {
	t.Helper()
	kOld, kNew := [32]byte{0x00}, [32]byte{newKey}
	vOld, declared := []byte("stored value of the earlier round"), bytes.Repeat([]byte{0x77}, 32)
	hOld := rsmt.HashLeaf(kOld, vOld)
	stored := rsmt.LeafValue(declared, tau)
	hNew := rsmt.HashLeaf(kNew, stored[:])
	newRoot := rsmt.HashNode(hOld, hNew, 0, rsmt.PrefixRegion(kOld, 0))
	// post-order: the preserved leaf opened (O_L), the new leaf (L), the junction N(0)
	proof := append([]byte{0x04}, kOld[:]...)
	proof = append(proof, byte(len(vOld)>>8), byte(len(vOld)))
	proof = append(proof, vOld...)
	proof = append(proof, 0x01, 0x02, 0x00)
	env, err := rsmt.EncodeEnvelope([]rsmt.Leaf{{Key: kNew, Value: declared}}, proof)
	require.NoError(t, err)
	return proofTransition{prev: hOld, next: newRoot, envelope: env}
}

type proofCase struct {
	proof, hash []byte
	// refusedAs is the verifier's own reason, so each case is judged for the one thing that is wrong with it
	refusedAs error
}

// proofCases are the proofs a request may carry besides the valid one; each differs from it in exactly one thing.
func proofCases(t *testing.T, ts uint64, valid proofTransition) map[string]proofCase {
	other := valid.next
	other[0] ^= 0xFF
	underOtherTime := newProofTransition(t, ts+1)
	return map[string]proofCase{
		"missing proof":                             {proof: nil, hash: valid.next[:], refusedAs: zkverifier.ErrInvalidProofFormat},
		"garbage proof":                             {proof: []byte{1, 2, 3}, hash: valid.next[:], refusedAs: zkverifier.ErrInvalidProofFormat},
		"proof of another new root":                 {proof: valid.envelope, hash: other[:], refusedAs: zkverifier.ErrProofVerificationFailed},
		"root derived under another reference time": {proof: valid.envelope, hash: underOtherTime.next[:], refusedAs: zkverifier.ErrProofVerificationFailed},
	}
}

func TestVerifyIRChangeReqViewJudgesTheConfiguredProof(t *testing.T) {
	const ts = 1000
	valid := newProofTransition(t, ts)
	ver, err := NewIRChangeReqVerifier(&Parameters{BlockRate: 900 * time.Millisecond}, &MockState{})
	require.NoError(t, err)

	build := func(v *viewTarget, i int, proof, hash []byte) *certification.BlockCertificationRequest {
		req := v.request(t, i)
		req.ZkProof, req.InputRecord.Hash = proof, hash
		require.NoError(t, req.Sign(v.nodes[i].Signer))
		return req
	}
	change := func(v *viewTarget, second *certification.BlockCertificationRequest) *abtypes.IRChangeReq {
		return &abtypes.IRChangeReq{Partition: 1, CertReason: abtypes.Quorum,
			Requests: []*certification.BlockCertificationRequest{build(v, 0, valid.envelope, valid.next[:]), second}}
	}

	t.Run("a valid proof passes", func(t *testing.T) {
		v := newViewTargetWith(t, 12, storage.PurposeCertify, rsmtParams, valid.prev[:])
		res, err := ver.VerifyIRChangeReqView(v.view, change(v, build(v, 1, valid.envelope, valid.next[:])))
		require.NoError(t, err)
		require.Equal(t, valid.next[:], []byte(res.IR.Hash))
	})
	for name, c := range proofCases(t, ts, valid) {
		t.Run(name+" is refused, in any carried request", func(t *testing.T) {
			v := newViewTargetWith(t, 12, storage.PurposeCertify, rsmtParams, valid.prev[:])
			// the second request only: the first is valid and would have been enough for the quorum's group
			res, err := ver.VerifyIRChangeReqView(v.view, change(v, build(v, 1, c.proof, c.hash)))
			require.Nil(t, res)
			if c.hash == nil || !bytes.Equal(c.hash, valid.next[:]) {
				// its input record differs from the first request's: the groups differ, which the quorum check refuses first
				require.Error(t, err)
				return
			}
			require.ErrorIs(t, err, ErrProofInvalid)
			require.ErrorIs(t, err, c.refusedAs)
		})
		t.Run(name+" is refused, in the only quorum group", func(t *testing.T) {
			v := newViewTargetWith(t, 12, storage.PurposeCertify, rsmtParams, valid.prev[:])
			req := &abtypes.IRChangeReq{Partition: 1, CertReason: abtypes.Quorum, Requests: []*certification.BlockCertificationRequest{
				build(v, 0, c.proof, c.hash), build(v, 1, c.proof, c.hash)}}
			res, err := ver.VerifyIRChangeReqView(v.view, req)
			require.Nil(t, res)
			require.ErrorIs(t, err, ErrProofInvalid)
			require.ErrorIs(t, err, c.refusedAs)
		})
	}
	t.Run("a shard without a configured proof takes the aggregators' signatures alone (control)", func(t *testing.T) {
		v := newViewTarget(t, 12, storage.PurposeCertify)
		ver, err := NewIRChangeReqVerifier(&Parameters{BlockRate: 900 * time.Millisecond}, &MockState{})
		require.NoError(t, err)
		_, err = ver.VerifyIRChangeReqView(v.view, &abtypes.IRChangeReq{Partition: 1, CertReason: abtypes.Quorum,
			Requests: []*certification.BlockCertificationRequest{build(v, 0, []byte{1, 2, 3}, []byte{9}), build(v, 1, []byte{1, 2, 3}, []byte{9})}})
		require.NoError(t, err)
	})
}

func TestVerifyIRChangeReqJudgesTheConfiguredProof(t *testing.T) {
	const ts = 1
	valid := newProofTransition(t, ts)
	tn := testutils.NewTestNode(t)
	pdr := func(params map[string]string) *types.PartitionDescriptionRecord {
		return &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: partitionID1, PartitionTypeID: 1, TypeIDLen: 8, UnitIDLen: 256,
			T2Timeout: 2000 * time.Millisecond, Validators: []*types.NodeInfo{tn.NodeInfo(t)}, EpochStart: 1, PartitionParams: params}
	}
	verifier := func(params map[string]string) *IRChangeReqVerifier {
		conf := pdr(params)
		orchestration := testpartition.NewOrchestration(t, logger.New(t))
		require.NoError(t, orchestration.AddShardConfig(conf))
		state := &MockState{shardInfo: func(id types.PartitionID, _ types.ShardID) *storage.ShardInfo {
			if id != conf.PartitionID {
				return nil
			}
			si, err := storage.NewShardInfo(conf, crypto.SHA256)
			require.NoError(t, err)
			si.LastCR = &certification.CertificationResponse{
				UC:        types.UnicityCertificate{UnicitySeal: &types.UnicitySeal{RootChainRoundNumber: 2, Timestamp: 1}, InputRecord: &types.InputRecord{}},
				Technical: certification.TechnicalRecord{Round: 2},
			}
			si.RootHash = valid.prev[:]
			return si
		}}
		ver, err := NewIRChangeReqVerifier(&Parameters{BlockRate: 500 * time.Millisecond, HashAlgorithm: crypto.SHA256}, state)
		require.NoError(t, err)
		return ver
	}
	change := func(proof, hash []byte) *abtypes.IRChangeReq {
		req := &certification.BlockCertificationRequest{PartitionID: partitionID1, NodeID: tn.PeerConf.ID.String(), ZkProof: proof, InputRecord: &types.InputRecord{
			Version: 1, PreviousHash: valid.prev[:], Hash: hash, BlockHash: []byte{4, 4, 4}, SummaryValue: []byte{5, 5, 5}, RoundNumber: 2, Timestamp: ts}}
		require.NoError(t, req.Sign(tn.Signer))
		return &abtypes.IRChangeReq{Partition: partitionID1, CertReason: abtypes.Quorum, Requests: []*certification.BlockCertificationRequest{req}}
	}

	t.Run("a valid proof passes the verifier and the buffer a leader admits it through", func(t *testing.T) {
		ver := verifier(rsmtParams)
		ir, err := ver.VerifyIRChangeReq(2, change(valid.envelope, valid.next[:]))
		require.NoError(t, err)
		require.Equal(t, valid.next[:], []byte(ir.Hash))
		require.NoError(t, NewIrReqBuffer(logger.New(t), 1).Add(2, change(valid.envelope, valid.next[:]), ver))
	})
	for name, c := range proofCases(t, ts, valid) {
		t.Run(name+" is refused", func(t *testing.T) {
			ver := verifier(rsmtParams)
			ir, err := ver.VerifyIRChangeReq(2, change(c.proof, c.hash))
			require.Nil(t, ir)
			require.ErrorIs(t, err, ErrProofInvalid)
			require.ErrorIs(t, err, c.refusedAs)
			// the leader refuses to buffer it, the follower to vote for the block that carries it
			require.ErrorIs(t, NewIrReqBuffer(logger.New(t), 1).Add(2, change(c.proof, c.hash), ver), ErrProofInvalid)
		})
	}
	t.Run("a shard without a configured proof takes the aggregators' signatures alone (control)", func(t *testing.T) {
		_, err := verifier(nil).VerifyIRChangeReq(2, change([]byte{1, 2, 3}, []byte{3, 3, 3}))
		require.NoError(t, err)
	})
}
