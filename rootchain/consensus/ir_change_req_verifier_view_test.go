package consensus

import (
	"bytes"
	"crypto"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	abtypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

var _ storage.RequestViewVerifier = (*IRChangeReqVerifier)(nil)

// viewTarget is a unit-weight shard of three identities, resolved through the exported snapshot API only.
type viewTarget struct {
	nodes []*testutils.TestNode
	infos []*types.NodeInfo
	view  *storage.RequestRoundView
}

func newViewTarget(t *testing.T, round uint64, purpose storage.RequestPurpose) *viewTarget {
	t.Helper()
	return newViewTargetWith(t, round, purpose, nil, nil)
}

// newViewTargetWith is newViewTarget with the shard's partition parameters and, when given, the root its previous state has.
func newViewTargetWith(t *testing.T, round uint64, purpose storage.RequestPurpose, params map[string]string, rootHash []byte) *viewTarget {
	t.Helper()
	nodes, infos := testutils.CreateTestNodes(t, 3)
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 1, PartitionTypeID: 1, ShardID: types.ShardID{},
		UnitIDLen: 256, TypeIDLen: 32, T2Timeout: 2500 * time.Millisecond, Validators: infos, PartitionParams: params}
	si, err := storage.NewShardInfo(pdr, crypto.SHA256)
	require.NoError(t, err)
	si.RootHash = bytes.Repeat([]byte{0x5C}, 32)
	if rootHash != nil {
		si.RootHash = rootHash
	}
	ir := &types.InputRecord{Version: 1, RoundNumber: si.TR.Round, PreviousHash: []byte{1}, Hash: si.RootHash, BlockHash: []byte{2}, SummaryValue: []byte{3}, Timestamp: 1000}
	si.LastCR = &certification.CertificationResponse{Partition: 1, Technical: si.TR, UC: types.UnicityCertificate{Version: 1, InputRecord: ir,
		UnicitySeal: &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: 10, Timestamp: 1000, Hash: []byte{4}}}}
	body, parent := bytes.Repeat([]byte{0xA0}, 32), bytes.Repeat([]byte{0x9D}, 32)
	anchor, err := storage.NewRequestAnchor(pdr, crypto.SHA256, 3, body, 7)
	require.NoError(t, err)
	snap, err := storage.NewRequestSnapshot(5, crypto.SHA256, si, parent, nil, anchor)
	require.NoError(t, err)
	digest, err := si.LastCR.UC.Hash(crypto.SHA256)
	require.NoError(t, err)
	view, err := storage.ResolveRequestContext(storage.RequestQuery{Network: 5, Partition: 1, Shard: types.ShardID{}, RootEpoch: 3, RootRound: round,
		RootBodyID: body, Version: 7, ParentID: parent, PrevUCDigest: digest, Purpose: purpose}, snap)
	require.NoError(t, err)
	return &viewTarget{nodes: nodes, infos: infos, view: view}
}

func (v *viewTarget) request(t *testing.T, i int) *certification.BlockCertificationRequest {
	t.Helper()
	tr := v.view.ExpectedTR()
	req := &certification.BlockCertificationRequest{PartitionID: 1, ShardID: types.ShardID{}, NodeID: v.infos[i].NodeID, InputRecord: &types.InputRecord{
		Version: 1, RoundNumber: tr.Round, PreviousHash: v.view.PreviousStateHash(), Hash: []byte{9}, BlockHash: []byte{8}, SummaryValue: []byte{3}, Timestamp: 1000}}
	require.NoError(t, req.Sign(v.nodes[i].Signer))
	return req
}

// The view-aware verifier judges under the view it is given and never reads the last committed ShardInfo.
func TestVerifyIRChangeReqViewNeverReadsCommittedState(t *testing.T) {
	state := &MockState{shardInfo: func(types.PartitionID, types.ShardID) *storage.ShardInfo {
		t.Fatal("the view branch read the last committed shard info")
		return nil
	}}
	ver, err := NewIRChangeReqVerifier(&Parameters{BlockRate: 900 * time.Millisecond}, state)
	require.NoError(t, err)
	require.Nil(t, ver.RequestHistory(), "production keeps the legacy dispatch")

	v := newViewTarget(t, 12, storage.PurposeCertify)
	res, err := ver.VerifyIRChangeReqView(v.view, &abtypes.IRChangeReq{Partition: 1, CertReason: abtypes.Quorum,
		Requests: []*certification.BlockCertificationRequest{v.request(t, 0), v.request(t, 1)}})
	require.NoError(t, err)
	require.Equal(t, v.view.ViewKey(), res.ViewKey)
	require.Len(t, res.ProofDigest, 32)

	_, err = ver.VerifyIRChangeReqView(v.view, &abtypes.IRChangeReq{Partition: 1, CertReason: abtypes.Quorum,
		Requests: []*certification.BlockCertificationRequest{v.request(t, 0)}})
	require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached)
	require.ErrorIs(t, err, abtypes.ErrInvalidRequest)

	_, err = ver.VerifyIRChangeReqView(nil, &abtypes.IRChangeReq{})
	require.ErrorIs(t, err, abtypes.ErrInvalidRequest)
	_, err = ver.VerifyIRChangeReqView(v.view, nil)
	require.ErrorIs(t, err, abtypes.ErrInvalidRequest)
	_, err = ver.VerifyIRChangeReqView(v.view, &abtypes.IRChangeReq{Partition: 2, CertReason: abtypes.Quorum})
	require.ErrorIs(t, err, abtypes.ErrInvalidRequest, "a proof of another shard is not judged under this view")

	custom := &fakeHistory{}
	ver.SetRequestHistory(custom)
	require.Same(t, custom, ver.RequestHistory())
}

type fakeHistory struct{ storage.RequestHistory }

// T2 is elapsed root rounds from the view's previous UC alone; the proof stays empty.
func TestVerifyIRChangeReqViewTimeoutIsElapsedRounds(t *testing.T) {
	ver, err := NewIRChangeReqVerifier(&Parameters{BlockRate: 900 * time.Millisecond}, &MockState{})
	require.NoError(t, err)
	const t2 = 6 // uint64(2500ms / 450ms) + 1
	timeout := &abtypes.IRChangeReq{Partition: 1, CertReason: abtypes.T2Timeout}

	due := newViewTarget(t, 10+t2, storage.PurposeTimeout)
	res, err := ver.VerifyIRChangeReqView(due.view, timeout)
	require.NoError(t, err, "control: the due timeout with an empty proof is accepted")
	require.NotNil(t, res.IR)

	t.Run("premature timeout", func(t *testing.T) {
		early := newViewTarget(t, 10+t2-1, storage.PurposeTimeout)
		res, err := ver.VerifyIRChangeReqView(early.view, timeout)
		require.ErrorIs(t, err, abtypes.ErrInvalidRequest)
		require.ErrorContains(t, err, "timeout proof")
		require.Nil(t, res)
	})
	t.Run("timeout proof with requests", func(t *testing.T) {
		res, err := ver.VerifyIRChangeReqView(due.view, &abtypes.IRChangeReq{Partition: 1, CertReason: abtypes.T2Timeout,
			Requests: []*certification.BlockCertificationRequest{due.request(t, 0)}})
		require.ErrorIs(t, err, abtypes.ErrInvalidRequest)
		require.ErrorContains(t, err, "proof contains requests")
		require.Nil(t, res)
	})
}

func TestVerifyIRChangeReqViewRefusesTheControlPartitionInProfile2(t *testing.T) {
	ver, err := NewIRChangeReqVerifier(&Parameters{BlockRate: time.Second, NetworkProfileVersion: 2}, &MockState{})
	require.NoError(t, err)
	v := newViewTarget(t, 12, storage.PurposeCertify)
	_, err = ver.VerifyIRChangeReqView(v.view, &abtypes.IRChangeReq{Partition: abtypes.ControlPartition, CertReason: abtypes.Quorum})
	require.ErrorIs(t, err, abtypes.ErrControlPartition)
}

// One identity for the duplicate refusal in both verifiers.
func TestDuplicateChangeReqIsOneSentinel(t *testing.T) {
	require.Same(t, storage.ErrDuplicateChangeReq, ErrDuplicateChangeReq)
}

func TestVerifyIRChangeReqViewNilRequestInProfile2(t *testing.T) {
	ver, err := NewIRChangeReqVerifier(&Parameters{BlockRate: time.Second, NetworkProfileVersion: 2}, &MockState{})
	require.NoError(t, err)
	v := newViewTarget(t, 12, storage.PurposeCertify)
	_, err = ver.VerifyIRChangeReqView(v.view, nil)
	require.ErrorIs(t, err, abtypes.ErrInvalidRequest)
}
