package service

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/signingauthority"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

/*
A pending authority behind its endpoints: the order a deployment follows. The authority starts
without a shard configuration, the operator reads its public key, writes the configuration naming
that key, and states it through the operator endpoint. Only then is a client credential issued.
*/
func TestAPendingAuthorityIsCompletedThroughTheOperatorEndpoint(t *testing.T) {
	ctx := context.Background()
	rootSigner, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb, ok := testtrustbase.NewTrustBase(t, rootSigner).(*types.RootTrustBaseV1)
	require.True(t, ok)

	authority, err := signingauthority.New(signingauthority.Enrollment{
		AuthorityID: "authority-1", NodeID: "node-1", NetworkID: 5, PartitionID: testPartitionID,
		ShardID: types.ShardID{}, ShardEpoch: 0, RootEpoch: signingauthority.PinRootEpoch(1),
		Profile: signingauthority.ProfileLegacyBCRv1,
	}, staticTrust{tb: tb})
	require.NoError(t, err)
	t.Cleanup(authority.Close)

	operatorCredential, err := NewCredential()
	require.NoError(t, err)
	server, err := NewServer(authority, Config{OperatorCredential: operatorCredential})
	require.NoError(t, err)
	t.Cleanup(server.Close)
	dir := socketDir(t)
	clientPath, operatorPath := filepath.Join(dir, "client.sock"), filepath.Join(dir, "operator.sock")
	clientListener, err := ListenUnix(clientPath)
	require.NoError(t, err)
	operatorListener, err := ListenUnix(operatorPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientListener.Close(); _ = operatorListener.Close() })
	go func() { _ = server.Serve(clientListener, ClientEndpoint) }()
	go func() { _ = server.Serve(operatorListener, OperatorEndpoint) }()

	operator, err := NewOperatorClient(ClientConfig{Dial: UnixDialer(operatorPath), Credential: operatorCredential, Timeout: 10 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { _ = operator.Close() })

	_, err = operator.ReplaceSession(ctx)
	require.ErrorIs(t, err, signingauthority.ErrEnrollmentIncomplete, "the refusal crosses the wire under its own name")

	enrollment, publicKey, err := operator.Enrollment(ctx)
	require.NoError(t, err)
	require.Empty(t, enrollment.ShardConfHash, "a pending enrollment reports no configuration")
	conf := &types.PartitionDescriptionRecord{
		Version: 1, NetworkID: 5, PartitionID: testPartitionID, PartitionTypeID: 1,
		ShardID: types.ShardID{}, Epoch: 0, TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 2500 * time.Millisecond,
		Validators: []*types.NodeInfo{{NodeID: "node-1", SigKey: publicKey, Stake: 1}},
	}

	t.Run("the client endpoint does not complete an enrollment", func(t *testing.T) {
		payload, err := types.Cbor.Marshal(conf)
		require.NoError(t, err)
		conn, err := net.Dial("unix", clientPath)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
		require.NoError(t, writeFrame(conn, wireRequest{Version: protocolVersion, Op: uint64(opCompleteEnrollment), Payload: payload}))
		var response wireResponse
		require.NoError(t, readFrame(conn, &response))
		require.Equal(t, errWrongEndpoint.Error(), response.Refusal)
		enrollment, _, err := operator.Enrollment(ctx)
		require.NoError(t, err)
		require.Empty(t, enrollment.ShardConfHash)
	})

	other := *conf
	other.Validators = []*types.NodeInfo{{NodeID: "node-1", SigKey: bytes.Clone(tb.RootNodes[0].SigKey), Stake: 1}}
	require.ErrorIs(t, operator.CompleteEnrollment(ctx, &other), signingauthority.ErrContextMismatch,
		"a configuration naming the node with another key is refused by the authority")

	require.NoError(t, operator.CompleteEnrollment(ctx, conf))
	require.ErrorIs(t, operator.CompleteEnrollment(ctx, conf), signingauthority.ErrContextMismatch, "and it is not reopened")

	credential, err := operator.ReplaceSession(ctx)
	require.NoError(t, err)
	client, err := NewClient(ClientConfig{Dial: UnixDialer(clientPath), Credential: credential, Timeout: 10 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	zero := make([]byte, 32)
	tr := &certification.TechnicalRecord{Round: 6, Epoch: 0, Leader: "node-1", StatHash: zero, FeeHash: zero}
	trHash, err := tr.Hash()
	require.NoError(t, err)
	stateRoot := bytes.Repeat([]byte{0xa1}, 32)
	uc := testcertificates.CreateUnicityCertificate(t, rootSigner, &types.InputRecord{
		Version: 1, RoundNumber: 5, PreviousHash: bytes.Repeat([]byte{0xa0}, 32), Hash: stateRoot,
		BlockHash: bytes.Repeat([]byte{0xb1}, 32), SummaryValue: []byte{}, Timestamp: 1,
	}, conf, 41, zero, trHash)
	proposed := &certification.BlockCertificationRequest{
		PartitionID: testPartitionID, ShardID: types.ShardID{}, NodeID: "node-1",
		InputRecord: &types.InputRecord{
			Version: 1, RoundNumber: 6, Epoch: 0, PreviousHash: stateRoot,
			Hash: bytes.Repeat([]byte{0xc1}, 32), BlockHash: bytes.Repeat([]byte{0xc2}, 32),
			SummaryValue: []byte{}, Timestamp: uc.UnicitySeal.Timestamp,
		},
	}

	authorization, err := client.Reserve(ctx, signingauthority.Request{UC: uc, Technical: tr, Proposed: proposed})
	require.NoError(t, err)
	require.NoError(t, client.Sign(ctx))
	require.NoError(t, client.RetainResponse(ctx))
	released, err := client.Release(ctx, authorization.AssignedRound, authorization.UnsignedDigest)
	require.NoError(t, err)
	var signed certification.BlockCertificationRequest
	require.NoError(t, types.Cbor.Unmarshal(released, &signed))
	verifier, err := conf.Validators[0].SigVerifier()
	require.NoError(t, err)
	require.NoError(t, signed.IsValid(verifier), "the response verifies under the key the completed configuration names")
	nextTrust := *tb
	nextTrust.Epoch = 2
	require.NoError(t, operator.AdvanceEpoch(ctx, conf, &nextTrust))
	_, err = client.RestoreStatus(ctx)
	require.ErrorIs(t, err, signingauthority.ErrFenced, "advance fences the previous credential")
	advanced, _, err := operator.Enrollment(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(2), *advanced.RootEpoch)
	newCredential, err := operator.ReplaceSession(ctx)
	require.NoError(t, err)
	newClient, err := NewClient(ClientConfig{Dial: UnixDialer(clientPath), Credential: newCredential, Timeout: 10 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { _ = newClient.Close() })
	status, err := newClient.RestoreStatus(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(6), status.ReservedRound)
}
