package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/signingauthority"
)

type followingOperator struct {
	status signingauthority.Status
	prove  func([]byte) (signingauthority.AdvanceResult, error)
}

func (o *followingOperator) Status(context.Context) (signingauthority.Status, error) {
	return o.status, nil
}
func (o *followingOperator) AdvanceWithProof(_ context.Context, proof []byte) (signingauthority.AdvanceResult, error) {
	return o.prove(proof)
}
func (o *followingOperator) ReplaceSession(context.Context) ([]byte, error) {
	return nil, errors.New("unexpected session replacement")
}

func TestAuthorityFollowsOnlyMissingProofsAndRepairsInterruptedPublication(t *testing.T) {
	o := &followingOperator{status: signingauthority.Status{RootEpoch: 128, LineageEpoch: 128, LineagePinned: true}}
	var fetched []uint64
	proofs, sessions := 0, 0
	errDisk := errors.New("publication interrupted")
	o.prove = func(raw []byte) (signingauthority.AdvanceResult, error) {
		require.Equal(t, []byte("epoch 129"), raw)
		proofs++
		o.status.RootEpoch, o.status.LineageEpoch, o.status.SessionIssued = 129, 129, false
		return signingauthority.AdvanceResult{Epoch: 129, Advanced: true}, nil
	}
	f := authorityActivationFollower{
		operator: o,
		fetch: func(_ context.Context, epoch uint64) ([]byte, error) {
			fetched = append(fetched, epoch)
			if epoch == 129 {
				return []byte("epoch 129"), nil
			}
			return nil, nil
		},
		ensureSession: func(_ context.Context, status signingauthority.Status) error {
			require.EqualValues(t, 129, status.RootEpoch)
			sessions++
			if sessions == 1 {
				return errDisk
			}
			o.status.SessionIssued = true
			return nil
		},
	}
	_, err := f.step(t.Context())
	require.NoError(t, err)
	require.Empty(t, fetched, "bootstrap stays operator-provisioned")
	o.status.SessionIssued = true
	_, err = f.step(t.Context())
	require.ErrorIs(t, err, errDisk)
	_, err = f.step(t.Context())
	require.NoError(t, err)
	require.Equal(t, []uint64{129}, fetched, "the verified proof was not replayed for the lost file")
	_, err = f.step(t.Context())
	require.NoError(t, err)
	require.Equal(t, []uint64{129, 130}, fetched)
	require.Equal(t, 1, proofs)
	require.Equal(t, 2, sessions)
}

func TestAuthorityFetchesCommittedSuccessorFromLoopback(t *testing.T) {
	var epoch atomic.Int32
	epoch.Store(1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/q3/status":
			_, _ = fmt.Fprintf(w, `{"activeEpoch":%d}`, epoch.Load())
		case "/api/v1/q3/bundle":
			_, _ = fmt.Fprintf(w, `{"epoch":%d,"bundle":"abcd"}`, epoch.Load())
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	}))
	defer server.Close()
	fetch := fetchAuthorityActivation(server.URL)
	raw, err := fetch(t.Context(), 2)
	require.NoError(t, err)
	require.Empty(t, raw)
	epoch.Store(2)
	raw, err = fetch(t.Context(), 2)
	require.NoError(t, err)
	require.Equal(t, []byte{0xab, 0xcd}, raw)
	f := signingAuthorityRunFlags{FollowRootRPC: server.URL, LineageGenesis: "genesis", FollowCredential: "client.cred", OperatorCredential: "operator.cred"}
	require.NoError(t, f.validateActivationFollower())
	f.FollowRootRPC = "http://192.0.2.2:8002"
	require.ErrorContains(t, f.validateActivationFollower(), "loopback")
}
