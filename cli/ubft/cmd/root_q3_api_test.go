package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3process"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
	basehex "github.com/unicitynetwork/bft-go-base/types/hex"
)

func callQ3(t *testing.T, a rootQ3API, path, remote string, body any) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	a.register(mux)
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.RemoteAddr = remote
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestTheRootStatusReportsTheChainAndTheStagedCandidate(t *testing.T) {
	var digest, body [32]byte
	digest[0], body[0] = 1, 2
	genesis := [32]byte{9}
	staged := &consensus.Q3Staged{CandidateDigest: digest, BodyID: body, Attempt: 3}
	a := rootQ3API{Status: func() (consensus.Q3Status, error) {
		return consensus.Q3Status{Network: 5, Genesis: genesis, Staged: staged, ActiveEpoch: 2}, nil
	}}
	rec := callQ3(t, a, "/api/v1/q3/status", "127.0.0.1:1", struct{}{})
	require.Equal(t, http.StatusOK, rec.Code)
	var got q3StatusResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.EqualValues(t, 5, got.Network)
	require.Equal(t, hex.EncodeToString(genesis[:]), got.Genesis)
	require.Equal(t, hex.EncodeToString(digest[:]), got.Staged.CandidateDigest)
	require.NotNil(t, got.Staged.Attempt)
	require.EqualValues(t, 3, *got.Staged.Attempt)
	require.EqualValues(t, 2, got.ActiveEpoch)

	staged = nil
	rec = callQ3(t, a, "/api/v1/q3/status", "127.0.0.1:1", struct{}{})
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	got = q3StatusResponse{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Nil(t, got.Staged, "nothing staged is reported as nothing")

	require.Equal(t, http.StatusForbidden, callQ3(t, a, "/api/v1/q3/status", "10.0.0.5:1", struct{}{}).Code, "operator only")
	a.Status = func() (consensus.Q3Status, error) { return consensus.Q3Status{}, errors.New("no Q3 history") }
	require.Equal(t, http.StatusUnprocessableEntity, callQ3(t, a, "/api/v1/q3/status", "127.0.0.1:1", struct{}{}).Code)
}

func TestTheRootSignersAreTheCommittedCertificatesSignersWithTheirEpochsWeights(t *testing.T) {
	tb := &types.RootTrustBaseV1{Epoch: 2, QuorumThreshold: 7, RootNodes: []*types.NodeInfo{
		{NodeID: "heavy", Stake: 6}, {NodeID: "l1", Stake: 1}, {NodeID: "l2", Stake: 1}, {NodeID: "l3", Stake: 1}}}
	sigs := func(ids ...string) map[string]basehex.Bytes {
		m := map[string]basehex.Bytes{}
		for _, id := range ids {
			m[id] = basehex.Bytes{1}
		}
		return m
	}
	var qc *rctypes.QuorumCert
	a := rootQ3API{
		State: func() (*abdrc.StateMsg, error) {
			return &abdrc.StateMsg{CommittedHead: &abdrc.CommittedBlock{CommitQc: qc}}, nil
		},
		Trust: func(epoch uint64) (*types.RootTrustBaseV1, error) {
			require.EqualValues(t, 2, epoch, "the epoch the certificate was verified under")
			return tb, nil
		},
	}
	signers := func() q3SignersResponse {
		rec := callQ3(t, a, "/api/v1/q3/signers", "127.0.0.1:1", struct{}{})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var out q3SignersResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
		return out
	}

	qc = &rctypes.QuorumCert{Scheme: 2, VoteInfo: &rctypes.RoundInfo{Epoch: 2, RoundNumber: 12}, Signatures: sigs("heavy", "l1")}
	got := signers()
	require.EqualValues(t, 7, got.SignedTotal, "heavy plus one light: 6+1")
	require.True(t, got.Quorum)
	require.EqualValues(t, 12, got.Round)

	qc.Signatures = sigs("l1", "l2", "l3")
	got = signers()
	require.EqualValues(t, 3, got.SignedTotal)
	require.False(t, got.Quorum, "three lights do not reach 7")

	qc.Signatures = sigs("heavy", "l1", "intruder")
	got = signers()
	require.EqualValues(t, 7, got.SignedTotal, "a signer outside the committee carries no weight")
	require.Len(t, got.Signers, 2)

	qc = nil
	require.Equal(t, http.StatusUnprocessableEntity, callQ3(t, a, "/api/v1/q3/signers", "127.0.0.1:1", struct{}{}).Code, "no committed certificate")
}

func TestTheRootServesTheActivationRecordHistoryAndBundleOfItsVerifiedActivation(t *testing.T) {
	ctx := context.Background()
	f := q3fixture.New(t, q3fixture.Options{})
	p := q3process.New(t, f)
	rt := p.Start()
	require.NoError(t, rt.Recover(ctx))
	a := rootQ3API{Rt: rt, Bundle: func(context.Context, uint64) (q3active.Bundle, error) { return p.Bundle(), nil }}

	rec := callQ3(t, a, "/api/v1/q3/activation", "127.0.0.1:1", q3EpochRequest{Epoch: f.Claim.Epoch})
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code, "nothing is staged yet")

	require.NoError(t, rt.Activate(ctx, p.Bundle()))
	rec = callQ3(t, a, "/api/v1/q3/activation", "127.0.0.1:1", q3EpochRequest{Epoch: f.Claim.Epoch})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var act q3active.ActivationRecord
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &act))
	require.EqualValues(t, 2, act.SigningScheme)
	require.Equal(t, f.Claim.Start, act.ActivationRound)

	rec = callQ3(t, a, "/api/v1/q3/history", "127.0.0.1:1", struct{}{})
	var hist q3HistoryResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &hist))
	require.Len(t, hist.Entries, 2)

	rec = callQ3(t, a, "/api/v1/q3/bundle", "127.0.0.1:1", q3EpochRequest{Epoch: f.Claim.Epoch})
	require.Equal(t, http.StatusOK, rec.Code)
	var bundle q3BundleResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &bundle))
	raw, err := hex.DecodeString(bundle.Bundle)
	require.NoError(t, err)
	want, err := q3active.EncodeBundle(p.Bundle())
	require.NoError(t, err)
	require.Equal(t, want, raw)
}

// A legacy certificate carries no scheme on the wire (0); the endpoint reports the scheme it is verified under, so a unit-epoch certificate
// is scheme 1 and a domain-bound one scheme 2.
func TestTheSignersEndpointReportsTheEffectiveSchemeOfALegacyCertificate(t *testing.T) {
	for wire, want := range map[uint64]uint64{0: 1, 1: 1, 2: 2} {
		api := rootQ3API{
			State: func() (*abdrc.StateMsg, error) {
				return &abdrc.StateMsg{CommittedHead: &abdrc.CommittedBlock{CommitQc: &rctypes.QuorumCert{Scheme: wire,
					VoteInfo: &rctypes.RoundInfo{Epoch: 1, RoundNumber: 7}, Signatures: map[string]basehex.Bytes{"n1": {1}}}}}, nil
			},
			Trust: func(uint64) (*types.RootTrustBaseV1, error) {
				return &types.RootTrustBaseV1{Epoch: 1, QuorumThreshold: 1, RootNodes: []*types.NodeInfo{{NodeID: "n1", Stake: 1}}}, nil
			},
		}
		got, err := api.signers()
		require.NoError(t, err)
		require.Equal(t, want, got.Scheme, "wire scheme %d", wire)
		require.EqualValues(t, 7, got.Round)
	}
}
