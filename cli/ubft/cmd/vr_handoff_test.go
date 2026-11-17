package cmd

import (
	"bytes"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/vrhandofffix"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/vrschedule"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

// fixtureOperator is a root's operator surface over the protocol fixture: the intent it derives, the body of an assembled candidate, and
// the certificate check SubmitVRCertificate runs (vrschedule.VerifyPlan).
type fixtureOperator struct {
	f    *vrhandofffix.Fixture
	d    vrschedule.Derived
	keys map[string][]byte
	held []vrschedule.PreparePlan
}

func (o *fixtureOperator) VRIntent() (consensus.VRIntentView, error) {
	ids := make([]string, 0, len(o.keys))
	for id := range o.keys {
		ids = append(ids, id)
	}
	order := vrhandoff.AssemblerOrder(o.d.Digest, ids)
	return consensus.VRIntentView{Intent: o.d.Intent, Digest: o.d.Digest, RootEpoch: o.d.RootEpoch, Incumbents: order, Assembler: order[0]}, nil
}

func (o *fixtureOperator) VRBody(candidate []byte) (q3format.BodyV3, []byte, error) {
	if _, err := vrhandoff.VerifyAssembly(o.d.Intent, vrhandoff.Assembly{IntentDigest: o.d.Digest[:], Candidate: candidate}); err != nil {
		return q3format.BodyV3{}, nil, err
	}
	b, err := vrhandoff.DeriveBody(o.d.Intent, o.d.RootEpoch, sha256.Sum256(candidate), o.d.Body)
	if err != nil {
		return b, nil, err
	}
	_, tb, err := vrhandoff.TrustBase(o.d.Intent, o.d.RootEpoch)
	return b, tb, err
}

func (o *fixtureOperator) SubmitVRCertificate(c vrschema.ViewCertificate) error {
	p, err := vrschedule.VerifyPlan(o.d, o.keys, 0, c)
	if err != nil {
		return err
	}
	o.held = append(o.held, p)
	return nil
}

func (o *fixtureOperator) OfferVRMessage(vrschedule.Message) error { return nil }

func (o *fixtureOperator) VRStage(uint64) (vrschedule.StageSet, [32]byte, error) {
	return vrschedule.StageSet{}, o.d.Digest, nil
}

// The operator endpoints and the development harness end to end: the harness reads the intent, signs every successor's PoP, the view's
// assembly and every readiness over the body the root derives, and every root admits the certificate it delivers.
func TestTheVRHandoffEndpointsAndTheHarness(t *testing.T) {
	f := vrhandofffix.New(t)
	in, d := f.Intent()
	keys, _ := f.Incumbents()
	op := &fixtureOperator{f: f, d: vrschedule.Derived{VRIntent: storage.VRIntent{Digest: d, AnchorRound: in.AnchorRound}, Intent: in, RootEpoch: f.RC.RootEpoch,
		Body: f.BC}, keys: keys}
	mux := http.NewServeMux()
	registerVRHandoffRoutes(mux, op)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	rootKeys, evmKeys := map[string]abcrypto.Signer{}, map[string]abcrypto.Signer{}
	for _, m := range f.Members {
		rootKeys[m.Root], evmKeys[m.EVM] = m.RK.Signer, m.EK.Signer
	}
	var out bytes.Buffer
	require.NoError(t, vrDrive(vrClient{http: &http.Client{Timeout: 10 * time.Second}}, []string{srv.URL, srv.URL}, rootKeys, evmKeys, 0, &out))
	require.Len(t, op.held, 2, "both roots admitted the certificate")
	require.Contains(t, out.String(), `"view": 0`)

	// a key the harness lacks refuses before anything is sent
	delete(evmKeys, f.J[0].EVMNodeID)
	require.ErrorIs(t, vrDrive(vrClient{http: http.DefaultClient}, []string{srv.URL}, rootKeys, evmKeys, 0, &out), ErrVRHandoffCmd)
	require.Len(t, op.held, 2)

	// a malformed certificate is a bad request
	resp, err := http.Post(srv.URL+"/api/v1/vr/certificate", "application/json", bytes.NewReader([]byte(`{"certificate":"0x00"}`)))
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	_ = resp.Body.Close()
}
