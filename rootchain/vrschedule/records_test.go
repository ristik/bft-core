package vrschedule

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/vrhandofffix"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/vrhandoff"
)

func fixtureDerived(f *vrhandofffix.Fixture) (Derived, map[string][]byte) {
	in, d := f.Intent()
	keys, _ := f.Incumbents()
	return Derived{VRIntent: storage.VRIntent{Digest: d, AnchorRound: in.AnchorRound}, Intent: in, RootEpoch: f.RC.RootEpoch, Body: f.BC}, keys
}

// The certificate an operator submits (SubmitVRCertificate) is held only once it verifies as Freeze validity judges it: a view not yet
// committed, a missing readiness or a candidate that is not the intent's are refused.
func TestVerifyPlan(t *testing.T) {
	f := vrhandofffix.New(t)
	d, keys := fixtureDerived(f)
	a := f.Assembly(d.Intent, d.Digest, 1, f.PoPs(d.Intent))
	c, body, _ := f.Certificate(d.Intent, a)
	_, err := VerifyPlan(d, keys, 0, c)
	require.Error(t, err, "view 1 is not committed")
	p, err := VerifyPlan(d, keys, 1, c)
	require.NoError(t, err)
	require.Equal(t, body.Identity(), p.Body.Identity())
	require.Equal(t, f.R, p.Result)
	require.Equal(t, d.Intent.Attempt, p.Attempt)
	short := c
	short.Readiness = c.Readiness[:3]
	_, err = VerifyPlan(d, keys, 1, short)
	require.Error(t, err)
	other := c
	other.Assembly.Candidate = append([]byte(nil), c.Assembly.Candidate...)
	other.Assembly.Candidate[len(other.Assembly.Candidate)-1] ^= 1
	_, err = VerifyPlan(d, keys, 1, other)
	require.Error(t, err)
	require.Equal(t, sha256.Sum256(a.Candidate), sha256.Sum256(p.Certificate.Assembly.Candidate))
	_ = vrhandoff.Assembly{}
}
