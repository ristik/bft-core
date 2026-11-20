package signingauthority

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/vrrules"
	"github.com/unicitynetwork/bft-core/vrschema"
)

func fenceGate(entries []vrschema.Activation, err error) *vrrules.Gate {
	return vrrules.NewGate(vrrules.StaticSource{Entries: entries, Err: err}, vrrules.Set{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestAuthorityRefusesAnEpochOfARuleItLacks(t *testing.T) {
	f := newFixture(t, 1)
	rule := vrschema.RuleID("future-rule")
	entry := func(e uint64, state uint8) []vrschema.Activation {
		return []vrschema.Activation{{RuleID: rule, ReleaseDigest: vrschema.Word{9}, RootEpoch: e, State: state, ChangeID: 1}}
	}
	try := func(g *vrrules.Gate) error {
		a, err := New(f.enroll, trustStub{tb: f.tb}, WithFence(g))
		require.NoError(t, err)
		_, err = a.Authenticate(context.Background(), f.request())
		return err
	}
	require.NoError(t, try(fenceGate(nil, nil)), "no entry")
	require.NoError(t, try(nil), "no source: the roots fence")
	require.NoError(t, try(fenceGate(entry(rootEpoch+1, vrschema.ActActive), nil)), "allowed before E")
	require.NoError(t, try(fenceGate(entry(rootEpoch, vrschema.ActSuperseded), nil)), "superseded entries are ignored")
	for _, e := range []uint64{rootEpoch, rootEpoch - 1} {
		if e == 0 {
			continue
		}
		err := try(fenceGate(entry(e, vrschema.ActActive), nil))
		require.ErrorIs(t, err, vrrules.ErrUpgradeRequired, "refused at and after E=%d", e)
	}
	// a known rule passes
	a, err := New(f.enroll, trustStub{tb: f.tb}, WithFence(vrrules.NewGate(vrrules.StaticSource{Entries: entry(rootEpoch, vrschema.ActActive)},
		vrrules.Set{rule: "future-rule"}, slog.New(slog.NewTextHandler(io.Discard, nil)))))
	require.NoError(t, err)
	_, err = a.Authenticate(context.Background(), f.request())
	require.NoError(t, err)
	// a source failure with nothing known fails closed
	err = try(fenceGate(nil, errors.New("rpc down")))
	require.Error(t, err)
	require.NotErrorIs(t, err, vrrules.ErrUpgradeRequired)
}

// An authority that advances by proof retains the certified schedule of the checkpoint it verified, and decides its signing for that epoch
// from it: an endpoint that is down (or still at the earlier VR state K while the authority installs K+2) is not consulted.
func TestProofAdvanceRetainsTheCertifiedScheduleForSigning(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	down := vrrules.NewGate(vrrules.StaticSource{Err: errors.New("endpoint down or behind")}, vrrules.Set{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	a := proofAuthority(t, f, 0, WithFence(down))
	a.mu.Lock()
	a.irAckSeen = true
	a.mu.Unlock()
	require.Error(t, down.Check(context.Background(), 2), "before the advance nothing certifies epoch 2")

	res, err := a.AdvanceWithProof(context.Background(), bundleOf(t, f))
	require.NoError(t, err)
	require.EqualValues(t, 2, res.RootEpoch)
	require.NoError(t, down.Check(context.Background(), 2), "the advance retained the checkpoint's certified schedule: signing at epoch 2 needs no endpoint")
	require.NoError(t, down.Check(context.Background(), 1))
	require.Error(t, down.Check(context.Background(), 5), "nothing certifies a later epoch")
}

func TestPreGenesisAuthoritySignsAndAdvancesNothingUntilItsFenceIsProvisioned(t *testing.T) {
	f := newFixture(t, 1)
	a, err := New(f.enroll, trustStub{tb: f.tb}, WithFencePending())
	require.NoError(t, err)
	_, err = a.SigningPublicKey()
	require.NoError(t, err, "the key is served: the shard configuration is generated from it")
	_, err = a.Authenticate(context.Background(), f.request())
	require.ErrorIs(t, err, ErrFencePending)
	_, err = a.AdvanceWithProof(context.Background(), nil)
	require.ErrorIs(t, err, ErrFencePending)
	require.ErrorIs(t, a.AdvanceEpoch(context.Background(), nil, nil), ErrFencePending)
	_, err = a.SignHandoffPoP(HandoffPoPRequest{})
	require.ErrorIs(t, err, ErrFencePending)

	require.Error(t, a.ProvisionFence(nil))
	require.NoError(t, a.ProvisionFence(fenceGate(nil, nil)))
	require.Error(t, a.ProvisionFence(fenceGate(nil, nil)), "once")
	_, err = a.Authenticate(context.Background(), f.request())
	require.NoError(t, err, "signing is enabled by provisioning")
}
