package signingauthority

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
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
