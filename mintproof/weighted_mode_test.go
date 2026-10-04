package mintproof

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
	"github.com/unicitynetwork/bft-go-base/types"
)

// modeTrustBase is a trust base that carries the validation mode of its epoch, as q3active's guarded lookup hands it out.
type modeTrustBase struct {
	types.RootTrustBase
	mode weightvalidation.Mode
}

func (m modeTrustBase) ValidationMode() weightvalidation.Mode { return m.mode }

// A bundle carrying a weighted validator set verifies only for a client whose trust base for the certificate's root epoch says that
// epoch is a verified weighted activation. A client with a plain trust base (every client before Q3) keeps the unit rules and
// refuses it; the bundle cannot select its own rules.
func TestAWeightedBundleVerifiesOnlyUnderAWeightedTrustBase(t *testing.T) {
	weigh := func(pdr *types.PartitionDescriptionRecord) {
		for i, w := range []uint64{6, 1, 1} {
			pdr.Validators[i].Stake = w
		}
	}
	v := newV2Fixture(t, weigh, 1)

	t.Run("an old client with a plain trust base", func(t *testing.T) {
		err := Verify(v.raw, v.trust, v.claim, DefaultLimits())
		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "configuration PDR validators")
	})
	t.Run("a trust base of a verified weighted epoch", func(t *testing.T) {
		require.NoError(t, Verify(v.raw, modeTrustBase{v.trust, weightvalidation.ModeWeighted}, v.claim, DefaultLimits()))
	})
	t.Run("a trust base that says unit, or an unset or unknown mode", func(t *testing.T) {
		for _, mode := range []weightvalidation.Mode{weightvalidation.ModeUnit, 0, 9} {
			err := Verify(v.raw, modeTrustBase{v.trust, mode}, v.claim, DefaultLimits())
			require.ErrorIs(t, err, ErrInvalid, "mode %d", mode)
		}
	})
	t.Run("a unit bundle is unchanged under either trust base", func(t *testing.T) {
		unit := newV2Fixture(t, nil, 1)
		require.NoError(t, Verify(unit.raw, unit.trust, unit.claim, DefaultLimits()))
		require.NoError(t, Verify(unit.raw, modeTrustBase{unit.trust, weightvalidation.ModeWeighted}, unit.claim, DefaultLimits()))
	})
}
