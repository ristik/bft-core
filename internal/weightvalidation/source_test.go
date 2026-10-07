package weightvalidation

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type fixedSource struct {
	mode Mode
	err  error
}

func (f fixedSource) Mode(uint64) (Mode, error) { return f.mode, f.err }

type fixedTrustBase Mode

func (f fixedTrustBase) ValidationMode() Mode { return Mode(f) }

func TestModeFor(t *testing.T) {
	boom := errors.New("not active")
	for _, tc := range []struct {
		name   string
		source any
		want   Mode
		err    error
	}{
		{"a source without a mode is the unit world", struct{}{}, ModeUnit, nil},
		{"nil is the unit world", nil, ModeUnit, nil},
		{"weighted", fixedSource{mode: ModeWeighted}, ModeWeighted, nil},
		{"unit", fixedSource{mode: ModeUnit}, ModeUnit, nil},
		{"a refusal is not a fallback", fixedSource{err: boom}, 0, boom},
		{"an unset mode", fixedSource{mode: 0}, 0, ErrContext},
		{"an unknown mode", fixedSource{mode: 9}, 0, ErrContext},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ModeFor(tc.source, 7)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				require.Zero(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestModeOfTrustBase(t *testing.T) {
	require.Equal(t, ModeUnit, ModeOfTrustBase(struct{}{}))
	require.Equal(t, ModeUnit, ModeOfTrustBase(nil))
	require.Equal(t, ModeWeighted, ModeOfTrustBase(fixedTrustBase(ModeWeighted)))
	require.Equal(t, ModeUnit, ModeOfTrustBase(fixedTrustBase(0)), "an unset mode is never weighted")
	require.Equal(t, ModeUnit, ModeOfTrustBase(fixedTrustBase(9)), "an unknown mode is never weighted")
}
