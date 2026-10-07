package rootinput_test

import (
	"context"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/b1fixture"
	"github.com/unicitynetwork/bft-core/rootinput"
	"testing"
)

func TestFreshRootInputCannotBypassOwnPairAdmission(t *testing.T) {
	f := b1fixture.New(t, 0)
	c := rootinput.ContextV2{Context: context.Background(), Genesis: f.Origin, Parent: f.Parent, Round: 1, ParentHash: f.Parent.ParentHash().Bytes()}
	_, err := rootinput.DeriveV2(c, f.Observation)
	require.ErrorIs(t, err, rootinput.ErrB1Admission)
	c.B1 = f.Pair
	result, err := rootinput.DeriveV2(c, f.Observation)
	require.NoError(t, err)
	require.NotEmpty(t, result.B1Update)
	require.Len(t, result.Input.B1UpdateHash, 32)
	require.Equal(t, byte(0x8c), result.Encoded[0])
}
