package rootinput_test

import (
	"context"
	"crypto/sha256"
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
	require.Equal(t, byte(0x8d), result.Encoded[0])
	require.Len(t, result.Input.RootRecordsHash, 32)
	require.NotEmpty(t, result.RecordsImport)
	require.Equal(t, sha256.Sum256(result.RecordsImport), [32]byte(result.Input.RootRecordsHash))
}
