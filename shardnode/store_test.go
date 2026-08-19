package shardnode_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/shardnode"
)

func TestFileStore_FreshStartReturnsNilNotError(t *testing.T) {
	s := shardnode.NewFileStore(filepath.Join(t.TempDir(), "luc.json"))
	uc, err := s.LoadLUC()
	require.NoError(t, err)
	require.Nil(t, uc)
}

func TestFileStore_RoundTrip(t *testing.T) {
	s := shardnode.NewFileStore(filepath.Join(t.TempDir(), "luc.json"))
	want := &types.UnicityCertificate{
		Version:     1,
		InputRecord: &types.InputRecord{Version: 1, RoundNumber: 7, Hash: []byte{0xAB, 0xCD}},
		UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 42, Timestamp: 12345},
	}
	require.NoError(t, s.SaveLUC(want))

	got, err := s.LoadLUC()
	require.NoError(t, err)
	require.Equal(t, want.InputRecord.RoundNumber, got.InputRecord.RoundNumber)
	require.Equal(t, want.InputRecord.Hash, got.InputRecord.Hash)
	require.Equal(t, want.UnicitySeal.RootChainRoundNumber, got.UnicitySeal.RootChainRoundNumber)
	require.Equal(t, want.UnicitySeal.Timestamp, got.UnicitySeal.Timestamp)
}

func TestFileStore_OverwriteReplacesPreviousValue(t *testing.T) {
	s := shardnode.NewFileStore(filepath.Join(t.TempDir(), "luc.json"))
	require.NoError(t, s.SaveLUC(&types.UnicityCertificate{
		Version:     1,
		InputRecord: &types.InputRecord{Version: 1, RoundNumber: 1},
		UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 1},
	}))
	require.NoError(t, s.SaveLUC(&types.UnicityCertificate{
		Version:     1,
		InputRecord: &types.InputRecord{Version: 1, RoundNumber: 2},
		UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 2},
	}))

	got, err := s.LoadLUC()
	require.NoError(t, err)
	require.EqualValues(t, 2, got.InputRecord.RoundNumber)
}
