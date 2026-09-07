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

// TestFileStore_LoadLUCDoesNotAuthenticate records an asymmetry found while investigating the
// same-partition-round certificate conflict (F1 #9, review 5132493933).
//
// A certificate arriving from the network is fully authenticated before it is classified:
// BFTClient.handleCertificationResponse calls UC.Verify against the trust base for its root epoch
// (signatures, quorum, inclusion paths) BEFORE ClassifyUC. The certificate it is classified
// *against* — the stored one, reinstalled by node.go via LoadLUC and SeedLUC on every restart —
// is only JSON-decoded. No signature, quorum, trust base, partition or shard check.
//
// So on the equivocation path the authority is the local file, and the thing being judged against
// it is the authenticated object. Since c.luc is deliberately left unchanged when classification
// fails (see TestUCConflictDisposition), a well-formed but wrong stored certificate makes a node
// reject genuinely quorum-certified certificates indefinitely.
//
// scripts/chaos-evm.sh's tampered-block scenario does not cover this: it corrupts the file so the
// decode itself fails, which is caught. This is the well-formed case.
//
// Recorded as a disposition, not a fix: whether SeedLUC should verify, and against which trust
// base at startup, is F2 (#10)'s decision, with F6 (#14) for the persistence contract.
func TestFileStore_LoadLUCDoesNotAuthenticate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "luc.json")
	s := shardnode.NewFileStore(path)

	// A structurally valid certificate whose seal is meaningless: no signatures at all, a root
	// round of the writer's choosing, and a hash that no root chain ever produced.
	forged := &types.UnicityCertificate{
		Version: 1,
		InputRecord: &types.InputRecord{
			Version: 1, RoundNumber: 4, Epoch: 0,
			PreviousHash: []byte{0x00}, Hash: []byte{0xde, 0xad},
			SummaryValue: []byte{}, Timestamp: 1,
		},
		UnicitySeal: &types.UnicitySeal{
			Version: 1, RootChainRoundNumber: 999999, Timestamp: 1,
			Hash:       []byte{0xbe, 0xef},
			Signatures: nil, // no root node ever signed this
		},
	}
	require.NoError(t, s.SaveLUC(forged))

	got, err := s.LoadLUC()
	require.NoError(t, err, "an unsigned certificate loads without complaint")
	require.NotNil(t, got)
	require.Equal(t, uint64(999999), got.GetRootRoundNumber())
	require.Empty(t, got.UnicitySeal.Signatures, "loaded and usable with no signatures whatsoever")
}
