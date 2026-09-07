package shardnode_test

import (
	"crypto"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/shardnode"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

const testPartitionID types.PartitionID = 1

// signedUC builds a real, signed certificate for round with the given input record.
func signedUC(t *testing.T, signer abcrypto.Signer, ir *types.InputRecord, rootRound uint64) *types.UnicityCertificate {
	t.Helper()
	h := make([]byte, 32)
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: testPartitionID}
	return testcertificates.CreateUnicityCertificate(t, signer, ir, pdr, rootRound, h, h)
}

// TestCheckpointPreservesAuthenticatedBytes is the regression test for issue #86. It was
// written as a characterisation of the defect (JSON turned a non-nil empty SummaryValue
// into nil, changing the authenticated CBOR) and is now inverted: every loss assertion is
// a preservation assertion.
func TestCheckpointPreservesAuthenticatedBytes(t *testing.T) {
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb := testtrustbase.NewTrustBase(t, signer)
	h := make([]byte, 32)

	ir := &types.InputRecord{
		Version: 1, RoundNumber: 4, PreviousHash: h, Hash: h,
		SummaryValue: []byte{}, Timestamp: 1,
	}
	original := signedUC(t, signer, ir, 50)
	require.NoError(t, original.Verify(tb, crypto.SHA256, testPartitionID, types.ShardID{}, original.ShardConfHash))

	store := shardnode.NewFileStore(filepath.Join(t.TempDir(), "luc.cbor"))
	require.NoError(t, store.SaveLUC(original))
	restored, err := store.LoadLUC()
	require.NoError(t, err)

	t.Run("the nil/empty distinction survives", func(t *testing.T) {
		require.NotNil(t, original.InputRecord.SummaryValue)
		require.NotNil(t, restored.InputRecord.SummaryValue, "empty must not become nil")
		require.Empty(t, restored.InputRecord.SummaryValue)
	})

	t.Run("canonical input record bytes are unchanged", func(t *testing.T) {
		before, err := original.InputRecord.Bytes()
		require.NoError(t, err)
		after, err := restored.InputRecord.Bytes()
		require.NoError(t, err)
		require.Equal(t, before, after)
	})

	t.Run("the complete certificate is unchanged", func(t *testing.T) {
		before, err := types.Cbor.Marshal(original)
		require.NoError(t, err)
		after, err := types.Cbor.Marshal(restored)
		require.NoError(t, err)
		require.Equal(t, before, after, "signatures, inclusion paths and commitments must all survive")
	})

	t.Run("the restored certificate still verifies", func(t *testing.T) {
		require.NoError(t, restored.Verify(tb, crypto.SHA256, testPartitionID, types.ShardID{}, original.ShardConfHash))
	})

	t.Run("the original is a duplicate of the restored, never equivocation", func(t *testing.T) {
		class, err := shardnode.ClassifyUC(restored, original)
		require.NoError(t, err)
		require.Equal(t, shardnode.UCDuplicate, class)
	})

	t.Run("a newer authentic seal for the same IR is a repeat", func(t *testing.T) {
		repeat := signedUC(t, signer, original.InputRecord.NewRepeatIR(), 51)
		class, err := shardnode.ClassifyUC(restored, repeat)
		require.NoError(t, err)
		require.Equal(t, shardnode.UCRepeat, class)
	})
}

// TestCheckpointNilEmptyTable covers the certificate byte fields in every nil/empty state
// they can legally take in a *valid* certificate, end to end: signed, stored, restored,
// re-verified and re-classified. Cases whose input record the protocol rejects outright
// (a nil SummaryValue, or a changed state hash with no block hash) cannot be signed at
// all, so their encoding is covered by TestCheckpointEncodingPreservesNilEmpty below
// rather than fabricated into an invalid certificate here.
func TestCheckpointNilEmptyTable(t *testing.T) {
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb := testtrustbase.NewTrustBase(t, signer)
	h := make([]byte, 32)

	base := func() *types.InputRecord {
		return &types.InputRecord{
			Version: 1, RoundNumber: 4, PreviousHash: h, Hash: h,
			SummaryValue: []byte{}, Timestamp: 1,
		}
	}

	cases := []struct {
		name   string
		mutate func(ir *types.InputRecord)
	}{
		{"quiet round: nil BlockHash, empty SummaryValue", func(ir *types.InputRecord) {
			ir.BlockHash = nil
		}},
		{"quiet round: empty BlockHash", func(ir *types.InputRecord) {
			ir.BlockHash = []byte{}
		}},
		{"non-quiet round: populated BlockHash and changed state", func(ir *types.InputRecord) {
			ir.BlockHash = []byte{0xb1, 0xb2}
			ir.Hash = []byte{0x11, 0x22}
			ir.SumOfEarnedFees = 7
		}},
		{"populated SummaryValue", func(ir *types.InputRecord) { ir.SummaryValue = []byte{0x5a} }},
		{"empty ETHash", func(ir *types.InputRecord) { ir.ETHash = []byte{} }},
		{"nil ETHash", func(ir *types.InputRecord) { ir.ETHash = nil }},
		{"populated ETHash", func(ir *types.InputRecord) { ir.ETHash = []byte{0xe1} }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ir := base()
			tc.mutate(ir)
			original := signedUC(t, signer, ir, 50)
			require.NoError(t, original.Verify(tb, crypto.SHA256, testPartitionID, types.ShardID{}, original.ShardConfHash),
				"fixture must be a valid certificate before the round trip")

			store := shardnode.NewFileStore(filepath.Join(t.TempDir(), "luc.cbor"))
			require.NoError(t, store.SaveLUC(original))
			restored, err := store.LoadLUC()
			require.NoError(t, err)

			requireSameIRByteState(t, original.InputRecord, restored.InputRecord)

			before, err := original.InputRecord.Bytes()
			require.NoError(t, err)
			after, err := restored.InputRecord.Bytes()
			require.NoError(t, err)
			require.Equal(t, before, after, "canonical IR bytes")

			// Signatures and inclusion paths still verify after the round trip.
			require.NoError(t, restored.Verify(tb, crypto.SHA256, testPartitionID, types.ShardID{}, original.ShardConfHash))

			class, err := shardnode.ClassifyUC(restored, original)
			require.NoError(t, err)
			require.Equal(t, shardnode.UCDuplicate, class)
		})
	}
}

// TestCheckpointEncodingPreservesNilEmpty covers the nil/empty states the signed table
// cannot reach, because the protocol rejects the input record before it could ever be
// certified. The encoding must still be lossless for them: a checkpoint reader that
// quietly normalises nil to empty (or back) is the defect issue #86 is about, and it
// should not be able to hide in a field that happens to be invalid for other reasons.
func TestCheckpointEncodingPreservesNilEmpty(t *testing.T) {
	h := make([]byte, 32)
	cases := []struct {
		name string
		ir   *types.InputRecord
	}{
		{"nil SummaryValue", &types.InputRecord{Version: 1, RoundNumber: 4, PreviousHash: h, Hash: h, SummaryValue: nil, Timestamp: 1}},
		{"empty SummaryValue", &types.InputRecord{Version: 1, RoundNumber: 4, PreviousHash: h, Hash: h, SummaryValue: []byte{}, Timestamp: 1}},
		{"nil PreviousHash", &types.InputRecord{Version: 1, RoundNumber: 4, PreviousHash: nil, Hash: h, SummaryValue: []byte{}, Timestamp: 1}},
		{"empty PreviousHash", &types.InputRecord{Version: 1, RoundNumber: 4, PreviousHash: []byte{}, Hash: h, SummaryValue: []byte{}, Timestamp: 1}},
		{"nil Hash", &types.InputRecord{Version: 1, RoundNumber: 4, PreviousHash: h, Hash: nil, SummaryValue: []byte{}, Timestamp: 1}},
		{"empty Hash", &types.InputRecord{Version: 1, RoundNumber: 4, PreviousHash: h, Hash: []byte{}, SummaryValue: []byte{}, Timestamp: 1}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := &types.UnicityCertificate{
				Version:     1,
				InputRecord: tc.ir,
				UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 50, Timestamp: 1},
			}
			store := shardnode.NewFileStore(filepath.Join(t.TempDir(), "luc.cbor"))
			require.NoError(t, store.SaveLUC(original))
			restored, err := store.LoadLUC()
			require.NoError(t, err)

			requireSameIRByteState(t, original.InputRecord, restored.InputRecord)

			before, err := original.InputRecord.Bytes()
			require.NoError(t, err)
			after, err := restored.InputRecord.Bytes()
			require.NoError(t, err)
			require.Equal(t, before, after, "canonical IR bytes must be identical")
		})
	}
}

func requireSameIRByteState(t *testing.T, want, got *types.InputRecord) {
	t.Helper()
	requireSameByteState(t, want.PreviousHash, got.PreviousHash, "previousHash")
	requireSameByteState(t, want.Hash, got.Hash, "hash")
	requireSameByteState(t, want.BlockHash, got.BlockHash, "blockHash")
	requireSameByteState(t, want.SummaryValue, got.SummaryValue, "summaryValue")
	requireSameByteState(t, want.ETHash, got.ETHash, "etHash")
}

func requireSameByteState(t *testing.T, want, got []byte, field string) {
	t.Helper()
	require.Equalf(t, want == nil, got == nil, "%s: nil-ness changed (want nil=%t)", field, want == nil)
	require.Equalf(t, want, got, "%s: value changed", field)
}

// TestCheckpointLegacyJSONFailsClosed covers the migration policy: a legacy JSON store is
// a precise, fatal error, and the file is left on disk.
func TestCheckpointLegacyJSONFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "luc.json")
	legacy := []byte(`{"version":1,"inputRecord":{"version":1,"roundNumber":4,"summaryValue":""},` +
		`"unicitySeal":{"version":1,"rootChainRoundNumber":50}}`)
	require.NoError(t, os.WriteFile(path, legacy, 0600))

	store := shardnode.NewFileStore(path)
	uc, err := store.LoadLUC()

	require.Nil(t, uc, "a legacy store must never be silently treated as usable")
	require.ErrorIs(t, err, shardnode.ErrLegacyJSONCheckpoint)
	require.ErrorContains(t, err, path, "the error names the file to recover")

	onDisk, readErr := os.ReadFile(path)
	require.NoError(t, readErr, "the rejected evidence must be preserved, not deleted")
	require.Equal(t, legacy, onDisk, "the legacy file must be left byte-identical")
}

// TestCheckpointRejectsUnusableStores: nothing damaged or unknown may be mistaken for a
// fresh store, which would restart a validator from genesis.
func TestCheckpointRejectsUnusableStores(t *testing.T) {
	t.Run("truncated CBOR", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "luc.cbor")
		require.NoError(t, os.WriteFile(path, []byte{0x82, 0x01}, 0600))
		uc, err := shardnode.NewFileStore(path).LoadLUC()
		require.Error(t, err)
		require.Nil(t, uc)
	})

	t.Run("unknown format version", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "luc.cbor")
		data, err := types.Cbor.Marshal([]any{uint32(99), nil})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, data, 0600))
		uc, err := shardnode.NewFileStore(path).LoadLUC()
		require.ErrorContains(t, err, "format version 99")
		require.Nil(t, uc)
	})

	t.Run("well-formed envelope with no certificate", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "luc.cbor")
		data, err := types.Cbor.Marshal([]any{uint32(1), nil})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, data, 0600))
		uc, err := shardnode.NewFileStore(path).LoadLUC()
		require.ErrorContains(t, err, "empty")
		require.Nil(t, uc)
	})

	t.Run("genuinely absent store is still a clean fresh start", func(t *testing.T) {
		uc, err := shardnode.NewFileStore(filepath.Join(t.TempDir(), "nope.cbor")).LoadLUC()
		require.NoError(t, err)
		require.Nil(t, uc)
	})
}

// TestCheckpointDamagedVersusLegacy: both fail closed, but an operator is told which
// problem they have. scripts/chaos-evm.sh's tampering scenario writes text starting with
// "{", which must not be reported as a migration.
func TestCheckpointDamagedVersusLegacy(t *testing.T) {
	write := func(t *testing.T, content string) (string, error) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "luc.json")
		require.NoError(t, os.WriteFile(path, []byte(content), 0600))
		uc, err := shardnode.NewFileStore(path).LoadLUC()
		require.Nil(t, uc)
		return path, err
	}

	t.Run("chaos-style corruption is reported as damage, not migration", func(t *testing.T) {
		path, err := write(t, "{this is not valid json, simulating disk corruption or tampering")
		require.Error(t, err)
		require.NotErrorIs(t, err, shardnode.ErrLegacyJSONCheckpoint)
		require.ErrorContains(t, err, "damaged")
		require.ErrorContains(t, err, path)
		require.FileExists(t, path, "damaged evidence is preserved")
	})

	t.Run("a readable legacy certificate is reported as migration", func(t *testing.T) {
		_, err := write(t, `{"version":1,"inputRecord":{"version":1,"roundNumber":4,"summaryValue":""},`+
			`"unicitySeal":{"version":1,"rootChainRoundNumber":50}}`)
		require.ErrorIs(t, err, shardnode.ErrLegacyJSONCheckpoint)
	})
}
