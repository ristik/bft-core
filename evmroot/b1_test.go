package evmroot

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestB1RootInputHasOneCommittedUpdateHash(t *testing.T) {
	ri := RootInputV2{}
	legacy := ri.Encode()
	hash := sha256.Sum256([]byte("independent canonical update"))
	expected := append([]byte(nil), legacy...)
	expected[0] = 0x8c
	expected = append(expected, 0x58, 0x20)
	expected = append(expected, hash[:]...)
	ri.B1UpdateHash = hash[:]
	require.Equal(t, expected, ri.Encode())
	require.Equal(t, Hash32(sha256.Sum256(expected)), ri.ExtraData())
	for _, n := range []int{0, 1, 31, 33} {
		ri.B1UpdateHash = bytes.Repeat([]byte{1}, n)
		require.ErrorIs(t, ri.Validate(), ErrB1UpdateHash)
	}
}

func TestRootRecordsHashIsTheThirteenthFieldAndTravelsWithTheUpdateHash(t *testing.T) {
	ri := RootInputV2{}
	legacy := ri.Encode()
	update := sha256.Sum256([]byte("independent canonical update"))
	records := sha256.Sum256([]byte("independent canonical import"))
	// an independent construction: the legacy array, its length head bumped to thirteen, then the two hash frames
	expected := append([]byte(nil), legacy...)
	expected[0] = 0x8d
	expected = append(expected, 0x58, 0x20)
	expected = append(expected, update[:]...)
	expected = append(expected, 0x58, 0x20)
	expected = append(expected, records[:]...)
	ri.B1UpdateHash, ri.RootRecordsHash = update[:], records[:]
	require.Equal(t, expected, ri.Encode())
	require.Equal(t, Hash32(sha256.Sum256(expected)), ri.ExtraData())

	// both or neither, each exactly 32 bytes
	valid := validV2(t)
	valid.B1UpdateHash, valid.RootRecordsHash = update[:], records[:]
	require.NoError(t, valid.Validate())
	for name, mutate := range map[string]func(r *RootInputV2){
		"an update hash without a records hash": func(r *RootInputV2) { r.RootRecordsHash = nil },
		"a records hash without an update hash": func(r *RootInputV2) { r.B1UpdateHash = nil },
		"a short records hash":                  func(r *RootInputV2) { r.RootRecordsHash = bytes.Repeat([]byte{1}, 31) },
		"a long records hash":                   func(r *RootInputV2) { r.RootRecordsHash = bytes.Repeat([]byte{1}, 33) },
		"an empty records hash":                 func(r *RootInputV2) { r.RootRecordsHash = []byte{} },
	} {
		r := valid
		mutate(&r)
		require.ErrorIs(t, r.Validate(), ErrRootRecordsHash, name)
	}
	// the update hash keeps its own error
	r := valid
	r.B1UpdateHash = bytes.Repeat([]byte{1}, 31)
	require.ErrorIs(t, r.Validate(), ErrB1UpdateHash)
}

// validV2 is the first independent vector's source as a valid legacy (eleven-field) root input.
func validV2(t *testing.T) RootInputV2 {
	t.Helper()
	b, err := os.ReadFile("testdata/v2-vectors.json")
	require.NoError(t, err)
	var f v2VectorFile
	require.NoError(t, json.Unmarshal(b, &f))
	s := f.Vectors[0].Source
	ri := RootInputV2{Version: s.Version, NetworkID: s.NetworkID, PartitionID: s.PartitionID,
		ShardID: vh(t, s.ShardID), Round: s.AuthorizedRound, CertifiedEpoch: s.CertifiedEpoch,
		AuthorizedEpoch: s.AuthorizedEpoch, ParentHash: vh(t, s.ParentHash),
		Origin: RootOriginV2{NetworkID: s.NetworkID, RootRound: s.RootRound, RootEpoch: s.RootEpoch,
			ReferenceTime: s.ReferenceTime, UnicityTreeRoot: vh(t, s.UnicityTreeRoot), InputVersion: 1,
			IR: ShardInputRecord{Round: s.InputRecord.Round, Epoch: s.InputRecord.Epoch,
				PreviousHash: vo(t, s.InputRecord.PreviousHash), Hash: vo(t, s.InputRecord.Hash),
				Timestamp: s.InputRecord.Timestamp, BlockHash: vo(t, s.InputRecord.BlockHash)},
			TRHash: vh(t, s.TRHash), ShardConfHash: vh(t, s.ShardConfHash)},
		TE: TechnicalRecord{Round: s.Technical.Round, Epoch: s.Technical.Epoch, Leader: s.Technical.Leader,
			StatHash: vh(t, s.Technical.StatHash), FeeHash: vh(t, s.Technical.FeeHash)}}
	require.NoError(t, ri.Validate())
	return ri
}
