package evmroot

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

type v2VectorFile struct {
	Vectors []struct {
		Name, Class string
		Source      struct {
			Version, NetworkID, PartitionID, AuthorizedRound, CertifiedEpoch, AuthorizedEpoch, RootRound, RootEpoch, ReferenceTime uint64
			ShardID, ParentHash, UnicityTreeRoot, TRHash, ShardConfHash                                                            string
			InputRecord                                                                                                            struct {
				Round, Epoch, Timestamp       uint64
				PreviousHash, Hash, BlockHash *string
			}
			Technical struct {
				Round, Epoch              uint64
				Leader, StatHash, FeeHash string
			}
		}
		Origin       struct{ CBOR, Identity string }
		RootInput    struct{ CBOR, Commitment string }
		SyscallWords map[string]string
	}
	InvalidShapes []struct {
		Name   string
		Source struct {
			InputRecord struct {
				Round, Epoch, Timestamp       uint64
				PreviousHash, Hash, BlockHash *string
			}
		}
	}
}

func vh(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	require.NoError(t, err)
	return b
}
func vo(t *testing.T, p *string) []byte {
	t.Helper()
	if p == nil {
		return nil
	}
	return vh(t, *p)
}

func TestV2IndependentVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/v2-vectors.json")
	require.NoError(t, err)
	var f v2VectorFile
	require.NoError(t, json.Unmarshal(b, &f))
	require.Len(t, f.Vectors, 7)
	classes := map[string]OriginClassV2{"bootstrap": OriginBootstrapV2, "first-certified": OriginFirstCertifiedV2, "ordinary": OriginOrdinaryV2}
	for _, v := range f.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			s := v.Source
			o := RootOriginV2{NetworkID: s.NetworkID, RootRound: s.RootRound, RootEpoch: s.RootEpoch, ReferenceTime: s.ReferenceTime, UnicityTreeRoot: vh(t, s.UnicityTreeRoot), InputVersion: 1, IR: ShardInputRecord{Round: s.InputRecord.Round, Epoch: s.InputRecord.Epoch, PreviousHash: vo(t, s.InputRecord.PreviousHash), Hash: vo(t, s.InputRecord.Hash), Timestamp: s.InputRecord.Timestamp, BlockHash: vo(t, s.InputRecord.BlockHash)}, TRHash: vh(t, s.TRHash), ShardConfHash: vh(t, s.ShardConfHash)}
			class, err := o.Class()
			require.NoError(t, err)
			require.Equal(t, classes[v.Class], class)
			require.Equal(t, vh(t, v.Origin.CBOR), o.Encode())
			oid := o.Identity()
			require.Equal(t, vh(t, v.Origin.Identity), oid[:])
			tr := certification.TechnicalRecord{Round: s.Technical.Round, Epoch: s.Technical.Epoch, Leader: s.Technical.Leader, StatHash: vh(t, s.Technical.StatHash), FeeHash: vh(t, s.Technical.FeeHash)}
			trh, err := tr.Hash()
			require.NoError(t, err)
			require.Equal(t, o.TRHash, trh)
			ri := RootInputV2{Version: s.Version, NetworkID: s.NetworkID, PartitionID: s.PartitionID, ShardID: vh(t, s.ShardID), Round: s.AuthorizedRound, CertifiedEpoch: s.CertifiedEpoch, AuthorizedEpoch: s.AuthorizedEpoch, ParentHash: vh(t, s.ParentHash), Origin: o, TE: TechnicalRecord{Round: tr.Round, Epoch: tr.Epoch, Leader: tr.Leader, StatHash: tr.StatHash, FeeHash: tr.FeeHash}}
			require.NoError(t, ri.Validate())
			require.Equal(t, vh(t, v.RootInput.CBOR), ri.Encode())
			commitment := ri.ExtraData()
			require.Equal(t, vh(t, v.RootInput.Commitment), commitment[:])
			p, err := o.CertifiedProjection()
			require.NoError(t, err)
			var roundWord [32]byte
			binary.BigEndian.PutUint64(roundWord[24:], p.Round)
			require.Equal(t, vh(t, v.SyscallWords["certifiedRound"]), roundWord[:])
			require.Equal(t, vh(t, v.SyscallWords["stateHash"]), p.StateHash[:])
			require.Equal(t, vh(t, v.SyscallWords["blockHash"]), p.BlockHash[:])
			hasBlockWord := vh(t, v.SyscallWords["hasBlockHash"])
			require.Equal(t, !bytes.Equal(hasBlockWord, make([]byte, 32)), p.HasBlockHash)
		})
	}
	for _, v := range f.InvalidShapes {
		v := v
		t.Run("invalid/"+v.Name, func(t *testing.T) {
			i := v.Source.InputRecord
			o := RootOriginV2{NetworkID: 3, RootRound: 1, RootEpoch: 1, UnicityTreeRoot: bytes.Repeat([]byte{1}, 32), InputVersion: 1,
				IR:     ShardInputRecord{Round: i.Round, Epoch: i.Epoch, PreviousHash: vo(t, i.PreviousHash), Hash: vo(t, i.Hash), Timestamp: i.Timestamp, BlockHash: vo(t, i.BlockHash)},
				TRHash: bytes.Repeat([]byte{2}, 32), ShardConfHash: bytes.Repeat([]byte{3}, 32)}
			_, err := o.Class()
			require.Error(t, err)
		})
	}
}

func TestV2TransitionCountAndLengthBounds(t *testing.T) {
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
	for _, n := range []int{1, 16 * 1024} {
		ri.Transitions = [][]byte{bytes.Repeat([]byte{1}, n)}
		require.NoError(t, ri.Validate())
	}
	for _, entries := range [][][]byte{{{}}, {bytes.Repeat([]byte{1}, 16*1024+1)}, {{1}, {2}}} {
		ri.Transitions = entries
		require.Error(t, ri.Validate())
	}
}

func TestV2NullIsNotEmptyOrSyntheticBootstrap(t *testing.T) {
	base := RootOriginV2{NetworkID: 1, RootRound: 1, RootEpoch: 1, UnicityTreeRoot: make([]byte, 32), InputVersion: 1, TRHash: make([]byte, 32), ShardConfHash: make([]byte, 32)}
	require.Equal(t, OriginBootstrapV2, mustClass(t, base))
	for _, mut := range []func(*RootOriginV2){func(o *RootOriginV2) { o.IR.PreviousHash = []byte{} }, func(o *RootOriginV2) { o.IR.Hash = make([]byte, 32) }, func(o *RootOriginV2) { o.IR.PreviousHash = make([]byte, 32); o.IR.Hash = make([]byte, 32) }} {
		o := base
		mut(&o)
		_, err := o.Class()
		require.Error(t, err)
	}
}
func mustClass(t *testing.T, o RootOriginV2) OriginClassV2 {
	t.Helper()
	c, e := o.Class()
	require.NoError(t, e)
	return c
}
