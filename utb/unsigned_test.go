package utb_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/utb"
)

func TestDecodeUnsignedIsTheInverseOfSigBytes(t *testing.T) {
	ns := nodes(t, 4)
	g, _ := utb.BuildUnsigned(nil, facts(ns, 1, 1))
	e2, err := utb.BuildUnsigned(g, facts(ns, 2, 100))
	require.NoError(t, err)
	for _, e := range []*types.RootTrustBaseV2{g, e2} {
		sb, err := e.SigBytes()
		require.NoError(t, err)
		got, err := utb.DecodeUnsigned(sb)
		require.NoError(t, err)
		again, _ := got.SigBytes()
		require.Equal(t, sb, again)
		id, _ := got.EntryID()
		require.Equal(t, sha256.Sum256(sb), id, "EntryID = SHA-256 of the unsigned bytes")
		require.Nil(t, got.Signatures)
	}
}

func TestDecodeUnsignedIsStrict(t *testing.T) {
	ns := nodes(t, 4)
	g, _ := utb.BuildUnsigned(nil, facts(ns, 1, 1))
	e2, _ := utb.BuildUnsigned(g, facts(ns, 2, 100))
	good, _ := e2.SigBytes()
	signed := *e2
	require.NoError(t, signed.Sign(ns[0].id, ns[0].signer))
	withSigs, _ := signed.MarshalCBOR()
	cases := map[string][]byte{
		"signed entry":   withSigs,
		"trailing byte":  append(bytes.Clone(good), 0),
		"truncated":      good[:len(good)-2],
		"wrong tag":      append([]byte{0xd9, 0x98, 0x59}, good[3:]...),
		"untagged":       good[3:],
		"garbage":        {1, 2, 3},
		"indefinite len": append(append([]byte{0xd9, 0x98, 0x58, 0x9f}, good[4:]...), 0xff),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := utb.DecodeUnsigned(b)
			require.ErrorIs(t, err, utb.ErrUnsigned)
		})
	}
	t.Run("version 1", func(t *testing.T) {
		var content any
		require.NoError(t, cbor.Unmarshal(good[3:], &content))
		arr := content.([]any)
		arr[0] = uint64(1)
		enc, _ := cbor.CoreDetEncOptions().EncMode()
		c, _ := enc.Marshal(arr)
		b, _ := enc.Marshal(cbor.RawTag{Number: types.UnicityTrustBaseTag, Content: c})
		_, err := utb.DecodeUnsigned(b)
		require.ErrorIs(t, err, utb.ErrUnsigned)
	})
	t.Run("more members than the deployment admits", func(t *testing.T) {
		many := nodes(t, utb.MaxMembers+1)
		f := facts(many[:utb.MaxMembers], 1, 1)
		ok, err := utb.BuildUnsigned(nil, f)
		require.NoError(t, err)
		b, _ := ok.SigBytes()
		_, err = utb.DecodeUnsigned(b)
		require.NoError(t, err)
		// 17 members: hand-built through go-base (the builder refuses it)
		var ms []*types.NodeInfo
		for _, n := range many {
			ms = append(ms, &types.NodeInfo{NodeID: n.id, SigKey: n.key, Stake: 1})
		}
		for i := range ms {
			for j := i + 1; j < len(ms); j++ {
				if ms[j].NodeID < ms[i].NodeID {
					ms[i], ms[j] = ms[j], ms[i]
				}
			}
		}
		big := &types.RootTrustBaseV2{Version: 2, NetworkID: 5, Epoch: 1, EpochStart: 1, RootNodes: ms, QuorumThreshold: 12, PreviousEntryID: make([]byte, 32)}
		bb, _ := big.SigBytes()
		_, err = utb.DecodeUnsigned(bb)
		require.ErrorIs(t, err, utb.ErrUnsigned)
	})
}
