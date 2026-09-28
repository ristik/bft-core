package handoffdelivery

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/handoffbundle"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestVerifyNativeBundleGuards(t *testing.T) {
	f := handoffbundle.New(t)
	base := Bundle{Proof: f.Proof, Body: f.Body, Snapshot: f.Snapshot}
	_, err := Verify(base, f.Old, f.Partition, f.Shard, f.ConfHash)
	require.NoError(t, err)
	clone := func() Bundle {
		raw, err := types.Cbor.Marshal(base)
		require.NoError(t, err)
		var b Bundle
		require.NoError(t, types.Cbor.Unmarshal(raw, &b))
		return b
	}
	cases := []struct {
		name   string
		mutate func(*Bundle)
	}{
		{"old proof", func(b *Bundle) { b.Proof.CommitQC.Signatures = nil }},
		{"successor body", func(b *Bundle) { b.Body.PredecessorHash = bytes.Repeat([]byte{9}, 32) }},
		{"nil snapshot", func(b *Bundle) { b.Snapshot = nil }},
		{"nil block", func(b *Bundle) { b.Snapshot.Block = nil }},
		{"nil control", func(b *Bundle) { b.Snapshot.Control = nil }},
		{"nil QC", func(b *Bundle) { b.Snapshot.CommitQc = nil }},
		{"nil seal", func(b *Bundle) { b.Snapshot.CommitQc.LedgerCommitInfo = nil }},
		{"block epoch", func(b *Bundle) { b.Snapshot.Block.Epoch++ }},
		{"block round", func(b *Bundle) { b.Snapshot.Block.Round++ }},
		{"control record", func(b *Bundle) { b.Snapshot.Control.RecordBytes = []byte{1} }},
		{"control digest", func(b *Bundle) { b.Snapshot.Control.PreviousDigest[0] ^= 1 }},
		{"seal root", func(b *Bundle) { b.Snapshot.CommitQc.LedgerCommitInfo.Hash[0] ^= 1 }},
		{"distinct QC", func(b *Bundle) { b.Snapshot.CommitQc.Signatures = nil }},
		{"wrong local config", func(b *Bundle) { b.Snapshot.ShardInfo[0].ShardConfHash[0] ^= 1 }},
		{"reserved partition", func(b *Bundle) { b.Snapshot.ShardInfo[0].Partition = 0 }},
		{"nil IR", func(b *Bundle) { b.Snapshot.ShardInfo[0].IR = nil }},
		{"short config hash", func(b *Bundle) { b.Snapshot.ShardInfo[0].ShardConfHash = []byte{1} }},
		{"duplicate shard", func(b *Bundle) { b.Snapshot.ShardInfo = append(b.Snapshot.ShardInfo, b.Snapshot.ShardInfo[0]) }},
		{"stat hash", func(b *Bundle) { b.Snapshot.ShardInfo[0].IRTR.StatHash[0] ^= 1 }},
		{"fee hash", func(b *Bundle) { b.Snapshot.ShardInfo[0].IRTR.FeeHash[0] ^= 1 }},
		{"reconstructed root", func(b *Bundle) { b.Snapshot.ShardInfo[0].IRTR.Round++ }},
		{"missing target", func(b *Bundle) { b.Snapshot.ShardInfo = []abdrc.ShardInfo{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := clone()
			tc.mutate(&b)
			_, err := Verify(b, f.Old, f.Partition, f.Shard, f.ConfHash)
			require.Error(t, err)
		})
	}
	t.Run("caller shard config", func(t *testing.T) {
		_, err := Verify(base, f.Old, f.Partition, f.Shard, bytes.Repeat([]byte{7}, 32))
		require.ErrorIs(t, err, ErrBundle)
	})
	t.Run("caller partition", func(t *testing.T) {
		_, err := Verify(base, f.Old, f.Partition+1, f.Shard, f.ConfHash)
		require.ErrorIs(t, err, ErrBundle)
	})
}
