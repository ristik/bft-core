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

func TestBundleCandidateMustMatchTheSuccessorBodyAndCodecsAreStrict(t *testing.T) {
	f := handoffbundle.New(t)
	base := Bundle{Proof: f.Proof, Body: f.Body, Snapshot: f.Snapshot}
	withCandidate := base
	withCandidate.Candidate = []byte("not the candidate the body binds")
	_, err := Verify(withCandidate, f.Old, f.Partition, f.Shard, f.ConfHash)
	require.ErrorIs(t, err, ErrBundle)
	require.ErrorContains(t, err, "candidate does not match the successor body")

	legacy, err := EncodeBundle(base)
	require.NoError(t, err)
	got, err := DecodeBundle(legacy)
	require.NoError(t, err)
	require.Empty(t, got.Candidate)
	current, err := EncodeBundle(withCandidate)
	require.NoError(t, err)
	got, err = DecodeBundle(current)
	require.NoError(t, err)
	require.Equal(t, withCandidate.Candidate, got.Candidate)
	require.NotEqual(t, legacy, current)
	// The four-element shape with an empty candidate is a second encoding of the legacy value: refused.
	raw, err := types.Cbor.Marshal(base)
	require.NoError(t, err)
	_, err = DecodeBundle(raw)
	require.ErrorIs(t, err, ErrBundle)
	_, err = DecodeBundle(append(legacy, 0))
	require.ErrorIs(t, err, ErrBundle)
}
