package handoffdelivery

import (
	"bytes"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/handoffbundle"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-go-base/types"
)

func cloneBundle(t *testing.T, b Bundle) Bundle {
	t.Helper()
	raw, err := EncodeBundle(b)
	require.NoError(t, err)
	c, err := DecodeBundle(raw)
	require.NoError(t, err)
	return c
}

// withSigners adds the old committee's fourth member's signature to the commit certificate, so two different three-of-four subsets are
// both valid quorums of the same handoff.
func withFourthSigner(t *testing.T, f handoffbundle.Fixture) Bundle {
	t.Helper()
	b := cloneBundle(t, Bundle{Proof: f.Proof, Body: f.Body, Snapshot: f.Snapshot})
	message, err := b.Proof.CommitQC.LedgerCommitInfo.SigBytes()
	require.NoError(t, err)
	sig, err := f.Nodes[3].Signer.SignBytes(message)
	require.NoError(t, err)
	b.Proof.CommitQC.Signatures[f.Nodes[3].PeerConf.ID.String()] = sig
	require.Len(t, b.Proof.CommitQC.Signatures, 4)
	b.Snapshot.CommitQc = b.Proof.CommitQC // the fixture shares one certificate
	return b
}

func without(t *testing.T, b Bundle, id string) Bundle {
	t.Helper()
	c := cloneBundle(t, b)
	require.Contains(t, c.Proof.CommitQC.Signatures, id)
	delete(c.Proof.CommitQC.Signatures, id)
	c.Snapshot.CommitQc = c.Proof.CommitQC
	return c
}

// The same handoff, certified by two different valid quorum subsets, has one semantic identity, and both copies verify.
func TestTheSameHandoffUnderTwoQuorumSubsetsHasOneIdentity(t *testing.T) {
	f := handoffbundle.New(t)
	full := withFourthSigner(t, f)
	var ids []string
	for id := range full.Proof.CommitQC.Signatures {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	one, other := without(t, full, ids[0]), without(t, full, ids[1])
	for _, b := range []Bundle{one, other} {
		_, err := Verify(b, f.Old, f.Partition, f.Shard, f.ConfHash)
		require.NoError(t, err, "each subset is itself a valid quorum")
	}
	a, err := EncodeBundle(one)
	require.NoError(t, err)
	b, err := EncodeBundle(other)
	require.NoError(t, err)
	require.False(t, bytes.Equal(a, b), "the bytes differ")
	same, err := SameHandoff(a, b)
	require.NoError(t, err)
	require.True(t, same)
}

// The order of the snapshot's shard entries is a node's own enumeration order, not part of the handoff.
func TestTheOrderOfTheSnapshotsShardEntriesIsNotPartOfTheIdentity(t *testing.T) {
	f := handoffbundle.New(t)
	base := Bundle{Proof: f.Proof, Body: f.Body, Snapshot: f.Snapshot}
	extra := base.Snapshot.ShardInfo[0]
	extra.Partition++
	x := cloneBundle(t, base)
	x.Snapshot.ShardInfo = []abdrc.ShardInfo{base.Snapshot.ShardInfo[0], extra}
	y := cloneBundle(t, x)
	y.Snapshot.ShardInfo = []abdrc.ShardInfo{x.Snapshot.ShardInfo[1], x.Snapshot.ShardInfo[0]}
	ix, err := SemanticIdentity(x)
	require.NoError(t, err)
	iy, err := SemanticIdentity(y)
	require.NoError(t, err)
	require.Equal(t, ix, iy)
}

// Anything the bundle commits to changes the identity: nothing semantic is absorbed with the signatures.
func TestASemanticDifferenceChangesTheIdentity(t *testing.T) {
	f := handoffbundle.New(t)
	base := Bundle{Proof: f.Proof, Body: f.Body, Snapshot: f.Snapshot}
	want, err := SemanticIdentity(base)
	require.NoError(t, err)
	for name, mutate := range map[string]func(*Bundle){
		"successor body":      func(b *Bundle) { b.Body.PredecessorHash = bytes.Repeat([]byte{9}, 32) },
		"earliest activation": func(b *Bundle) { b.Body.EarliestActivation++ },
		"handoff record":      func(b *Bundle) { b.Proof.Record.Attempt++ },
		"control state":       func(b *Bundle) { b.Proof.Control.PreviousDigest[0] ^= 1 },
		"candidate":           func(b *Bundle) { b.Candidate = []byte("another candidate") },
		"snapshot block":      func(b *Bundle) { b.Snapshot.Block.Round++ },
		"shard entry":         func(b *Bundle) { b.Snapshot.ShardInfo[0].RootHash = bytes.Repeat([]byte{7}, 32) },
		"commit seal":         func(b *Bundle) { b.Snapshot.CommitQc.LedgerCommitInfo.Hash[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			c := cloneBundle(t, base)
			mutate(&c)
			got, err := SemanticIdentity(c)
			require.NoError(t, err)
			require.NotEqual(t, want, got)
		})
	}
}

// A shard entry's own certificate carries a seal signature set too: another subset is the same handoff, another seal is not.
func TestAShardEntrysSealSignaturesAreNotPartOfTheIdentityButItsSealIs(t *testing.T) {
	f := handoffbundle.New(t)
	base := cloneBundle(t, Bundle{Proof: f.Proof, Body: f.Body, Snapshot: f.Snapshot})
	base.Snapshot.ShardInfo[0].UC = &types.UnicityCertificate{Version: 1, UnicitySeal: &types.UnicitySeal{Version: 1, Timestamp: 5,
		Signatures: types.SignatureMap{"a": {1}, "b": {2}, "c": {3}}}}
	want, err := SemanticIdentity(base)
	require.NoError(t, err)

	fewer := base
	fewer.Snapshot = &abdrc.CommittedBlock{Block: base.Snapshot.Block, Control: base.Snapshot.Control, Qc: base.Snapshot.Qc, CommitQc: base.Snapshot.CommitQc,
		ShardInfo: []abdrc.ShardInfo{base.Snapshot.ShardInfo[0]}}
	uc := *base.Snapshot.ShardInfo[0].UC
	seal := *uc.UnicitySeal
	seal.Signatures = types.SignatureMap{"b": {2}, "d": {4}}
	uc.UnicitySeal = &seal
	fewer.Snapshot.ShardInfo[0].UC = &uc
	got, err := SemanticIdentity(fewer)
	require.NoError(t, err)
	require.Equal(t, want, got, "a different signature subset of the same seal")

	seal.Timestamp++
	got, err = SemanticIdentity(fewer)
	require.NoError(t, err)
	require.NotEqual(t, want, got, "a different seal")
}
