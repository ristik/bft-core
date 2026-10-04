package handoffdelivery

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"

	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// SemanticIdentity is the digest of everything a handoff bundle commits to, without the two things honest copies of one handoff differ
// in: the signature sets (each node holds the quorum it happened to collect: a different valid subset) and the order of the snapshot's
// shard entries (a node's own enumeration order). The bundle must already be verified: the snapshot's contents are bound by the root hash
// the commit certificate seals, so a copy that differs in content does not verify, and the identity is only what is left to compare.
func SemanticIdentity(b Bundle) ([32]byte, error) {
	raw, err := EncodeBundle(b)
	if err != nil {
		return [32]byte{}, err
	}
	c, err := DecodeBundle(raw) // a deep copy: the caller's bundle is not changed
	if err != nil {
		return [32]byte{}, err
	}
	return identityOf(&c)
}

// identityOf strips the per-root parts from c, which it changes, and hashes what is left.
func identityOf(c *Bundle) ([32]byte, error) {
	strip := func(qc *rctypes.QuorumCert) {
		if qc != nil {
			qc.Signatures, qc.SealSignatures = nil, nil
		}
	}
	strip(c.Proof.CommitQC)
	strip(c.Proof.OptionalQC)
	if s := c.Snapshot; s != nil {
		strip(s.Qc)
		strip(s.CommitQc)
		for i := range s.ShardInfo {
			if uc := s.ShardInfo[i].UC; uc != nil && uc.UnicitySeal != nil {
				uc.UnicitySeal.Signatures = nil
			}
		}
		sort.SliceStable(s.ShardInfo, func(i, j int) bool {
			a, b := &s.ShardInfo[i], &s.ShardInfo[j]
			if a.Partition != b.Partition {
				return a.Partition < b.Partition
			}
			return shardKey(a.Shard) < shardKey(b.Shard)
		})
	}
	// the stripped form is not a canonical persisted shape, so it is encoded directly rather than through EncodeBundle
	stripped, err := types.Cbor.Marshal(c)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrBundle, err)
	}
	return sha256.Sum256(stripped), nil
}

func shardKey(s types.ShardID) string {
	key := s.Key()
	return string(key)
}

// SameHandoff reports whether two encoded bundles are the same handoff. Both must have been verified by the caller.
func SameHandoff(existing, incoming []byte) (bool, error) {
	a, err := DecodeBundle(existing)
	if err != nil {
		return false, err
	}
	b, err := DecodeBundle(incoming)
	if err != nil {
		return false, err
	}
	ia, err := SemanticIdentity(a)
	if err != nil {
		return false, err
	}
	ib, err := SemanticIdentity(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(ia[:], ib[:]), nil
}
