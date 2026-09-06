package evmroot

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

// D6 part 2: EVM proof export, historical header ancestry, and the
// shared-seal multi-shard anchor — with real hash-linked fixtures, not
// trusted booleans.
//
// Normative source: docs/design/d6-historical-trust-proof-custody.md §3,
// docs/pos/specification/appendix-evm.tex §"Execution Proof Export",
// appendix-bridging.tex §"Shared Anchor for Inclusion Checking".

// hashNode is the fixed inner-node hash for the model's Merkle structures:
// SHA-256(left ‖ right). It stands in for the production trie hash; the
// property under test (a path recomputes to a bound root, a broken link
// fails) does not depend on which collision-resistant hash is used.
func hashNode(left, right []byte) []byte {
	h := sha256.New()
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// PathStep is one sibling on a Merkle path. Left reports whether the
// sibling is the left child (so the running hash is the right child).
type PathStep struct {
	Sibling []byte
	Left    bool
}

// evalPath folds `leaf` up through `steps`, returning the recomputed root.
func evalPath(leaf []byte, steps []PathStep) []byte {
	cur := leaf
	for _, s := range steps {
		if s.Left {
			cur = hashNode(s.Sibling, cur)
		} else {
			cur = hashNode(cur, s.Sibling)
		}
	}
	return cur
}

// --- historical header ancestry ------------------------------------------

// Header is a minimal hash-linked block header. Hash is
// SHA-256(be64(Number) ‖ ParentHash ‖ Payload); a real client uses
// Keccak(RLP(header)) but the linkage property is the same.
type Header struct {
	Number     uint64
	ParentHash []byte
	Payload    []byte // stand-in for the rest of the header
}

// Hash computes the header hash.
func (h Header) Hash() []byte {
	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], h.Number)
	s := sha256.New()
	s.Write(nb[:])
	s.Write(h.ParentHash)
	s.Write(h.Payload)
	return s.Sum(nil)
}

// LinkHeaders builds a hash-linked chain of `n` headers starting at
// `startNumber` with the given genesis parent hash. Returned oldest-first.
func LinkHeaders(startNumber uint64, genesisParent []byte, n int) []Header {
	out := make([]Header, 0, n)
	parent := genesisParent
	for i := 0; i < n; i++ {
		hd := Header{Number: startNumber + uint64(i), ParentHash: parent, Payload: []byte{byte(i)}}
		out = append(out, hd)
		parent = hd.Hash()
	}
	return out
}

// HistoricalAuth is the result of authenticating an old block.
type HistoricalAuth struct {
	Authenticated bool
	HeaderCount   int  // parent headers walked — grows with distance
	ConstantSize  bool // always false for the header-chain path
	Reason        string
}

// AuthenticateOldBlock walks a parent-header chain from a recently
// authenticated head (trustedHeadHash, at chain[len-1]) down to the subject
// (chain[0]). It checks: the top header hashes to trustedHeadHash; every
// header's ParentHash equals the previous header's hash; numbers decrease
// by exactly one. An old certificate signed by retired keys is NOT part of
// this path — the header chain is what authenticates the block instead. The
// cost is linear in len(chain) and this is explicitly NOT a constant-size
// proof.
func AuthenticateOldBlock(subjectHash []byte, chain []Header, trustedHeadHash []byte) HistoricalAuth {
	n := len(chain)
	if n == 0 {
		return HistoricalAuth{Reason: "empty header chain"}
	}
	if !bytes.Equal(chain[n-1].Hash(), trustedHeadHash) {
		return HistoricalAuth{HeaderCount: n, Reason: "top header does not hash to the trusted head"}
	}
	if !bytes.Equal(chain[0].Hash(), subjectHash) {
		return HistoricalAuth{HeaderCount: n, Reason: "bottom header does not hash to the subject block"}
	}
	for i := 1; i < n; i++ {
		if !bytes.Equal(chain[i].ParentHash, chain[i-1].Hash()) {
			return HistoricalAuth{HeaderCount: n, Reason: "broken hash linkage between consecutive headers"}
		}
		if chain[i].Number != chain[i-1].Number+1 {
			return HistoricalAuth{HeaderCount: n, Reason: "header numbers are not consecutive"}
		}
	}
	return HistoricalAuth{Authenticated: true, HeaderCount: n, ConstantSize: false}
}

// --- shared-seal multi-shard anchor ------------------------------------

// AnchorSeal is the shared root seal C* / its Unicity Tree root r*, plus
// the weighted signature evidence over r*. It is verified ONCE for a
// multi-shard history.
type AnchorSeal struct {
	RootStateRoot []byte    // r*
	Signers       []string  // NodeIDs that signed r*
	Weights       WeightSet // the assignment; verification sums unique signer weights
	Threshold     uint64
}

// VerifySeal reports whether the seal's unique authorised signer weight
// meets the threshold.
func (s AnchorSeal) VerifySeal() (uint64, bool) {
	w, ok := s.Weights.SignerWeight(s.Signers)
	if !ok {
		return 0, false
	}
	return w, w >= s.Threshold
}

// ShardAnchorPath authenticates one shard's state root against r* : the
// shard state root folds up through Path to RootStateRoot.
type ShardAnchorPath struct {
	PartitionID    uint64
	ShardID        string
	ShardStateRoot []byte
	Path           []PathStep
}

// AnchoredLeaf is one transaction leaf verified under its shard's
// authenticated state root.
type AnchoredLeaf struct {
	PartitionID uint64
	ShardID     string
	LeafHash    []byte
	Path        []PathStep
}

// AnchorBundle is the shared-seal multi-shard anchor.
type AnchorBundle struct {
	Seal       AnchorSeal
	ShardPaths []ShardAnchorPath
}

// AnchorResult is the outcome of VerifyAnchoredHistory.
type AnchorResult struct {
	Verified         bool
	SealVerifiedOnce bool
	SealWeight       uint64
	ShardPathCount   int
	Reason           string
}

func shardKey(pid uint64, sid string) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], pid)
	return string(b[:]) + "|" + sid
}

// VerifyAnchoredHistory verifies a (possibly multi-shard) history: the
// shared seal is verified once; each shard path recomputes to r*; each leaf
// recomputes to its own shard's authenticated state root. The number of
// shard paths grows with the touched shards, seal verification does not.
func VerifyAnchoredHistory(a AnchorBundle, leaves []AnchoredLeaf) AnchorResult {
	w, ok := a.Seal.VerifySeal()
	if !ok {
		return AnchorResult{Reason: "shared seal signatures do not meet the threshold"}
	}
	roots := map[string][]byte{}
	for _, sp := range a.ShardPaths {
		if !bytes.Equal(evalPath(sp.ShardStateRoot, sp.Path), a.Seal.RootStateRoot) {
			return AnchorResult{SealVerifiedOnce: true, SealWeight: w, Reason: "a shard path does not recompute to r*"}
		}
		roots[shardKey(sp.PartitionID, sp.ShardID)] = sp.ShardStateRoot
	}
	for _, l := range leaves {
		sr, have := roots[shardKey(l.PartitionID, l.ShardID)]
		if !have {
			return AnchorResult{SealVerifiedOnce: true, SealWeight: w, ShardPathCount: len(a.ShardPaths),
				Reason: "leaf references a shard with no anchor path"}
		}
		if !bytes.Equal(evalPath(l.LeafHash, l.Path), sr) {
			return AnchorResult{SealVerifiedOnce: true, SealWeight: w, ShardPathCount: len(a.ShardPaths),
				Reason: "a leaf does not recompute to its shard state root"}
		}
	}
	return AnchorResult{Verified: true, SealVerifiedOnce: true, SealWeight: w, ShardPathCount: len(a.ShardPaths)}
}

// --- proof bundle self-containment -----------------------------------

// AuthMode is how a bundle's subject is authenticated back to trust.
type AuthMode uint8

const (
	AuthLiveCertificate    AuthMode = iota // within W_cert relative to the imported origin
	AuthCheckpointAncestry                 // outside W_cert: a parent-header chain from a recent authenticated head
)

// ProofBundle is the self-contained export for one subject.
type ProofBundle struct {
	Version      uint64
	ChainContext []byte
	SubjectHash  []byte
	Mode         AuthMode
	HeaderChain  []Header // for AuthCheckpointAncestry
	Receipt      []byte
}

// SelfContained reports whether the bundle can be verified offline given a
// recent trusted checkpoint (a trusted head hash for the ancestry mode).
func (b ProofBundle) SelfContained(trustedHeadHash []byte) bool {
	if len(b.ChainContext) == 0 || len(b.SubjectHash) == 0 {
		return false
	}
	switch b.Mode {
	case AuthLiveCertificate:
		return true
	case AuthCheckpointAncestry:
		return AuthenticateOldBlock(b.SubjectHash, b.HeaderChain, trustedHeadHash).Authenticated
	default:
		return false
	}
}
