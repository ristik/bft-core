package evmroot

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"hash"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
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

// AnchorSealStatement is the exact byte string every seal signature must
// cover: SHA-256(CBOR([ "UNICITY_ANCHOR_SEAL", r*, epoch, assignmentID ])).
// Binding r*, the epoch and the authorising assignment identity means a
// substituted root, a replayed seal from another epoch, or a seal from a
// different assignment all invalidate every signature.
func AnchorSealStatement(rootStateRoot []byte, epoch uint64, assignmentID []byte) []byte {
	return sha256Bytes(marshalCBOR(cArray{
		cText("UNICITY_ANCHOR_SEAL"),
		cBytes(rootStateRoot), cUint(epoch), cBytes(assignmentID),
	}))
}

// AnchorSeal is the shared root seal C* / its Unicity Tree root r*, plus
// the weighted signature evidence over r*. It is verified ONCE for a
// multi-shard history. The threshold is NOT carried — it is derived from
// the authenticated assignment (RootQuorumThreshold of its total weight) —
// and signer names are not evidence: each claimed signer must present a
// secp256k1 signature over AnchorSealStatement that verifies against that
// member's ConsensusKey.
type AnchorSeal struct {
	RootStateRoot []byte            // r*
	Epoch         uint64            // the epoch whose assignment authorises this seal
	AssignmentID  []byte            // identity of that assignment (e.g. the D3 trust-base body id)
	Weights       WeightSet         // the authenticated assignment; members carry real ConsensusKeys
	Signatures    map[string][]byte // NodeID -> signature over AnchorSealStatement(RootStateRoot, Epoch, AssignmentID)
}

// VerifySeal returns the validated unique signer weight, the DERIVED
// threshold (⌊2W/3⌋+1 over the assignment's total weight), and whether the
// weight meets it. It rejects: a malformed assignment; an empty root or an
// empty signature set; and any signature that does not verify against the
// named member's key over the seal statement. A supplied zero threshold or
// a bare signer list can no longer pass.
func (s AnchorSeal) VerifySeal() (weight, threshold uint64, ok bool) {
	w, wok := s.Weights.TotalWeight()
	if !wok {
		return 0, 0, false
	}
	threshold = RootQuorumThreshold(w) // always >= 1
	if len(s.RootStateRoot) == 0 || len(s.Signatures) == 0 {
		return 0, threshold, false
	}
	stmt := AnchorSealStatement(s.RootStateRoot, s.Epoch, s.AssignmentID)
	counted := map[string]struct{}{}
	for _, m := range s.Weights {
		sig, has := s.Signatures[m.NodeID]
		if !has {
			continue
		}
		if _, dup := counted[m.NodeID]; dup {
			continue
		}
		v, err := abcrypto.NewVerifierSecp256k1(m.ConsensusKey)
		if err != nil {
			continue
		}
		if v.VerifyBytes(sig, stmt) != nil {
			continue // a name without a valid signature over r* counts for nothing
		}
		counted[m.NodeID] = struct{}{}
		weight += m.Weight
	}
	return weight, threshold, weight >= threshold
}

// shardAnchorLeaf binds a shard path's certified identity INTO the leaf
// that folds up to r*: SHA-256("UNICITY_SHARD_ANCHOR_LEAF" ‖ len‖be64(pid)
// ‖ len‖shardID ‖ len‖configHash ‖ len‖shardStateRoot). Every field is
// length-delimited, so relabelling a path's partition/shard/config — or
// shifting a byte across a field boundary — changes this leaf and it no
// longer recomputes to the certified r*.
func shardAnchorLeaf(pid uint64, sid string, configHash, shardStateRoot []byte) []byte {
	h := sha256.New()
	h.Write([]byte("UNICITY_SHARD_ANCHOR_LEAF"))
	// Every field is length-delimited (be64 length prefix), so moving bytes
	// between shardID and configHash — or any other field boundary — changes
	// the hash. A bare concatenation of variable-length fields would not.
	writeLenField(h, u64be(pid))
	writeLenField(h, []byte(sid))
	writeLenField(h, configHash)
	writeLenField(h, shardStateRoot)
	return h.Sum(nil)
}

func u64be(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

func writeLenField(h hash.Hash, b []byte) {
	h.Write(u64be(uint64(len(b))))
	h.Write(b)
}

// ShardAnchorPath authenticates one shard's state root against r*: the
// bound leaf (partition ‖ shard ‖ configHash ‖ shardStateRoot) folds up
// through Path to RootStateRoot. ConfigHash is the certified shard-config
// identity; an empty one is rejected.
type ShardAnchorPath struct {
	PartitionID    uint64
	ShardID        string
	ConfigHash     []byte
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
	SealThreshold    uint64
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
	w, threshold, ok := a.Seal.VerifySeal()
	if !ok {
		return AnchorResult{SealWeight: w, SealThreshold: threshold,
			Reason: "shared seal: signatures over r* do not reach the derived quorum threshold"}
	}
	roots := map[string][]byte{}
	for _, sp := range a.ShardPaths {
		if len(sp.ConfigHash) == 0 {
			return AnchorResult{SealVerifiedOnce: true, SealWeight: w, SealThreshold: threshold,
				Reason: "a shard anchor path carries no certified config hash"}
		}
		leaf := shardAnchorLeaf(sp.PartitionID, sp.ShardID, sp.ConfigHash, sp.ShardStateRoot)
		if !bytes.Equal(evalPath(leaf, sp.Path), a.Seal.RootStateRoot) {
			return AnchorResult{SealVerifiedOnce: true, SealWeight: w, SealThreshold: threshold,
				Reason: "a shard path does not recompute to r* (partition/shard/config are not the certified ones)"}
		}
		roots[shardKey(sp.PartitionID, sp.ShardID)] = sp.ShardStateRoot
	}
	for _, l := range leaves {
		sr, have := roots[shardKey(l.PartitionID, l.ShardID)]
		if !have {
			return AnchorResult{SealVerifiedOnce: true, SealWeight: w, SealThreshold: threshold, ShardPathCount: len(a.ShardPaths),
				Reason: "leaf references a shard with no anchor path"}
		}
		if !bytes.Equal(evalPath(l.LeafHash, l.Path), sr) {
			return AnchorResult{SealVerifiedOnce: true, SealWeight: w, SealThreshold: threshold, ShardPathCount: len(a.ShardPaths),
				Reason: "a leaf does not recompute to its shard state root"}
		}
	}
	return AnchorResult{Verified: true, SealVerifiedOnce: true, SealWeight: w, SealThreshold: threshold, ShardPathCount: len(a.ShardPaths)}
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

	// For AuthLiveCertificate: the anchor that authenticates the subject
	// back to a certified root seal, and the shard/leaf the subject sits
	// under. A non-empty Receipt alone is NOT authentication.
	LiveAnchor *AnchorBundle
	LiveLeaf   *AnchoredLeaf
	Receipt    []byte
}

// CarriesEvidence reports STRUCTURAL availability only: the bundle has the
// pieces its mode needs. It does not run any verification. Use
// OfflineVerify for the actual check.
func (b ProofBundle) CarriesEvidence() bool {
	if len(b.ChainContext) == 0 || len(b.SubjectHash) == 0 {
		return false
	}
	switch b.Mode {
	case AuthLiveCertificate:
		return b.LiveAnchor != nil && b.LiveLeaf != nil && len(b.Receipt) > 0
	case AuthCheckpointAncestry:
		return len(b.HeaderChain) > 0
	default:
		return false
	}
}

// VerifierTrustAnchor is the EXTERNAL authenticated state a verifier holds
// from its own checkpoint / trust store. OfflineVerify derives the seal
// assignment from THIS, never from the proof bundle. A bundle can carry a
// trust-base body as evidence, but it is untrusted until its chain is
// authenticated back to something in here.
type VerifierTrustAnchor struct {
	Network              uint64
	ChainContext         []byte    // the authenticated chain/config context this verifier trusts
	Epoch                uint64    // the epoch whose assignment is active at the subject's round
	BodyIdentity         []byte    // identity of the authenticated trust-base body; the seal's AssignmentID must equal this
	Weights              WeightSet // that body's members (real keys) — the assignment used to check the seal
	TrustedHeadHash      []byte    // for ancestry mode: a recently authenticated EVM head
	Freshness            FreshnessPolicy
	CheckpointAgeSeconds uint64 // how old the verifier's own checkpoint is right now
}

func (t VerifierTrustAnchor) fresh() bool {
	if !t.Freshness.Valid() {
		return false
	}
	return t.CheckpointAgeSeconds <= t.Freshness.MaxCheckpointStalenessSeconds()
}

// OfflineVerify verifies the bundle against the verifier's OWN authenticated
// trust anchor. Live mode: the bundle's carried assignment/epoch/id are
// UNTRUSTED — the seal's Epoch and AssignmentID must match the anchor, and
// the seal is re-checked against the ANCHOR's Weights (the carried
// assignment is discarded), so an attacker-supplied one-member assignment
// with a valid attacker signature does not verify. Ancestry mode:
// AuthenticateOldBlock walks the header chain to the anchor's trusted head.
// A bundle that only "carries evidence" but does not verify returns false.
func (b ProofBundle) OfflineVerify(t VerifierTrustAnchor) bool {
	if !b.CarriesEvidence() {
		return false
	}
	if !t.fresh() {
		return false // stale / unsupported checkpoint policy — cannot make a safety claim
	}
	if len(t.ChainContext) == 0 || !bytes.Equal(b.ChainContext, t.ChainContext) {
		return false // subject is not in the chain/config context this verifier trusts
	}
	switch b.Mode {
	case AuthLiveCertificate:
		if !bytes.Equal(b.LiveLeaf.LeafHash, b.SubjectHash) {
			return false
		}
		seal := b.LiveAnchor.Seal
		if seal.Epoch != t.Epoch {
			return false
		}
		if len(seal.AssignmentID) == 0 || !bytes.Equal(seal.AssignmentID, t.BodyIdentity) {
			return false
		}
		// Re-verify against the ANCHOR's assignment, not the carried one.
		authAnchor := *b.LiveAnchor
		authAnchor.Seal.Weights = t.Weights
		return VerifyAnchoredHistory(authAnchor, []AnchoredLeaf{*b.LiveLeaf}).Verified
	case AuthCheckpointAncestry:
		return AuthenticateOldBlock(b.SubjectHash, b.HeaderChain, t.TrustedHeadHash).Authenticated
	default:
		return false
	}
}

// SelfContained is retained as the offline-verifiable predicate: it means
// "verifies offline against the verifier's own authenticated trust anchor",
// not merely "has non-empty fields".
func (b ProofBundle) SelfContained(t VerifierTrustAnchor) bool {
	return b.OfflineVerify(t)
}
