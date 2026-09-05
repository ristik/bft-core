package evmroot

// D6 part 2: EVM proof export, historical header ancestry, and the
// shared-seal multi-shard anchor.
//
// Normative source: docs/design/d6-historical-trust-proof-custody.md §3,
// docs/pos/specification/appendix-evm.tex §"Execution Proof Export",
// appendix-bridging.tex §"Shared Anchor for Inclusion Checking".

// ProofBundle is the self-contained export for one subject.
type ProofBundle struct {
	Version           uint64
	ChainContext      []byte // full network/partition/shard/genesis/execution identity
	SubjectHeader     []byte
	UC                []byte // the block's own Unicity Certificate
	AuthPath          AuthPath
	ReceiptOrTxPath   []byte // for an event proof
	AccountOrStorPath []byte // for a state proof
}

// SelfContained reports whether the bundle can be verified offline once the
// recipient has a sufficiently recent trusted checkpoint — no external
// query during verification.
func (b ProofBundle) SelfContained(haveRecentCheckpoint bool) bool {
	return haveRecentCheckpoint && len(b.ChainContext) > 0 && len(b.SubjectHeader) > 0 &&
		(b.AuthPath.Mode == AuthLiveCertificate || b.AuthPath.Mode == AuthCheckpointAncestry)
}

// AuthMode is how a bundle's subject is authenticated back to trust.
type AuthMode uint8

const (
	AuthLiveCertificate    AuthMode = iota // within W_cert: the UC itself
	AuthCheckpointAncestry                 // outside W_cert: parent-header chain from a recent authenticated EVM head
)

// AuthPath authenticates the subject block. For AuthCheckpointAncestry it
// is an Ethereum parent-header chain from a recently authenticated EVM head
// down to the subject; its cost is LINEAR in the distance and it is
// explicitly NOT a constant-size historical proof.
type AuthPath struct {
	Mode           AuthMode
	FromHeadNumber uint64
	ToBlockNumber  uint64
	HeaderChainOK  bool // hash linkage, heights and chain configuration all check
}

// HistoricalAuth is the result of authenticating an old block.
type HistoricalAuth struct {
	Authenticated bool
	HeaderCount   uint64 // number of parent headers walked — grows with distance
	ConstantSize  bool   // always false for the header-chain path
	Note          string
}

// AuthenticateOldBlock walks the parent-header chain from a recently
// authenticated EVM head to an old block. An old certificate signed by
// retired keys alone is insufficient; this path is what authenticates it
// instead. A future accumulator could compress the path — this profile
// makes no such claim.
func AuthenticateOldBlock(p AuthPath) HistoricalAuth {
	if p.Mode != AuthCheckpointAncestry {
		return HistoricalAuth{Note: "not a checkpoint-ancestry path"}
	}
	if p.FromHeadNumber < p.ToBlockNumber {
		return HistoricalAuth{Note: "head is below the target block"}
	}
	n := p.FromHeadNumber - p.ToBlockNumber
	if !p.HeaderChainOK {
		return HistoricalAuth{Authenticated: false, HeaderCount: n, ConstantSize: false,
			Note: "header chain linkage/height/config check failed"}
	}
	return HistoricalAuth{Authenticated: true, HeaderCount: n, ConstantSize: false,
		Note: "authenticated by parent-header ancestry, linear in distance; retired signer keys not trusted"}
}

// ShardPath is one shard's certified input/configuration record plus its
// path through the shard tree and the Unicity Tree to the shared root r*.
type ShardPath struct {
	PartitionID    uint64
	ShardID        string
	ShardStateRoot []byte
	PathToRootOK   bool // shard-tree + Unicity-tree path to r* verifies
}

// AnchorBundle is the shared-seal multi-shard anchor: one root seal C* and
// its Unicity Tree root r*, plus a shard path for every touched shard.
type AnchorBundle struct {
	SealSignaturesVerified bool   // the seal's unique weighted signatures — verified ONCE
	RootStateRoot          []byte // r*
	ShardPaths             []ShardPath
}

// AnchoredLeaf is one transaction leaf to check under its authenticated
// shard state root (not directly under r*).
type AnchoredLeaf struct {
	PartitionID uint64
	ShardID     string
	RoutingKey  []byte
	LeafOK      bool // the leaf's inclusion under its shard state root verifies
}

// AnchorResult is the outcome of VerifyAnchoredHistory.
type AnchorResult struct {
	Verified         bool
	SealVerifiedOnce bool
	ShardPathCount   int // grows with the number of distinct touched shards
	Reason           string
}

// VerifyAnchoredHistory verifies a (possibly multi-shard) history: the
// shared seal is verified once; each required shard supplies a path to r*;
// each leaf is checked under its own authenticated shard state root. The
// number of shard paths grows with the touched shards even though seal
// verification is shared.
func VerifyAnchoredHistory(a AnchorBundle, leaves []AnchoredLeaf) AnchorResult {
	if !a.SealSignaturesVerified {
		return AnchorResult{Reason: "shared seal signatures not verified"}
	}
	// every touched (partition, shard) must have a verified path to r*
	have := map[string]bool{}
	for _, sp := range a.ShardPaths {
		if !sp.PathToRootOK {
			return AnchorResult{SealVerifiedOnce: true, Reason: "a shard path to r* failed"}
		}
		have[sp.ShardID+"@"+itoa(sp.PartitionID)] = true
	}
	for _, l := range leaves {
		if !have[l.ShardID+"@"+itoa(l.PartitionID)] {
			return AnchorResult{SealVerifiedOnce: true, ShardPathCount: len(a.ShardPaths),
				Reason: "leaf references a shard with no anchor path"}
		}
		if !l.LeafOK {
			return AnchorResult{SealVerifiedOnce: true, ShardPathCount: len(a.ShardPaths),
				Reason: "a leaf failed verification under its shard state root"}
		}
	}
	return AnchorResult{Verified: true, SealVerifiedOnce: true, ShardPathCount: len(a.ShardPaths)}
}
