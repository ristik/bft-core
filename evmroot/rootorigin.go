// Package evmroot is the D1 reference model for the enshrined-EVM
// canonical root input: the signature-free root origin O_-, the full
// rootInput tuple committed in a block header's extraData, the
// domain-separated round parameters (prevRandao, parentBeaconBlockRoot,
// timestamp) and the certified round clock.
//
// It exists to make the D1 profile executable and independently checkable
// before F2 implements it in the adapter and the reth fork implements the
// privileged call. Nothing here drives reth or the root chain; it is pure
// data plus deterministic hashing, and it depends only on the standard
// library (see cbor.go for why the CBOR encoder is hand-rolled).
//
// Normative source: docs/design/d1-canonical-root-input.md and
// docs/adr/0003-canonical-root-input-profile.md. Issue:
// https://github.com/ristik/bft-core/issues/3
package evmroot

import "crypto/sha256"

// ProfileVersion is the D1 root-input profile version this package
// implements. v1 is the normative form defined by the specification
// (appendix-evm.tex §"Round Parameter Derivation" and §"Seal Transaction").
//
// v0 is the pre-D1 prototype form in engineapi/params.go — one-byte domain
// prefixes 0x01/0x02, SHA-256 over raw concatenation (not CBOR), keyed by
// (UnicityTreeRoot, shardRound) rather than (rootRound, shardRound), and no
// extraData commitment at all. v0 is retained only for the compatibility
// vectors in testdata/vectors.json; it is not a supported deployment
// profile. There is no live deployment on v0, so no migration path is
// specified — F2 replaces the derivation wholesale.
const ProfileVersion = 1

// Domain strings for the two domain-separated round-parameter derivations.
// ASCII, hashed as CBOR text strings inside a CBOR array — see DerivePrevRandao.
const (
	DomainPrevRandao = "UNICITY_EVM_RANDAO" // DOM_rho
	DomainBeaconRoot = "UNICITY_EVM_BEACON" // DOM_beta
)

// Hash32 is a 32-byte digest. Whether it is a Unicity SHA-256/CBOR digest
// or an Ethereum Keccak-256/RLP digest depends on the field — the profile
// fixes which for every constituent, and this type deliberately does not
// distinguish them so that a Keccak parent hash can be carried verbatim
// inside a CBOR-encoded rootInput without being rehashed.
type Hash32 [32]byte

// RoundKind classifies the shard round a certificate authorizes. The
// canonical root input is built the same way for every kind; the kind
// governs which seal-registry cursors advance and whether a block is
// committed (see docs/design/d1-canonical-root-input.md §"Round types").
type RoundKind uint8

const (
	// RoundGenesis: the initial certificate for shard round 0, issued with
	// no certification requests. Authenticated by the pinned genesis
	// commitment, not a quorum signature.
	RoundGenesis RoundKind = iota
	// RoundSuccessful: state root changed, block hash present. Advances the
	// root origin and every cursor exactly once.
	RoundSuccessful
	// RoundQuiet: IR.h == IR.h' and IR.h_b == nil — no block executed this
	// shard round. Advances the root origin (new seal) but commits no block
	// and does not advance the transition or reward cursor.
	RoundQuiet
	// RoundRepeat: identical InputRecord to the previous certificate, later
	// root round — the root chain re-issued the last good certificate after
	// a shard timeout. Not a newly executed block; the reward cursor does
	// not advance and no second reward claim is created for the interval.
	RoundRepeat
	// RoundCanceled: an in-flight attempt discarded at an epoch handoff.
	// Never committed to a block's extraData; never revived under the new
	// assignment.
	RoundCanceled
)

func (k RoundKind) String() string {
	switch k {
	case RoundGenesis:
		return "genesis"
	case RoundSuccessful:
		return "successful"
	case RoundQuiet:
		return "quiet"
	case RoundRepeat:
		return "repeat"
	case RoundCanceled:
		return "canceled"
	default:
		return "unknown"
	}
}

// ShardInputRecord is the enshrined-EVM shard input record IR = (n,e,h',h,t,h_b)
// from evm-partition.tex §"Rounds and Blocks", plus the fields the
// underlying types.InputRecord always carries. Only the fields listed in
// the profile enter the canonical body; the rest are validated but not
// re-committed here.
type ShardInputRecord struct {
	Round        uint64 // n  — shard round
	Epoch        uint64 // e  — shard epoch
	PreviousHash []byte // h' — previous execution state root (nil only at genesis)
	Hash         []byte // h  — resulting execution state root (nil only at genesis)
	Timestamp    uint64 // t  — reference time of the authorizing certificate
	BlockHash    []byte // h_b — Ethereum block hash, nil iff quiet
}

// TechnicalRecord mirrors certification.TechnicalRecord. TE_- authorizes
// the next shard round; the canonical root input commits its hash via
// TRHash and also carries the record itself in companion data.
type TechnicalRecord struct {
	Round    uint64
	Epoch    uint64
	Leader   string
	StatHash []byte
	FeeHash  []byte
}

// RootOrigin is O_- : everything the seal feed imports from the committed
// certification statement authorizing the shard round, with every
// signature and transport proof excluded. Two certificates that authenticate
// the same statement with different valid signature subsets or transport
// encodings MUST produce a byte-identical RootOrigin (see
// TestAlternateSignatureSubsetsAgree).
type RootOrigin struct {
	NetworkID       uint64 // alpha
	RootRound       uint64 // r   = UnicitySeal.RootChainRoundNumber
	RootEpoch       uint64 //       UnicitySeal.Epoch
	ReferenceTime   uint64 // t_r = UnicitySeal.Timestamp
	UnicityTreeRoot []byte // u   = UnicitySeal.Hash
	IR              ShardInputRecord
	TRHash          []byte // hash of TE_- (UC.TRHash)
	ShardConfHash   []byte // certified configuration commitment (UC.ShardConfHash)
}

// canonicalBody returns O_- as a deterministic CBOR array in the field
// order fixed by the profile. This is the signature-free body; it never
// contains a signature map, a shard-tree path or a unicity-tree path.
func (o RootOrigin) canonicalBody() cArray {
	return cArray{
		cUint(o.NetworkID),
		cUint(o.RootRound),
		cUint(o.RootEpoch),
		cUint(o.ReferenceTime),
		cBytes(o.UnicityTreeRoot),
		cArray{
			cUint(o.IR.Round),
			cUint(o.IR.Epoch),
			cBytes(o.IR.PreviousHash), // 32 bytes; at genesis, the pinned genesis commitment (never null)
			cBytes(o.IR.Hash),         // 32 bytes; at genesis, the pinned genesis commitment (never null)
			cUint(o.IR.Timestamp),
			optBytes(o.IR.BlockHash), // null iff quiet (h_b = ⊥)
		},
		cBytes(o.TRHash),
		cBytes(o.ShardConfHash),
	}
}

// Encode returns the canonical deterministic-CBOR encoding of O_-.
func (o RootOrigin) Encode() []byte { return marshalCBOR(o.canonicalBody()) }

// Identity returns H(CBOR(O_-)) — the 32-byte Unicity (SHA-256) identity of
// the root origin, used wherever the profile needs to name a root origin
// without carrying its whole body.
func (o RootOrigin) Identity() Hash32 { return sha256.Sum256(o.Encode()) }

// RootInput is the canonical input the privileged seal operation receives
// and the header commits:
//
//	rootInput = (v, alpha, beta, sigma, n, e, h_parent, O_-, TE_-, D)
//
// D is the ordered sequence of committed trust-base bodies and handoff
// acknowledgements the importing EVM is still missing; each element is an
// opaque, already-canonical body whose external authentication witness is
// NOT re-hashed into this input.
type RootInput struct {
	Version     uint64 // v — must equal ProfileVersion
	NetworkID   uint64 // alpha
	PartitionID uint64 // beta
	ShardID     []byte // sigma — canonical shard-id bytes ("" for the single unsharded governance shard)
	Round       uint64 // n — authorized shard round
	Epoch       uint64 // e — shard epoch
	ParentHash  []byte // h_parent — last certified EVM parent block hash (Ethereum Keccak/RLP hash), carried verbatim
	Origin      RootOrigin
	TE          TechnicalRecord
	Transitions [][]byte // D — ordered; each entry a canonical committed body
}

func (ri RootInput) canonicalBody() cArray {
	te := cArray{
		cUint(ri.TE.Round),
		cUint(ri.TE.Epoch),
		cText(ri.TE.Leader),
		cBytes(ri.TE.StatHash),
		cBytes(ri.TE.FeeHash),
	}
	d := make(cArray, len(ri.Transitions))
	for i, b := range ri.Transitions {
		d[i] = cBytes(b)
	}
	return cArray{
		cUint(ri.Version),
		cUint(ri.NetworkID),
		cUint(ri.PartitionID),
		cBytes(ri.ShardID),
		cUint(ri.Round),
		cUint(ri.Epoch),
		optBytes(ri.ParentHash), // null at genesis (no parent block)
		ri.Origin.canonicalBody(),
		te,
		d,
	}
}

// Encode returns the canonical deterministic-CBOR encoding of rootInput.
func (ri RootInput) Encode() []byte { return marshalCBOR(ri.canonicalBody()) }

// ExtraData returns H(CBOR(rootInput)) — the 32-byte input commitment the
// block header carries in extraData (appendix-evm.tex Table "Deterministic
// block parameters"). H is Unicity SHA-256; the encoding is deterministic
// CBOR. This never involves Keccak or RLP even though rootInput contains an
// Ethereum parent hash as an opaque field.
func (ri RootInput) ExtraData() Hash32 { return sha256.Sum256(ri.Encode()) }
