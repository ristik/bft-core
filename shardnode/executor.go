// Package shardnode implements the shard-node role: a BFT Core client that
// certifies state-root transitions against the root chain. It knows nothing
// about what a "block" contains — that is the Executor's job.
//
// See docs/shard-protocol.md for the normative round protocol and
// docs/adr/0001-executor-boundary.md for why the boundary is drawn here.
package shardnode

import (
	"context"
	"errors"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// Hash is a raw digest — a state root, a block hash, a UC hash. Length is
// Executor-defined; the framework never inspects it, only compares and
// forwards it.
type Hash []byte

// ErrBlockBindingUnavailable marks a local prerequisite that can be retried
// without treating the peer's certified body as invalid.
var ErrBlockBindingUnavailable = errors.New("shardnode: block binding prerequisite unavailable")

// ErrLeaderProposalConflict means a different local proposal was already
// journaled for this authorization. The round must abstain without stopping.
var ErrLeaderProposalConflict = errors.New("shardnode: leader proposal already retained")

// BlockRef identifies one committed block without carrying its contents.
type BlockRef struct {
	Number    uint64
	Hash      Hash
	StateRoot Hash
}

// RoundParams is everything the framework derives from a Unicity Certificate
// and hands to the Executor for the next round. It is the only Unicity
// concept an Executor needs to understand; deriving concrete block
// parameters (an EVM header's timestamp, prevRandao, and so on) from it is
// the Executor's job, not the framework's.
type RoundParams struct {
	Round     uint64 // TechnicalRecord.Round for this round
	Epoch     uint64 // TechnicalRecord.Epoch for this round
	Timestamp uint64 // UnicitySeal.Timestamp of the certificate that authorized this round (seconds)

	// SealHash is UnicitySeal.Hash — the certified Unicity Tree root, already
	// a computed, signed 32-byte value. Deliberately NOT a hash of the whole
	// certificate: CBOR re-encoding or signature-map ordering could differ
	// byte-for-byte between two honest implementations of the *same*
	// certificate, where the seal's own Hash field cannot, since it's the
	// literal signed value.
	//
	// It is NOT a source for round-derived randomness. This comment used to
	// point an EVM adapter at it for prevRandao and parentBeaconBlockRoot,
	// with its own domain-separation prefix; that is the v0 derivation W4
	// deleted, and F2c §9 forbids reviving it. A seal hash is a value, not a
	// certificate — it carries no quorum, no inclusion path and no trust
	// base, so a caller can fabricate one and an executor holding it cannot
	// tell. Derive from the authenticated root input instead
	// (engineapi.DeriveAttributes over rootinput.Derive's result), which
	// keys off the certified (RootRound, Round) pair.
	SealHash Hash

	Leader string // TechnicalRecord.Leader — the shard node ID building this round
	Parent BlockRef

	// AuthorizingCertificate is the certificate that authorizes this round: the
	// one whose bound technical record names this round, whose InputRecord.Hash
	// is the last certified state. Round, Epoch and Timestamp above are
	// scalars extracted from this same certificate and its record; it is
	// carried whole so an executor can authenticate a certificate rather than
	// trust the framework's summary of one.
	//
	// It is a pinned input, not a value to trust. A consumer must authenticate
	// it against its own configured trust base, partition, shard and
	// configuration hash before deriving anything from it, exactly as
	// rootinput.Derive does, and it must infer nothing from the executor's own
	// state: the executor's head is not a substitute for the certified parent,
	// and the highest root round this node has observed is not a substitute for
	// its committed cursor. See
	// docs/design/f2c-root-input-wiring-contract.md §3 and §3.1 for the contract
	// under which it is consumed. Nothing consumes it yet — W2b builds on it.
	AuthorizingCertificate *types.UnicityCertificate

	// AuthorizingTechnicalRecord is the technical record the authorizing
	// certificate commits to by hash (AuthorizingCertificate.TRHash). The two
	// travel together because the certificate carries only that hash, and
	// reconstructing the record is not possible from it. Like the certificate,
	// it is a pinned input a consumer must authenticate, never a value to trust.
	AuthorizingTechnicalRecord *certification.TechnicalRecord
}

// BuildID identifies an in-progress block construction, valid only between
// Build and Seal on the same Executor instance.
type BuildID string

// Block is what one round produces. Raw is the Executor's own wire encoding
// used for dissemination (leader to followers); the framework never parses
// it, only carries it.
//
// BlockSize and StateSize feed directly into the outgoing
// BlockCertificationRequest, and the root chain hashes both of them into
// its quorum key alongside the InputRecord (see
// rootchain/request_buffer.go's Add) — two validators reporting different
// sizes for byte-identical state is exactly as fatal to quorum as
// disagreeing on the state root itself. Every Executor implementation must
// derive both deterministically from the block's own content, never from
// something ambient (wall-clock timing, local buffer sizes, and so on).
type Block struct {
	Number     uint64
	Hash       Hash
	StateRoot  Hash
	ParentHash Hash
	Raw        []byte

	BlockSize uint64 // canonical size of the block's own encoding — e.g. len(Raw) if Raw is already that canonical form
	StateSize uint64 // canonical size of the resulting state, or 0 if the Executor does not track one
}

// Status mirrors the four outcomes the Ethereum Engine API defines for a
// payload, because every execution layer this framework is likely to wrap
// needs the same four states, not because the framework assumes an Ethereum
// executor.
type Status int

const (
	// StatusValid: the block is valid and, if this was Commit, now canonical.
	StatusValid Status = iota
	// StatusInvalid: the block is malformed or does not extend head correctly.
	// Fatal for the round — the framework does not retry it.
	StatusInvalid
	// StatusSyncing: the executor cannot judge validity yet, typically
	// because it lacks the parent block locally. The framework must not
	// submit a certification request while its executor reports this.
	StatusSyncing
	// StatusAccepted: the block was received and looks plausible but is not
	// yet fully validated. Treated like StatusSyncing by the framework: safe
	// to wait on, not safe to certify from.
	StatusAccepted
)

func (s Status) String() string {
	switch s {
	case StatusValid:
		return "valid"
	case StatusInvalid:
		return "invalid"
	case StatusSyncing:
		return "syncing"
	case StatusAccepted:
		return "accepted"
	default:
		return "unknown"
	}
}

// ErrNotFound is returned by Seal when BuildID is unknown (expired, wrong
// executor instance, or never issued).
var ErrNotFound = errors.New("shardnode: build id not found")

// ErrBuildUnavailable means the executor refused to start a payload job on a
// locally trusted parent. It is not a verdict about a proposed block.
var ErrBuildUnavailable = errors.New("shardnode: execution payload build unavailable")

// Executor is what a shard node runs. Implementations decide what a block
// contains and what its state root means; the framework only sequences
// calls and carries the results into and out of Unicity Certificates.
//
// No implementation may block indefinitely without honoring ctx
// cancellation — the round loop depends on that to enforce T2-derived
// deadlines.
type Executor interface {
	// Head reports the executor's current committed block and state root.
	// Called once per round to learn what the next round builds on.
	Head(ctx context.Context) (BlockRef, error)

	// GenesisBlock reports the executor's block ZERO — the block its chain
	// configuration starts from, not whatever it has committed since.
	//
	// It exists because the framework needs an execution identity it can
	// state independently of anything this process has done. The shard's
	// first certified round is non-quiet by convention even when nothing
	// moved, so it carries a block hash the executor may never make
	// canonical (see BlockHashOrFallback and Round's P-id check); deciding
	// "the executor is still at its configured genesis" from the first head
	// this process happened to observe is not the same claim, because a new
	// process can attach to an executor that has already committed blocks.
	// Implementations must answer from configuration — an Ethereum client
	// by asking for block 0 — never by caching an observed head.
	GenesisBlock(ctx context.Context) (BlockRef, error)

	// Commit makes the block identified by hash canonical and final. Called
	// only after a Unicity Certificate has certified it — an Executor
	// implementation never needs to un-commit a block, because the
	// framework never commits one that lacks a UC.
	Commit(ctx context.Context, hash Hash) (Status, error)

	// Build starts constructing a block on top of p.Parent. Called only on
	// the round's leader (RoundParams.Leader equals this node's ID). The
	// returned BuildID is later passed to Seal.
	//
	// The parent to build on is p.Parent, not a separate argument: an
	// earlier revision of this interface took the parent's state root as
	// its own Hash parameter alongside RoundParams, which was redundant
	// with RoundParams.Parent and ambiguous about whether it meant a state
	// root or a block hash. RoundParams.Parent.StateRoot and .Hash are both
	// available and unambiguous; use whichever this Executor keys blocks by.
	Build(ctx context.Context, p RoundParams) (BuildID, error)

	// Seal finalizes and returns the block started by Build. Leader only.
	Seal(ctx context.Context, id BuildID) (Block, error)

	// Verify executes a block built by the round's leader and disseminated
	// to this node. Called on every non-leader validator, once per round —
	// and by the leader on its own output too (see round.go's
	// HandleCertificate), so an Executor cannot assume "Verify" implies
	// "someone else built this."
	//
	// p is the same RoundParams the leader was given for this round.
	// Without it, an Executor has no way to independently recompute what
	// the block's parameters *should* be and can only trust whatever is
	// embedded in b itself — which defeats follower-side validation
	// entirely (a leader that lies about, say, its own timestamp would be
	// trusted rather than caught). p is what makes recompute-and-compare
	// possible; engineapi's Verify is built around exactly that.
	Verify(ctx context.Context, b Block, p RoundParams) (Status, error)
}
