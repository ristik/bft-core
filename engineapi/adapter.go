package engineapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// The companion-boundary refusals, each named so a caller can tell one from another (F2c §8). None is
// a generic failure and none is a fallback: a block whose companion is absent, malformed, bound to
// different bytes, or unauthenticated against this node's own configuration is refused, never routed
// to the stock V3 path.
var (
	// ErrCompanionMissing means the proposal envelope carried no seal companion at all.
	ErrCompanionMissing = errors.New("engineapi: block has no seal companion")
	// ErrCompanionWitnesses means the witness list is not the required two canonical entries.
	ErrCompanionWitnesses = errors.New("engineapi: seal companion witnesses are not the required [certificate, technical record] pair")
	// ErrCompanionBinding means the leader's published rootInput is not the bytes this node derives.
	ErrCompanionBinding = errors.New("engineapi: seal companion rootInput does not match the canonical derivation")
	// ErrCompanionCommitment means the block header does not commit to the derived input.
	ErrCompanionCommitment = errors.New("engineapi: block extraData does not match the derived commitment")
	// ErrCompanionUnauthenticated means VerifyCompanionWitnesses refused the bound evidence.
	ErrCompanionUnauthenticated = errors.New("engineapi: seal companion failed VerifyCompanionWitnesses")
)

// Adapter implements shardnode.Executor by driving reth over the Engine
// API. It is the only place in this package that touches shardnode types —
// everything else (types.go, client.go, params.go, codec.go) is pure
// Engine-API-facing machinery Adapter composes.
type Adapter struct {
	engine *Client
	eth    *EthClient
	log    *slog.Logger

	// verifier is the derivation context the seal build path authenticates a certificate against.
	// Nil for an adapter that only runs the non-deriving checks (the doctor command); Build refuses
	// rather than deriving against an invented context. See VerifierContext and F2c §3.
	verifier *VerifierContext

	mu      sync.Mutex
	pending map[shardnode.BuildID]buildContext
}

// buildContext is what Build remembers so Seal — called later, with only a
// BuildID — can (a) ask reth for the right payload, (b) construct a correct
// quiet-round echo without re-deriving the parent from scratch, and (c) fill
// the seal companion's witnesses from the authorization this round was built
// on rather than from anything ureth returns.
type buildContext struct {
	payloadID data
	parent    shardnode.BlockRef
	// certificate and technicalRecord are the authenticated, owned copies
	// rootinput.Derive produced. Seal encodes exactly these as the two companion
	// witnesses — the certificate the block binds and the record it commits to.
	certificate     *types.UnicityCertificate
	technicalRecord *certification.TechnicalRecord
}

type Config struct {
	EngineURL string // authenticated engine_* endpoint, e.g. http://localhost:8551
	EthURL    string // plain eth_* endpoint, e.g. http://localhost:8545
	Secret    Secret

	// Verifier is the derivation context Adapter.Build authenticates the authorizing certificate
	// against. It is required to build through the seal siblings and is deliberately nil for an
	// adapter that only runs the non-deriving checks: where the derivation context comes from is the
	// node's own configuration, never the certificate, so Build refuses without it rather than
	// inferring one (F2c §3).
	Verifier *VerifierContext
}

// VerifierContext is the verifier-owned half of rootinput.Context: what this node is configured to
// be, where its trust comes from, and the seal-registry cursor. It carries no per-round pin — Build
// fills Round and the certified parent from RoundParams on every call. Every field comes from the
// node's configuration or its own trust store, never from a certificate or a peer.
type VerifierContext struct {
	NetworkID     types.NetworkID
	PartitionID   types.PartitionID
	ShardID       types.ShardID
	ShardConfHash []byte
	TrustBases    rootinput.TrustBases
	Cursor        SealRegistryCursor
}

func NewAdapter(cfg Config, log *slog.Logger) *Adapter {
	a := &Adapter{
		engine:   NewClient(cfg.EngineURL, cfg.Secret),
		eth:      NewEthClient(cfg.EthURL),
		log:      log,
		verifier: cfg.Verifier,
		pending:  make(map[shardnode.BuildID]buildContext),
	}
	// Once here, never per round: the cursor decision is a startup property, and repeating it every
	// Build would turn one configuration fact into a stream of warnings. Only logged when a verifier
	// context is present, so the doctor's non-deriving adapter stays quiet.
	if a.verifier != nil {
		if warning, ok := a.verifier.Cursor.startupWarning(); ok && log != nil {
			log.Warn(warning)
		}
	}
	return a
}

// RequireSealCapabilities makes the three engine_*WithSealV1 siblings part of the startup capability
// check, so a deployment that builds through the seal siblings fails startup against a client that
// lacks them instead of on the first round. See Client.RequireSealCapabilities for why this is
// opt-in rather than the default.
func (a *Adapter) RequireSealCapabilities() { a.engine.RequireSealCapabilities() }

// CheckCapabilities is the startup check from
// docs/adr/0001-executor-boundary.md decision 3: it refuses to start
// against a client that does not offer the exact V3 method set this
// adapter speaks.
//
// What it establishes is narrow, and was previously overstated here.
// engine_exchangeCapabilities reports what a client BUILD supports, not
// what the loaded chain spec has SCHEDULED. A client whose spec activates
// Prague at genesis offers the V3 set too, and passes this check. Nor does
// generating a chain spec with `ubft engine-api genesis` establish
// anything about the remote client: producing the intended file locally is
// not evidence that this endpoint loaded it, and two specs with identical
// genesis state and identical current capabilities can still schedule
// different future forks.
//
// So the fork schedule is verified separately, by CheckExecutionProfile
// reading the standard eth_config (EIP-7910) — see profile.go. An earlier
// revision of this comment called it an operator constraint no startup
// check could verify; the Engine API offers no such read, but the eth_*
// namespace does. What this check buys is catching the wrong URL, the
// wrong JWT and a clearly incompatible client build before the node can
// vote. Call it once, before Run.
func (a *Adapter) CheckCapabilities(ctx context.Context) error {
	missing, err := a.engine.ExchangeCapabilities(ctx)
	if err != nil {
		return fmt.Errorf("engineapi: checking capabilities: %w", err)
	}
	if len(missing) > 0 {
		return fmt.Errorf("engineapi: execution client is missing required capabilities: %v", missing)
	}
	return nil
}

// CheckChainID verifies the execution client is running the chain this shard is
// configured for, by comparing eth_chainId against the shard conf's chain_id
// partition param — over BOTH configured connections.
//
// Why both. --engine-url and --eth-url are separate flags, so nothing structurally
// stops an operator from pointing them at two different execution clients. The Engine
// connection is the one that decides what this node votes for: Build, Seal and Commit
// all go over it. The plain connection only answers header lookups. Checking the plain
// endpoint alone therefore verifies the chain of a client that does not produce our
// blocks. Asking the same question on the authenticated Engine port needs no new Engine
// method and no client divergence — the Engine API specification's "underlying protocol"
// section requires eth_chainId there, and the pinned client serves it (see Client.ChainID).
//
// Requiring both to equal the configured value also makes them equal to each other, so a
// mispaired pair of clients on different chains is refused here rather than surviving to
// produce blocks nobody certifies.
//
// Scope, stated because it is easy to overclaim. Agreement on chain id establishes
// agreement on chain id. It does NOT establish that the two URLs address the same client
// PROCESS — two clients on the same chain agree on this value and on genesis (see
// CheckGenesisHash), and only diverge once they build different blocks. It also says
// nothing about future fork activations. What it does rule out is the mispairing that
// actually happens in deployment: an endpoint left pointing at another shard's client, or
// at a client started from a different genesis.
func (a *Adapter) CheckChainID(ctx context.Context, want uint64) error {
	engineID, err := a.engine.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("engineapi: reading chain id over the Engine connection: %w", err)
	}
	if engineID != want {
		return fmt.Errorf("engineapi: execution client reports chainId=%d, shard conf says %d", engineID, want)
	}
	ethID, err := a.eth.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("engineapi: reading chain id over the plain connection: %w", err)
	}
	if ethID != want {
		return fmt.Errorf("engineapi: --eth-url reports chainId=%d but --engine-url reports %d "+
			"(shard conf says %d): the two URLs address different execution clients", ethID, engineID, want)
	}
	return nil
}

// CheckGenesisHash verifies the execution client's block 0 is the one this deployment was
// configured for — again over both connections, for the reasons on CheckChainID.
//
// Chain id does not establish this: two chains can share a chain id and differ in allocation,
// fork schedule or any other genesis field, and `ubft engine-api genesis` derives the chain spec
// from the shard conf but not the allocation, so a same-chainId/different-genesis client is a real
// deployment mistake rather than a hypothetical.
//
// `want` must be operator-configured. Deriving it from the client under test would compare a value
// with itself and prove nothing (issue #89 item 2).
//
// Scope: this binds the genesis BLOCK on both connections. It does not establish same-process
// identity, and it does not establish agreement on any fork activation after genesis — a matching
// genesis hash says nothing about a fork scheduled by timestamp later in the chain's life, because
// a fork that has not activated changes no genesis header field. CheckExecutionProfile binds that.
func (a *Adapter) CheckGenesisHash(ctx context.Context, want shardnode.Hash) error {
	if len(want) == 0 {
		return fmt.Errorf("engineapi: no expected genesis hash configured")
	}
	engineGenesis, err := a.engine.GetBlockByNumber(ctx, "0x0")
	if err != nil {
		return fmt.Errorf("engineapi: reading genesis block over the Engine connection: %w", err)
	}
	if !bytes.Equal(engineGenesis.Hash[:], want) {
		return fmt.Errorf("engineapi: execution client genesis is %x, configured expectation is %x",
			engineGenesis.Hash[:], want)
	}
	ethGenesis, err := a.eth.GetBlockByNumber(ctx, "0x0")
	if err != nil {
		return fmt.Errorf("engineapi: reading genesis block over the plain connection: %w", err)
	}
	if !bytes.Equal(ethGenesis.Hash[:], engineGenesis.Hash[:]) {
		return fmt.Errorf("engineapi: --eth-url genesis is %x but --engine-url genesis is %x: "+
			"the two URLs address different execution clients", ethGenesis.Hash[:], engineGenesis.Hash[:])
	}
	return nil
}

// CheckEndpointsPaired compares the genesis block the two configured URLs report, without
// needing an operator-supplied expectation, and returns the hash they agreed on.
//
// CheckChainID and CheckGenesisHash already cross-compare, but the first is coarse (two
// clients on one chain id agree) and the second only runs when --expected-genesis-hash is
// set. This makes the pairing check unconditional: it costs one extra request and catches
// the same-chain-id/different-genesis mispairing on a deployment that has not configured an
// expected hash. It is strictly a pairing check — it asserts nothing about whether that
// shared genesis is the RIGHT one, which is what CheckGenesisHash is for.
//
// It returns the agreed hash so a caller that wants to REPORT the genesis (doctor does) can
// use the value this check actually validated rather than issuing another request. That
// matters for the same reason #89 item 4 did: two requests can disagree, and a report built
// from a second query can describe a state the check never saw.
func (a *Adapter) CheckEndpointsPaired(ctx context.Context) (shardnode.Hash, error) {
	engineGenesis, err := a.engine.GetBlockByNumber(ctx, "0x0")
	if err != nil {
		return nil, fmt.Errorf("engineapi: reading genesis block over the Engine connection: %w", err)
	}
	ethGenesis, err := a.eth.GetBlockByNumber(ctx, "0x0")
	if err != nil {
		return nil, fmt.Errorf("engineapi: reading genesis block over the plain connection: %w", err)
	}
	if !bytes.Equal(ethGenesis.Hash[:], engineGenesis.Hash[:]) {
		return nil, fmt.Errorf("engineapi: --eth-url genesis is %x but --engine-url genesis is %x: "+
			"the two URLs address different execution clients", ethGenesis.Hash[:], engineGenesis.Hash[:])
	}
	return shardnode.Hash(engineGenesis.Hash[:]), nil
}

func (a *Adapter) Head(ctx context.Context) (shardnode.BlockRef, error) {
	h, err := a.eth.GetBlockByNumber(ctx, "latest")
	if err != nil {
		return shardnode.BlockRef{}, fmt.Errorf("engineapi: reading head: %w", err)
	}
	return shardnode.BlockRef{
		Number:    uint64(h.Number),
		Hash:      shardnode.Hash(h.Hash[:]),
		StateRoot: shardnode.Hash(h.StateRoot[:]),
	}, nil
}

// GenesisBlock answers from the client's chain configuration: block number zero, which is fixed by
// the chain spec this client was started with and does not move with what it has committed. That is
// what makes it usable as an execution identity — see shardnode.Executor.GenesisBlock, and note that
// `ubft shard-node run` separately refuses to start when this hash does not match a configured
// --expected-genesis-hash, so the value the round loop compares against is the configured one.
func (a *Adapter) GenesisBlock(ctx context.Context) (shardnode.BlockRef, error) {
	h, err := a.eth.GetBlockByNumber(ctx, "0x0")
	if err != nil {
		return shardnode.BlockRef{}, fmt.Errorf("engineapi: reading genesis block: %w", err)
	}
	return shardnode.BlockRef{
		Number:    uint64(h.Number),
		Hash:      shardnode.Hash(h.Hash[:]),
		StateRoot: shardnode.Hash(h.StateRoot[:]),
	}, nil
}

// Commit issues a forkchoiceUpdated pinning head/safe/finalized to hash —
// see ForkchoiceStateV1's doc comment for why all three are always the same
// value here. This is also round.go's crash-recovery retry target (see
// shardnode/round.go's reconcile and docs/adr/0001-executor-boundary.md
// decision 2): calling it with a hash reth was never told to build is safe
// and simply reports SYNCING if reth doesn't have that block, which is
// exactly the outcome the recovery path needs to distinguish "recovered"
// from "genuinely gone."
func (a *Adapter) Commit(ctx context.Context, hash shardnode.Hash) (shardnode.Status, error) {
	h32, err := toData32(hash)
	if err != nil {
		return shardnode.StatusInvalid, fmt.Errorf("engineapi: commit: %w", err)
	}
	state := ForkchoiceStateV1{HeadBlockHash: h32, SafeBlockHash: h32, FinalizedBlockHash: h32}
	resp, err := a.engine.ForkchoiceUpdatedV3(ctx, state, nil)
	if err != nil {
		return shardnode.StatusSyncing, fmt.Errorf("engineapi: forkchoiceUpdated (commit): %w", err)
	}
	return toStatus(resp.PayloadStatus.Status), nil
}

func (a *Adapter) Build(ctx context.Context, p shardnode.RoundParams) (shardnode.BuildID, error) {
	if a.verifier == nil {
		return "", errors.New("engineapi: build requires a verifier context — NetworkID, PartitionID, ShardID, ShardConfHash and TrustBases come from this node's own configuration, never from the certificate (docs/design/f2c-root-input-wiring-contract.md §3)")
	}
	appliedRootRound, err := a.verifier.Cursor.appliedRootRound()
	if err != nil {
		return "", fmt.Errorf("engineapi: build: %w", err)
	}

	// Derive the canonical root input from the certificate and record that authorized this round.
	// Every rootinput refusal is wrapped rather than replaced, so errors.Is still finds
	// ErrWrongContext, ErrUnauthenticated, ErrNotPinned and the rest at the call site: F2c §8
	// requires a caller to tell a misconfiguration from an attack, and one opaque error would not.
	derived, err := rootinput.Derive(ctx, rootinput.Context{
		NetworkID:     a.verifier.NetworkID,
		PartitionID:   a.verifier.PartitionID,
		ShardID:       a.verifier.ShardID,
		ShardConfHash: a.verifier.ShardConfHash,
		TrustBases:    a.verifier.TrustBases,

		Round:                p.Round,
		ParentHash:           p.Parent.Hash,
		LastAppliedRootRound: appliedRootRound,

		// False, and not a guess: rootinput.Derive independently refuses the epoch-handoff boundary
		// (rootinput/rootinput.go), so false here means "none are pending" for the accepted
		// single-epoch profile. The handoff case is caught by Derive itself rather than by an empty
		// list standing in for "some are pending and could not be authenticated". See F2c §8.
		TransitionsPending: false,
	}, p.AuthorizingCertificate, p.AuthorizingTechnicalRecord)
	if err != nil {
		return "", fmt.Errorf("engineapi: deriving root input for round %d: %w", p.Round, err)
	}

	parentHash32, err := toData32(p.Parent.Hash)
	if err != nil {
		return "", fmt.Errorf("engineapi: build: %w", err)
	}

	parentHeader, err := a.eth.GetBlockByHash(ctx, parentHash32)
	if err != nil {
		return "", fmt.Errorf("engineapi: looking up parent header %x: %w", parentHash32, err)
	}
	attrs := DeriveAttributes(derived.Input, ParentHeader{Timestamp: uint64(parentHeader.Timestamp)})

	sealAttrs := UnicityPayloadAttributes{
		PayloadAttributesV3: attrs,
		Commitment:          data32(derived.Commitment),
	}

	state := ForkchoiceStateV1{HeadBlockHash: parentHash32, SafeBlockHash: parentHash32, FinalizedBlockHash: parentHash32}
	resp, err := a.engine.ForkchoiceUpdatedWithSealV1(ctx, state, &sealAttrs, SealBuildInput{RootInput: derived.Encoded})
	if err != nil {
		return "", fmt.Errorf("engineapi: forkchoiceUpdatedWithSealV1 (build): %w", err)
	}
	if resp.PayloadStatus.Status != PayloadStatusValid {
		return "", fmt.Errorf("engineapi: forkchoiceUpdatedWithSealV1 (build) on our own trusted head returned %s, not VALID: %v",
			resp.PayloadStatus.Status, errString(resp.PayloadStatus.ValidationError))
	}
	if resp.PayloadID == nil {
		return "", errors.New("engineapi: forkchoiceUpdatedWithSealV1 accepted payloadAttributes but returned no payload id")
	}

	id := shardnode.BuildID(hex.EncodeToString(*resp.PayloadID))
	a.mu.Lock()
	a.pending[id] = buildContext{
		payloadID:       *resp.PayloadID,
		parent:          p.Parent,
		certificate:     derived.Certificate,
		technicalRecord: derived.Technical,
	}
	a.mu.Unlock()
	return id, nil
}

// Seal retrieves the built payload and decides, only now, whether the round
// was quiet — see the build plan §6's note on why this can't be known
// before sealing: there is no txpool-inspection API, and
// parentBeaconBlockRoot moves the state root on every produced block
// regardless of transaction count (EIP-4788), so "empty payload" is the
// only reliable signal.
func (a *Adapter) Seal(ctx context.Context, id shardnode.BuildID) (shardnode.Block, error) {
	a.mu.Lock()
	bc, ok := a.pending[id]
	if ok {
		delete(a.pending, id)
	}
	a.mu.Unlock()
	if !ok {
		return shardnode.Block{}, shardnode.ErrNotFound
	}

	resp, err := a.engine.GetPayloadWithSealV1(ctx, bc.payloadID)
	if err != nil {
		return shardnode.Block{}, fmt.Errorf("engineapi: getPayloadWithSealV1: %w", err)
	}

	if len(resp.ExecutionPayload.Transactions) == 0 {
		// Quiet: echo the parent's Number/StateRoot, matching
		// executortest.Fake's own convention for the same case — round.go's
		// quiet-detection compares against Expectation.PreviousHash, not
		// against anything Executor-specific, so every Executor must agree
		// on this shape.
		//
		// Hash is deliberately nil here, NOT bc.parent.Hash — this is not
		// optional cosmetic parity with Fake, it's load-bearing. Fake's own
		// genesis head has a nil Hash by construction (executortest.New),
		// which is what makes blockHashOrFallback's genesis fallback (use
		// StateRoot instead of Hash) trigger correctly. A real execution
		// client's genesis always has a real, non-nil block hash — echoing
		// it here would hand the framework that SAME real hash to use as
		// the genesis round's BlockHash, aliasing a certified round to a
		// block that already existed before this round ran, rather than a
		// value distinct to this round. See docs/troubleshooting.md and
		// TestAdapter_Seal_QuietRound_EchoesParentWithNilHash.
		return shardnode.Block{
			Number:     bc.parent.Number,
			Hash:       nil,
			StateRoot:  bc.parent.StateRoot,
			ParentHash: bc.parent.Hash,
			Raw:        nil,
			BlockSize:  0,
			StateSize:  0,
		}, nil
	}

	// ureth deliberately returns witnesses empty (D2 §"The authentication lifecycle": witnesses are
	// verifier-owned and the execution client holds no trust base), so the leader supplies them before
	// dissemination; without them a follower has nothing to authenticate. rootInput and provenance
	// come back from ureth and are left as they are. The list is exactly [bound certificate, bound
	// technical record] — see SealCompanionWitnessCount for why both travel and why the length is
	// fixed. The pair was authenticated by Build, so an encoding failure here is a local fault and is
	// surfaced rather than turned into an unfilled companion no follower could authenticate.
	witnesses, err := encodeSealCompanionWitnesses(bc.certificate, bc.technicalRecord)
	if err != nil {
		return shardnode.Block{}, fmt.Errorf("engineapi: sealing round: %w", err)
	}
	return EncodeBlockWithSealCompanion(resp.ExecutionPayload, &SealCompanion{
		RootInput:  resp.SealCompanion.RootInput,
		Witnesses:  witnesses,
		Provenance: resp.SealCompanion.Provenance,
	})
}

// Verify is where C2.3's follower-side validation actually happens, and where the F2c §3.1
// authentication boundary sits. The order is forced by v1: the expected parameters are a function of
// the bound certificate's root round and reference time, which arrive with the companion, so the
// block's companion is authenticated against THIS node's own configured trust first, then the
// parameters are derived from the authenticated input and the payload fields are checked against
// them, and only then does the expensive newPayloadWithSealV1 call execute the block. Deriving
// before the companion was authenticated would mean deriving from this node's own
// p.AuthorizingCertificate, which is exactly the re-selection F2c §3.1 forbids. A leader whose
// companion does not authenticate is rejected before reth sees the bound evidence, a leader that
// altered the timestamp or fee recipient is still rejected before execution, and a missing companion
// is a refusal rather than a fallback to the stock V3 path.
//
// The follower validates the binding the block carries; it never re-selects. Two honest nodes hold
// different valid certificates for the same round (duplicates from several root nodes, repeats after
// a timeout), so deriving from whichever this node happens to hold would make them compute different
// commitments for the same block or refuse a valid proposal by delivery order. Everything below is
// derived from the certificate the block binds, and the only view-dependent input is this node's own
// committed seal-registry cursor, which is shared state rather than arrival order (F2c §3.1).
func (a *Adapter) Verify(ctx context.Context, b shardnode.Block, p shardnode.RoundParams) (shardnode.Status, error) {
	if len(b.Raw) == 0 {
		// Quiet block: must be exactly the parent's Number/StateRoot,
		// unchanged. Nothing to execute — see Seal's quiet case above,
		// which this mirrors, including deliberately NOT checking b.Hash
		// against p.Parent.Hash: Seal's echo always sets Hash nil (never
		// the parent's real hash — see that comment for why), so a
		// same-as-parent Hash comparison here would reject every honest
		// quiet block. executortest.Fake.Verify's quiet check has the same
		// shape, for the same reason.
		if b.Number == p.Parent.Number && bytes.Equal(b.StateRoot, p.Parent.StateRoot) {
			return shardnode.StatusValid, nil
		}
		return shardnode.StatusInvalid, nil
	}

	envelope, err := DecodeBlock(b)
	if err != nil {
		return shardnode.StatusInvalid, nil //nolint:nilerr // a malformed envelope is an invalid block, not a local error
	}

	parentHash32, err := toData32(p.Parent.Hash)
	if err != nil {
		return shardnode.StatusInvalid, fmt.Errorf("engineapi: verify: %w", err)
	}
	parentHeader, err := a.eth.GetBlockByHash(ctx, parentHash32)
	if err != nil {
		// We can't tell yet whether the block is bad or we're just behind
		// on the parent — SYNCING is the honest answer, matching the same
		// distinction the Engine API itself draws.
		return shardnode.StatusSyncing, fmt.Errorf("engineapi: looking up parent header for verification: %w", err)
	}

	// From here on the block is authenticated before it is executed. A missing companion is a
	// refusal, never a fallback to the stock V3 path: a block disseminated without one cannot be
	// authenticated by anyone, and silently executing it as a V3 payload would skip exactly the
	// boundary this unit exists to install.
	if a.verifier == nil {
		return shardnode.StatusInvalid, fmt.Errorf("engineapi: verifying round %d: no verifier context — a follower authenticates the bound certificate against its own configured trust base, partition, shard, configuration hash and cursor (docs/design/f2c-root-input-wiring-contract.md §3), and no such context is configured", p.Round)
	}
	if envelope.SealCompanion == nil {
		return shardnode.StatusInvalid, fmt.Errorf("%w: round %d", ErrCompanionMissing, p.Round)
	}
	companion := envelope.SealCompanion

	// Witnesses[0] and witnesses[1] are the bound certificate and the record it commits to, in the
	// canonical-CBOR encoding this repository already uses for both. A wrong length, a decode
	// failure, or a re-encode that is not byte-identical is a refusal.
	uc, tr, err := decodeSealCompanionWitnesses(companion.Witnesses)
	if err != nil {
		return shardnode.StatusInvalid, fmt.Errorf("engineapi: verifying round %d: %w", p.Round, err)
	}

	appliedRootRound, err := a.verifier.Cursor.appliedRootRound()
	if err != nil {
		return shardnode.StatusInvalid, fmt.Errorf("engineapi: verifying round %d: %w", p.Round, err)
	}

	// The authentication: rootinput.Derive against this node's own trust base, network, partition,
	// shard, configuration hash and committed cursor — the same path the builder uses. Nothing is
	// accepted on the proposer's word, and the certificate is never a value this node already held.
	// A stale bound certificate is refused here as a named rootinput class (ErrNotPinned), which is
	// what F2c §8 and §10 negative 6 require: fail fast, with the class that lets an operator tell a
	// misconfiguration from an attack.
	derived, err := rootinput.Derive(ctx, rootinput.Context{
		NetworkID:     a.verifier.NetworkID,
		PartitionID:   a.verifier.PartitionID,
		ShardID:       a.verifier.ShardID,
		ShardConfHash: a.verifier.ShardConfHash,
		TrustBases:    a.verifier.TrustBases,

		Round:                p.Round,
		ParentHash:           p.Parent.Hash,
		LastAppliedRootRound: appliedRootRound,

		// False, as on the build path, and for the same reason: rootinput.Derive independently
		// refuses the epoch-handoff boundary, so false here means "none are pending" for the
		// accepted single-epoch profile, not "some are pending and could not be authenticated".
		TransitionsPending: false,
	}, uc, tr)
	if err != nil {
		return shardnode.StatusInvalid, fmt.Errorf("engineapi: authenticating the bound certificate for round %d: %w", p.Round, err)
	}

	// The leader published bytes; this node derived bytes. They must be the same bytes. This is
	// sharper than a field-by-field comparison: a substituted transition, a swapped record, a wrong
	// origin or a wrong parent all fail on the encoding itself. It also pins that the companion's
	// rootInput is the canonical encoding and not merely a decodable variant.
	if !bytes.Equal(companion.RootInput, derived.Encoded) {
		return shardnode.StatusInvalid, fmt.Errorf("%w: round %d: companion rootInput %x is not the canonical derivation %x",
			ErrCompanionBinding, p.Round, companion.RootInput, derived.Encoded)
	}

	// And the header itself must commit to that same input.
	if !bytes.Equal(envelope.ExecutionPayload.ExtraData, derived.Commitment[:]) {
		return shardnode.StatusInvalid, fmt.Errorf("%w: round %d: header extraData %x, derived commitment %x",
			ErrCompanionCommitment, p.Round, envelope.ExecutionPayload.ExtraData, derived.Commitment[:])
	}

	// VerifyCompanionWitnesses, with this node's own committed cursor. F2c §3.1 step 4 names this
	// check explicitly, and it runs here as defence in depth against the same value: the Derive above
	// has already enforced that cursor, so a stale bound certificate never reaches this call and no
	// distinct refusal reason can originate here. That is the intended outcome, not a gap — F2c §8 and
	// §10 negative 6 require the refusal to arrive as its own rootinput class, which the earlier step
	// gives, not as a reason from this call.
	//
	// Be precise about what is tautological here: the signature verdict and the canonical root input
	// both come from that same Derive, so the O_-/TRHash binding, the teHash(ri.TE) ==
	// ri.Origin.TRHash check and the transitions comparison are satisfied by construction. This is
	// not a second authentication boundary and must not be described as one.
	auth := evmroot.VerifyCompanionWitnesses(evmroot.CompanionWitness{
		UC: evmroot.UCWitness{Cert: evmroot.VerifiedCert{
			// True because rootinput.Derive verified the certificate above, against this node's own
			// configured trust base — never a field a peer supplied.
			SignaturesValid: true,
			RootRound:       derived.Authorizing.RootRound,
			AuthorizedRound: derived.Input.Round,
			OriginID:        derived.Authorizing.OriginID,
			TRHash:          derived.Authorizing.TRHash,
		}},
		// Verifier-owned and empty: no authenticated feed of committed trust-base bodies or handoff
		// acknowledgements reaches a shard node (F2c §8), and an empty list here means "none are
		// pending", never "some are pending and could not be authenticated".
		ExpectedTransitions: nil,
	}, derived.Input, appliedRootRound)
	if !auth.OK {
		return shardnode.StatusInvalid, fmt.Errorf("%w: %s", ErrCompanionUnauthenticated, auth.Reason)
	}

	// Only now, with the input authenticated, are the v1 parameters computable: they are functions of
	// the bound certificate's root round and reference time, both read from derived.Input. The payload
	// fields are checked last of the checks, so a block that fails authentication is reported as an
	// authentication failure rather than as a field divergence. A divergence stays StatusInvalid with
	// the local warning, not an error return, exactly as before the reordering.
	attrs := DeriveAttributes(derived.Input, ParentHeader{Timestamp: uint64(parentHeader.Timestamp)})
	claimed := PayloadFields{
		Timestamp:             envelope.ExecutionPayload.Timestamp,
		PrevRandao:            envelope.ExecutionPayload.PrevRandao,
		SuggestedFeeRecipient: envelope.ExecutionPayload.FeeRecipient,
		Withdrawals:           envelope.ExecutionPayload.Withdrawals,
	}
	if err := VerifyPayloadFields(derived.Input, ParentHeader{Timestamp: uint64(parentHeader.Timestamp)}, claimed); err != nil {
		if a.log != nil {
			a.log.WarnContext(ctx, "rejecting round before execution: attributes diverge from local derivation", slog.String("err", err.Error()))
		}
		return shardnode.StatusInvalid, nil
	}

	// parentBeaconBlockRoot is never trusted from the envelope (it isn't even a field in it — see
	// codec.go's ProposalEnvelope doc comment): derive it from the authenticated input, the same way
	// the leader was required to, and feed our own value into newPayloadWithSealV1. A leader that
	// built against a different value gets caught by the field comparison above and, failing that, as
	// a state-root mismatch, not by comparing the value directly.
	//
	// Only now does the execution client see it, over the JWT-authenticated Engine connection, with
	// reth accepting the verdict produced above.
	status, err := a.engine.NewPayloadWithSealV1(ctx, envelope.ExecutionPayload, envelope.ExpectedBlobVersionedHashes, attrs.ParentBeaconBlockRoot, *companion)
	if err != nil {
		return shardnode.StatusSyncing, fmt.Errorf("engineapi: newPayloadWithSealV1: %w", err)
	}
	return toStatus(status.Status), nil
}

func toStatus(s PayloadStatus) shardnode.Status {
	switch s {
	case PayloadStatusValid:
		return shardnode.StatusValid
	case PayloadStatusSyncing:
		return shardnode.StatusSyncing
	case PayloadStatusAccepted:
		return shardnode.StatusAccepted
	case PayloadStatusInvalid, PayloadStatusInvalidBlockHash:
		return shardnode.StatusInvalid
	default:
		return shardnode.StatusInvalid
	}
}

func toData32(h shardnode.Hash) (data32, error) {
	var d data32
	if len(h) != 32 {
		return d, fmt.Errorf("expected a 32-byte hash, got %d bytes", len(h))
	}
	copy(d[:], h)
	return d, nil
}

func errString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

var _ shardnode.Executor = (*Adapter)(nil)
