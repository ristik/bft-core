package engineapi

// H3 #20 criterion X2: a NONEMPTY H3 assignment transition is derived to identical input, commitment and
// execution-client input however the old root quorum happened to sign it, on the builder, follower and replay
// paths, and each of X2's refusals is raised by exactly one isolated mutation.
//
// Everything is real up to the execution client's JSON-RPC surface: a four-member root trust base signs the
// certificate with two different valid three-signer subsets, the transition is installed through
// VerifierContext.InstallHandoffTransition from a bundle that carries a real candidate (successor PDR plus
// a signed proof of possession), the parent registry witness is served over RPC and verified by the
// production ParentWitnessSource, and the three paths are Adapter.PrepareBuild (builder), Adapter.Verify
// (follower) and Adapter.Verify under Adapter.HistoricalContext (replay). Only reth is a mock, and its
// handlers capture the bytes the real reth (ureth) would receive.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/internal/testutils/identityfix"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/registrywitness"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	x2RootEpoch      = 2  // the root epoch the acknowledgement installs
	x2AuthRootRound  = 12 // root round of the authorizing certificate
	x2StaleRootRound = 4  // behind the parent's recorded root round (5)
	x2ShardRound     = 11 // the acknowledgement's EVM round, i.e. the authorized shard round
)

// x2Epochs is a RootEpochAuthority fixed at one epoch.
type x2Epochs uint64

func (e x2Epochs) CurrentRootEpoch() (uint64, bool) { return uint64(e), true }

type x2Trust map[uint64]*types.RootTrustBaseV1

func (m x2Trust) GetByEpoch(_ context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	tb, ok := m[epoch]
	if !ok {
		return nil, errors.New("no trust base")
	}
	return tb, nil
}

// x2World is the deployment: sealRegistry/v2 genesis, the certified parent P whose registry still shows the
// genesis assignment, a four-node root and one real successor assignment with a candidate carrying its PoP.
type x2World struct {
	t        *testing.T
	chain    *certifiedchain.Chain
	origin   registrygenesis.GenesisOrigin
	genesis  certifiedchain.Block
	parent   certifiedchain.Block
	pdr      [2]*types.PartitionDescriptionRecord
	hash     [2][32]byte
	signers  []abcrypto.Signer
	ids      []string
	trust    x2Trust
	bundle   handoffdelivery.Bundle
	verified handoffdelivery.Verified
	step     handoff.EVMTransition
	// active is the assignment the parent registry shows: the genesis one until the acknowledgement is imported.
	active registryproof.Assignment
	// genesisParent makes the genesis block the acknowledgement block's parent.
	genesisParent bool
}

// newX2World builds the deployment with the acknowledgement block's parent either the post-genesis block B1 (registry
// witness served over RPC) or the genesis block itself (the configured bootstrap snapshot, the shape Ureth's own
// acknowledgement kernel tests use).
func newX2World(t *testing.T, genesisParent bool) *x2World {
	t.Helper()
	c := certifiedchain.NewV2(t, 3, 0)
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(c.Genesis.GenesisJSON(), &doc))
	var alloc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(doc["alloc"], &alloc))
	for k := range alloc {
		if strings.EqualFold(strings.TrimPrefix(k, "0x"), strings.TrimPrefix(registryproof.RegistryAddress.Hex(), "0x")) {
			delete(alloc, k)
		}
	}
	doc["alloc"], _ = json.Marshal(alloc)
	source, err := json.Marshal(doc)
	require.NoError(t, err)
	art, err := registrygenesis.PinnedArtifactV2()
	require.NoError(t, err)
	p, err := registrygenesis.PrepareGenesisJSON(certifiedchain.Config(3), c.Pins, art, source, registrygenesis.GenesisJSONLimits{})
	require.NoError(t, err)
	o := p.Origin()
	b0 := certifiedchain.Block{Hash: o.BlockHash(), StateRoot: o.StateRoot(), Evidence: o.Evidence()}
	w := &x2World{t: t, chain: c, origin: o, genesis: b0, parent: c.Executed(b0, 1, 5), trust: x2Trust{}, genesisParent: genesisParent}
	if genesisParent {
		w.parent = b0
	}

	// Four root nodes: three signatures make a quorum, so several distinct valid subsets exist.
	w.signers = []abcrypto.Signer{c.Signer}
	for i := 1; i < 4; i++ { // fixed keys, so the exported vector is reproducible byte for byte
		s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(bytes.Repeat([]byte{byte(0x50 + i)}, 32))
		require.NoError(t, err)
		w.signers = append(w.signers, s)
	}
	for _, s := range w.signers {
		w.ids = append(w.ids, nodeID(t, s))
	}
	tb, ok := testtrustbase.NewTrustBase(t, w.signers...).(*types.RootTrustBaseV1)
	require.True(t, ok)
	for epoch := uint64(1); epoch <= x2RootEpoch; epoch++ {
		cp := *tb
		cp.Epoch, cp.Signatures = epoch, nil
		w.trust[epoch] = &cp
	}

	// The successor assignment replaces validator 0's key by a fresh key that signs its own possession proof.
	w.pdr[0] = c.Full
	succ, err := evmassign.NewSuccessor(w.pdr[0], w.pdr[0].Validators)
	require.NoError(t, err)
	fresh, err := abcrypto.NewInMemorySecp256K1SignerFromKey(bytes.Repeat([]byte{0x60}, 32))
	require.NoError(t, err)
	fv, err := fresh.Verifier()
	require.NoError(t, err)
	key, err := fv.MarshalPublicKey()
	require.NoError(t, err)
	succ.Validators[0] = &types.NodeInfo{NodeID: "validator-2", SigKey: key, Stake: 1}
	w.pdr[1], err = evmassign.Activate(succ, 10)
	require.NoError(t, err)
	for i, pdr := range w.pdr {
		h, err := evmassign.PDRHash(pdr)
		require.NoError(t, err)
		w.hash[i] = h
	}
	popCtx := evmassign.PoPContext{Network: 3, Predecessor: [32]byte{0x44}, Attempt: 1}
	pop, err := evmassign.SignPoP(fresh, popCtx, succ, "validator-2")
	require.NoError(t, err)
	require.NoError(t, evmassign.VerifyPoPs(popCtx, succ, []evmassign.PoP{pop}), "premise: the candidate carries a valid proof of possession")
	assignment, err := types.Cbor.Marshal(succ)
	require.NoError(t, err)
	candidate, err := identityfix.Shaped(evmassign.Candidate{Version: evmassign.CandidateVersion, Network: 3, Predecessor: popCtx.Predecessor[:], Attempt: 1,
		OldShardEpoch: 0, OldActiveHash: w.hash[0][:], Assignment: assignment, PoPs: []evmassign.PoP{pop}}).Encode()
	require.NoError(t, err)

	// The committed H: root epoch 1 -> 2, shard epoch 0 -> 1, frozen on the parent P.
	tr10 := certification.TechnicalRecord{Round: x2ShardRound - 1, Epoch: 0}
	hash10, err := tr10.Hash()
	require.NoError(t, err)
	w.bundle = handoffdelivery.Bundle{Body: evmroot.TrustBaseBodyV2{Epoch: x2RootEpoch}, Candidate: candidate}
	w.bundle.Proof.Record = evmroot.OrderedHandoffRecord{Network: 3, Epoch: 1, Attempt: 1, OrderedRound: 6, ActivationRound: 10,
		PredecessorBodyID: bytes.Repeat([]byte{7}, 32), FrozenID: bytes.Repeat([]byte{2}, 32), NextBodyID: bytes.Repeat([]byte{1}, 32),
		SuccessorTRHash: hash10, Kind: "commit"}
	w.bundle.Proof.Control.FrozenParent = w.parent.Hash.Bytes()
	w.verified = handoffdelivery.Verified{Genesis: evmroot.EpochGenesis{Epoch: x2RootEpoch},
		Shard: abdrc.ShardInfo{TR: &tr10, IRTR: tr10, ShardConfHash: w.hash[0][:]}}
	w.active = registryproof.Assignment{Set: true, ShardEpoch: 0, RootEpoch: 1, ActiveConfHash: common.Hash(w.hash[0])}
	return w
}

func nodeID(t *testing.T, s abcrypto.Signer) string {
	v, err := s.Verifier()
	require.NoError(t, err)
	pk, err := v.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(t, err)
	return id.String()
}

func (w *x2World) irAt() *types.InputRecord {
	if w.genesisParent { // the exact bootstrap input record (#153 §7.3 E2)
		return &types.InputRecord{Version: 1}
	}
	return &types.InputRecord{Version: 1, RoundNumber: w.parent.Round, Epoch: 0, PreviousHash: w.genesis.StateRoot.Bytes(),
		Hash: w.parent.StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_000 + w.parent.Round, BlockHash: w.parent.Hash.Bytes()}
}

func (w *x2World) technical() *certification.TechnicalRecord {
	tr := certifiedchain.Technical(x2ShardRound - 1)
	tr.Epoch, tr.Round = 1, x2ShardRound
	return tr
}

// certify has the root quorum of rootEpoch sign the successor-configuration certificate of P with exactly the given subset.
func (w *x2World) certify(tr *certification.TechnicalRecord, rootRound, rootEpoch uint64, subset ...int) *types.UnicityCertificate {
	w.t.Helper()
	uc := w.chain.CertifyFor(w.pdr[1], w.chain.Signer, w.irAt(), tr, rootRound)
	uc.UnicitySeal.NetworkID = 3
	uc.UnicitySeal.Epoch = rootEpoch
	uc.UnicitySeal.Signatures = nil
	for _, i := range subset {
		require.NoError(w.t, uc.UnicitySeal.Sign(w.ids[i], w.signers[i]))
	}
	return uc
}

// x2Path is one independently constructed verifier-owned stack: its own VerifierContext with the installed
// transition, its own parent-witness source and its own mock reth.
type x2Path struct {
	a        *Adapter
	verifier *VerifierContext
	seen     *x2Seen
}

// x2Seen is what the execution client would have received.
type x2Seen struct {
	buildRootInput   []byte
	buildTransitions [][]byte
	buildCommitment  []byte
	buildCalls       int
	newRootInput     []byte
	newExtraData     []byte
	newBeaconRoot    []byte
	newCalls         int
}

func (w *x2World) path(mutate func(*VerifierContext), epoch uint64) *x2Path {
	w.t.Helper()
	snapshot, err := registryproof.Verify(w.origin.ProofContext(), w.genesis.Hash, w.genesis.Evidence)
	require.NoError(w.t, err)
	v := &VerifierContext{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, ShardConfHash: w.origin.FullShardConfHash().Bytes(),
		RootEpoch: 1, TrustBases: w.trust, EpochAuthority: x2Epochs(epoch), GenesisOrigin: w.origin, BootstrapSnapshot: snapshot, Cursor: CursorNotActivated()}
	v.SetConfForEpoch(func(shardEpoch uint64) ([]byte, bool) {
		if shardEpoch > 1 {
			return nil, false
		}
		return bytes.Clone(w.hash[shardEpoch][:]), true
	})
	require.NoError(w.t, v.InstallHandoffTransition(w.bundle, w.verified))
	if mutate != nil {
		mutate(v)
	}

	var source *ParentWitnessSource
	if !w.genesisParent {
		registry := w.origin.ProofContext()
		registry.Active = w.active
		srv := x2WitnessServer(w.t, w.parent.Hash, w.parent.Evidence)
		w.t.Cleanup(srv.Close)
		var err error
		source, err = NewParentWitnessSource(context.Background(), ParentWitnessPins{NetworkID: v.NetworkID, PartitionID: v.PartitionID,
			ShardID: v.ShardID, FullShardConfHash: w.origin.FullShardConfHash(), Registry: registry},
			registrywitness.NewHTTPCaller(srv.URL, time.Second), DefaultParentWitnessBudget())
		require.NoError(w.t, err)
		w.t.Cleanup(source.Close)
	}

	seen := &x2Seen{}
	engine, eth := newMockReth(w.t, Secret{}), newMockReth(w.t, Secret{})
	payloadID := data{1, 2, 3, 4, 5, 6, 7, 8}
	engine.on("engine_forkchoiceUpdatedWithSealV1", func(raw json.RawMessage) (any, *rpcError) {
		var args []json.RawMessage
		require.NoError(w.t, json.Unmarshal(raw, &args))
		require.Len(w.t, args, 3)
		var attrs UnicityPayloadAttributes
		require.NoError(w.t, json.Unmarshal(args[1], &attrs))
		var in SealBuildInput
		require.NoError(w.t, json.Unmarshal(args[2], &in))
		seen.buildCalls++
		seen.buildCommitment = bytes.Clone(attrs.Commitment[:])
		seen.buildRootInput = bytes.Clone(in.RootInput)
		for _, tx := range in.Transitions {
			seen.buildTransitions = append(seen.buildTransitions, bytes.Clone(tx))
		}
		return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}, PayloadID: &payloadID}, nil
	})
	engine.on("engine_newPayloadWithSealV1", func(raw json.RawMessage) (any, *rpcError) {
		var args []json.RawMessage
		require.NoError(w.t, json.Unmarshal(raw, &args))
		require.Len(w.t, args, 4)
		var payload ExecutionPayloadV3
		require.NoError(w.t, json.Unmarshal(args[0], &payload))
		var beacon data32
		require.NoError(w.t, json.Unmarshal(args[2], &beacon))
		var companion SealCompanion
		require.NoError(w.t, json.Unmarshal(args[3], &companion))
		seen.newCalls++
		seen.newExtraData = bytes.Clone(payload.ExtraData)
		seen.newBeaconRoot = bytes.Clone(beacon[:])
		seen.newRootInput = bytes.Clone(companion.RootInput)
		return PayloadStatusV1{Status: PayloadStatusValid}, nil
	})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: quantity(w.parent.Number), Hash: data32(w.parent.Hash), Timestamp: 0}, nil
	})
	a, closeFn := newTestAdapterWithVerifier(w.t, engine, eth, v)
	w.t.Cleanup(closeFn)
	if source != nil {
		a.parentWitness = source
	}
	return &x2Path{a: a, verifier: v, seen: seen}
}

// x2WitnessServer serves the parent block's v2-layout registry evidence over the two RPCs the production requester uses.
// (sourceServer in parent_witness_source_test.go checks the layout-1 key count.)
func x2WitnessServer(t *testing.T, block common.Hash, ev registryproof.Evidence) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		var result any
		switch req.Method {
		case "debug_getRawHeader":
			result = hexutil.Bytes(ev.Header)
		case "eth_getProof":
			var keys []string
			if len(req.Params) != 3 || json.Unmarshal(req.Params[1], &keys) != nil || len(keys) != len(ev.StorageProofs) ||
				string(req.Params[2]) != `{"blockHash":"`+block.Hex()+`"}` {
				t.Errorf("unexpected proof request %s", req.Params)
				return
			}
			p := registryproof.GetProofResult{Address: registryproof.RegistryAddress}
			for _, n := range ev.AccountProof {
				p.AccountProof = append(p.AccountProof, hexutil.Bytes(bytes.Clone(n)))
			}
			for i := range ev.StorageProofs {
				sp := registryproof.StorageProofResult{Key: keys[i]}
				for _, n := range ev.StorageProofs[i] {
					sp.Proof = append(sp.Proof, hexutil.Bytes(bytes.Clone(n)))
				}
				p.StorageProof = append(p.StorageProof, sp)
			}
			result = p
		default:
			t.Errorf("unexpected RPC %s", req.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	}))
}

func (w *x2World) params(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) shardnode.RoundParams {
	return shardnode.RoundParams{Round: tr.Round,
		Parent:                 shardnode.BlockRef{Number: w.parent.Number, Hash: w.parent.Hash.Bytes(), StateRoot: w.parent.StateRoot.Bytes()},
		AuthorizingCertificate: uc, AuthorizingTechnicalRecord: tr}
}

// block is what an honest leader disseminates: payload fields and extraData from the leader's own derivation,
// the companion carrying that derivation's bytes and the bound witnesses.
func (w *x2World) block(leader *x2Path, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) shardnode.Block {
	w.t.Helper()
	derived, err := leader.a.deriveV2(context.Background(), w.params(uc, tr), uc, tr)
	require.NoError(w.t, err)
	attrs := DeriveAttributesV2(derived.Input, ParentHeader{}, leader.a.feeCollector)
	payload := samplePayload()
	payload.ParentHash = data32(w.parent.Hash)
	payload.BlockNumber = quantity(w.parent.Number + 1)
	payload.Timestamp, payload.PrevRandao, payload.FeeRecipient, payload.Withdrawals = attrs.Timestamp, attrs.PrevRandao, attrs.SuggestedFeeRecipient, attrs.Withdrawals
	payload.ExtraData = derived.Commitment[:]
	witnesses, err := encodeSealCompanionWitnesses(uc, tr)
	require.NoError(w.t, err)
	b, err := EncodeBlockWithSealCompanion(payload, &SealCompanion{RootInput: derived.Encoded, Witnesses: witnesses, Provenance: "build"})
	require.NoError(w.t, err)
	return b
}

func (p *x2Path) build(params shardnode.RoundParams) error {
	_, err := p.a.Build(context.Background(), params)
	return err
}

// x2Result is everything one path derived, for byte comparison.
type x2Result struct {
	rootInput, commitment, transition, beaconRoot []byte
}

// run drives one signer subset through all three paths, each on its own stack, and returns what each handed to the
// execution client. The follower and replay stacks verify a block the builder's derivation produced; the replay stack's
// current root epoch is already past the acknowledgement, so only the historical context admits the certificate.
func (w *x2World) run(subset ...int) (builder, follower, replay x2Result, uc *types.UnicityCertificate) {
	w.t.Helper()
	tr := w.technical()
	uc = w.certify(tr, x2AuthRootRound, x2RootEpoch, subset...)
	params := w.params(uc, tr)

	b := w.path(nil, x2RootEpoch)
	require.NoError(w.t, b.build(params), "builder path: PrepareBuild")
	require.Equal(w.t, 1, b.seen.buildCalls)
	require.Len(w.t, b.seen.buildTransitions, 1, "the build input carries exactly the one assignment transition")
	builder = x2Result{rootInput: b.seen.buildRootInput, commitment: b.seen.buildCommitment, transition: b.seen.buildTransitions[0]}

	block := w.block(b, uc, tr)

	f := w.path(nil, x2RootEpoch)
	status, err := f.a.Verify(context.Background(), block, params)
	require.NoError(w.t, err, "follower path: Verify")
	require.Equal(w.t, shardnode.StatusValid, status)
	require.Equal(w.t, 1, f.seen.newCalls)
	follower = x2Result{rootInput: f.seen.newRootInput, commitment: f.seen.newExtraData, beaconRoot: f.seen.newBeaconRoot}

	r := w.path(nil, x2RootEpoch+1)
	_, err = r.a.Verify(context.Background(), block, params)
	require.ErrorIs(w.t, err, rootinput.ErrV2Context, "premise: a live Verify at a later root epoch refuses the old certificate")
	require.Zero(w.t, r.seen.newCalls)
	status, err = r.a.Verify(r.a.HistoricalContext(context.Background()), block, params)
	require.NoError(w.t, err, "replay path: Verify under HistoricalContext")
	require.Equal(w.t, shardnode.StatusValid, status)
	require.Equal(w.t, 1, r.seen.newCalls)
	replay = x2Result{rootInput: r.seen.newRootInput, commitment: r.seen.newExtraData, beaconRoot: r.seen.newBeaconRoot}

	// The transition body itself: the verifier's installed span for the parent registry's epoch.
	raw, err := b.verifier.transitionFor(1, x2RootEpoch)
	require.NoError(w.t, err)
	follower.transition, replay.transition = raw, raw
	return builder, follower, replay, uc
}

func TestX2NonemptyAssignmentTransitionIsSignerSubsetIndependent(t *testing.T) {
	t.Run("parent is the post-genesis block", func(t *testing.T) { x2SubsetIndependence(t, newX2World(t, false), false) })
	t.Run("parent is the genesis block", func(t *testing.T) { x2SubsetIndependence(t, newX2World(t, true), true) })
}

func x2SubsetIndependence(t *testing.T, w *x2World, export bool) {

	// Two distinct valid three-of-four subsets; B excludes root node 0, which A includes.
	bA, fA, rA, ucA := w.run(0, 1, 2)
	bB, fB, rB, ucB := w.run(1, 2, 3)

	require.NotEqual(t, ucA.UnicitySeal.Signatures, ucB.UnicitySeal.Signatures, "premise: the subsets really differ")
	require.Len(t, ucA.UnicitySeal.Signatures, 3)
	require.Len(t, ucB.UnicitySeal.Signatures, 3)

	// The transition is nonempty and is a real assignment step: shard epoch 0 -> 1 over the candidate's hash.
	step, err := handoff.DecodeEVMTransition(bA.transition)
	require.NoError(t, err)
	require.EqualValues(t, [2]uint64{1, 2}, [2]uint64{step.OldRootEpoch, step.NewRootEpoch})
	require.EqualValues(t, [2]uint64{0, 1}, [2]uint64{step.OldShardEpoch, step.NewShardEpoch})
	require.Equal(t, w.hash[0], step.OldActiveConfHash)
	require.Equal(t, w.hash[1], step.NewActiveConfHash)
	require.EqualValues(t, x2ShardRound, step.Ack.EVMRound)
	require.Equal(t, [32]byte(w.parent.Hash), step.Ack.FrozenParent)

	// Within one subset the three paths agree; across subsets everything agrees. Compared as bytes.
	all := map[string]x2Result{"builder/A": bA, "follower/A": fA, "replay/A": rA, "builder/B": bB, "follower/B": fB, "replay/B": rB}
	for name, got := range all {
		require.NotEmpty(t, got.rootInput, name)
		require.Equal(t, bA.rootInput, got.rootInput, "%s: root input (encoded)", name)
		require.Equal(t, bA.commitment, got.commitment, "%s: commitment", name)
		require.Equal(t, bA.transition, got.transition, "%s: transition body", name)
	}
	for _, name := range []string{"follower/A", "replay/A", "follower/B", "replay/B"} {
		require.Equal(t, fA.beaconRoot, all[name].beaconRoot, "%s: beacon root the follower hands the execution client", name)
	}
	require.Len(t, bA.commitment, 32)

	if !export {
		return
	}
	// The vector the ureth state-equality test consumes: per subset the build input, the commitment the header carries, the
	// beacon root the follower forwards, and the companion witnesses, which are the only subset-dependent bytes.
	vec := x2Vector{Network: 3, Partition: 8, ParentHash: hexOf(w.parent.Hash.Bytes()), RootEpoch: x2RootEpoch, ShardRound: x2ShardRound,
		RootRound: x2AuthRootRound, Transition: hexOf(bA.transition), RootInput: hexOf(bA.rootInput), Commitment: hexOf(bA.commitment),
		BeaconRoot: hexOf(fA.beaconRoot)}
	for _, sub := range []struct {
		name    string
		signers []int
		uc      *types.UnicityCertificate
	}{{"A", []int{0, 1, 2}, ucA}, {"B", []int{1, 2, 3}, ucB}} {
		witnesses, err := encodeSealCompanionWitnesses(sub.uc, w.technical())
		require.NoError(t, err)
		entry := x2VectorSubset{Name: sub.name, Signers: sub.signers}
		for _, wit := range witnesses {
			entry.Witnesses = append(entry.Witnesses, hexOf(wit))
		}
		vec.Subsets = append(vec.Subsets, entry)
	}
	require.NotEqual(t, vec.Subsets[0].Witnesses, vec.Subsets[1].Witnesses, "the subsets' witness bytes differ")
	want, err := json.MarshalIndent(vec, "", "  ")
	require.NoError(t, err)
	want = append(want, '\n')
	checkGolden(t, "h3-assignment-signer-subsets.json", want)

	// The genesis the parent block belongs to, so the consumer starts from the very registry state this world's B0 names.
	var genesis core.Genesis
	genesisJSON := w.chain.Genesis.GenesisJSON()
	require.NoError(t, json.Unmarshal(genesisJSON, &genesis))
	require.Equal(t, w.genesis.Hash, genesis.ToBlock().Hash(), "the exported genesis hashes to the parent block")
	var indented bytes.Buffer
	require.NoError(t, json.Indent(&indented, genesisJSON, "", "  "))
	indented.WriteByte('\n')
	checkGolden(t, "h3-assignment-genesis.json", indented.Bytes())
}

func checkGolden(t *testing.T, name string, want []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("X2_UPDATE_VECTORS") == "1" {
		require.NoError(t, os.WriteFile(path, want, 0o644))
	}
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.True(t, bytes.Equal(want, got), "%s is stale; regenerate with X2_UPDATE_VECTORS=1", name)
}

// x2Vector is the exported cross-repo vector (consumed by ristik/ureth crates/unicity/payload/tests/execution_payload.rs).
// The root input, transition and commitment are the same for every subset by construction; only witnesses differ.
type x2Vector struct {
	Network    uint64           `json:"network_id"`
	Partition  uint64           `json:"partition_id"`
	ParentHash string           `json:"parent_hash"`
	RootEpoch  uint64           `json:"new_root_epoch"`
	ShardRound uint64           `json:"authorized_round"`
	RootRound  uint64           `json:"root_round"`
	Transition string           `json:"transition"`
	RootInput  string           `json:"root_input"`
	Commitment string           `json:"commitment"`
	BeaconRoot string           `json:"parent_beacon_block_root"`
	Subsets    []x2VectorSubset `json:"subsets"`
}

type x2VectorSubset struct {
	Name      string   `json:"name"`
	Signers   []int    `json:"root_signers"`
	Witnesses []string `json:"witnesses"` // [certificate, technical record], canonical CBOR, hex
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

// Every case below changes exactly one thing relative to a control that is accepted on the same construction, and each
// refusal must arrive as its own sentinel and before anything reaches the execution client.
func TestX2RefusalsOnANonemptyAssignmentTransition(t *testing.T) {
	w := newX2World(t, false)
	tr := w.technical()
	uc := w.certify(tr, x2AuthRootRound, x2RootEpoch, 0, 1, 2)
	params := w.params(uc, tr)
	honest := w.path(nil, x2RootEpoch)
	block := w.block(honest, uc, tr)

	type refusal struct {
		name   string
		mutate func(*VerifierContext)
		epoch  uint64 // the verifier's current root epoch; zero means x2RootEpoch
		want   []error
		not    []error
	}
	forge := func(f func(*handoff.EVMTransition)) func(*VerifierContext) {
		return func(v *VerifierContext) {
			v.transitionMu.Lock()
			defer v.transitionMu.Unlock()
			step := v.transitions[1]
			f(&step)
			v.transitions[1] = step
		}
	}
	for _, tc := range []refusal{
		{name: "omitted body: the installed transition is missing",
			mutate: func(v *VerifierContext) { v.transitionMu.Lock(); delete(v.transitions, 1); v.transitionMu.Unlock() },
			want:   []error{ErrAssignmentSpanUnavailable, rootinput.ErrV2Context}},
		{name: "reordered body: the step for the next epoch sits at this epoch",
			mutate: forge(func(s *handoff.EVMTransition) { s.OldRootEpoch, s.NewRootEpoch = 2, 3 }),
			want:   []error{ErrAssignmentSpanUnavailable, rootinput.ErrV2Context}},
		{name: "forged body: the old configuration hash is not the registry's",
			mutate: forge(func(s *handoff.EVMTransition) { s.OldActiveConfHash[0] ^= 1 }),
			want:   []error{rootinput.ErrV2Context}},
		{name: "forged body: the successor configuration hash is not the certificate's",
			mutate: forge(func(s *handoff.EVMTransition) { s.NewActiveConfHash[0] ^= 1 }),
			want:   []error{rootinput.ErrV2Context}},
		{name: "wrong network",
			mutate: func(v *VerifierContext) { v.NetworkID = 4 },
			want:   []error{rootinput.ErrWrongContext}},
		{name: "wrong partition",
			mutate: func(v *VerifierContext) { v.PartitionID = 9 },
			want:   []error{rootinput.ErrUnauthenticated}},
		{name: "wrong shard",
			mutate: func(v *VerifierContext) {
				left, _ := types.ShardID{}.Split()
				v.ShardID = left
			},
			want: []error{rootinput.ErrUnauthenticated}},
		{name: "wrong root epoch: the verifier is past the certificate's epoch",
			epoch: x2RootEpoch + 1,
			want:  []error{rootinput.ErrV2Context}},
		{name: "wrong shard epoch: the installed configuration for the certificate's shard epoch is another",
			mutate: func(v *VerifierContext) {
				other := w.hash[0]
				v.SetConfForEpoch(func(e uint64) ([]byte, bool) {
					if e == 1 {
						return other[:], true
					}
					return bytes.Clone(w.hash[0][:]), e == 0
				})
			},
			want: []error{rootinput.ErrUnauthenticated}, not: []error{rootinput.ErrConfEpochUnknown}},
		{name: "wrong shard epoch: none is installed for the certificate's epoch",
			mutate: func(v *VerifierContext) {
				v.SetConfForEpoch(func(e uint64) ([]byte, bool) { return bytes.Clone(w.hash[0][:]), e == 0 })
			},
			want: []error{rootinput.ErrConfEpochUnknown}, not: []error{rootinput.ErrUnauthenticated}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			epoch := tc.epoch
			if epoch == 0 {
				epoch = x2RootEpoch
			}
			b := w.path(tc.mutate, epoch)
			err := b.build(params)
			require.Error(t, err, "builder")
			f := w.path(tc.mutate, epoch)
			status, verr := f.a.Verify(context.Background(), block, params)
			require.Error(t, verr, "follower")
			require.Equal(t, shardnode.StatusInvalid, status)
			for _, e := range tc.want {
				require.ErrorIs(t, err, e, "builder")
				require.ErrorIs(t, verr, e, "follower")
			}
			for _, e := range tc.not {
				require.NotErrorIs(t, err, e, "builder")
				require.NotErrorIs(t, verr, e, "follower")
			}
			require.Zero(t, b.seen.buildCalls, "a refused build never reaches the execution client")
			require.Zero(t, f.seen.newCalls, "a refused block never reaches the execution client")
		})
	}

	t.Run("control: the unmutated stacks accept the same certificate and block", func(t *testing.T) {
		b := w.path(nil, x2RootEpoch)
		require.NoError(t, b.build(params))
		f := w.path(nil, x2RootEpoch)
		status, err := f.a.Verify(context.Background(), block, params)
		require.NoError(t, err)
		require.Equal(t, shardnode.StatusValid, status)
	})

	t.Run("forged body disseminated by a leader: a follower with the honest installed step refuses the block", func(t *testing.T) {
		// The forged field (the commit identifier) is one the registry binding cannot check, so the leader's own derivation
		// succeeds; only the follower's byte comparison against ITS installed transition refuses it.
		leader := w.path(forge(func(s *handoff.EVMTransition) { s.Ack.CommitID[0] ^= 1 }), x2RootEpoch)
		forged := w.block(leader, uc, tr)
		f := w.path(nil, x2RootEpoch)
		status, err := f.a.Verify(context.Background(), forged, params)
		require.ErrorIs(t, err, ErrCompanionBinding)
		require.Equal(t, shardnode.StatusInvalid, status)
		require.Zero(t, f.seen.newCalls)
	})

	t.Run("stale cursor: the acknowledgement is replayed against a registry that has already imported it", func(t *testing.T) {
		// The registry's transition cursor has moved: the verifier is told the parent shows the successor assignment as
		// active, but the parent's proven storage still holds the old one, so the witness is refused before any derivation.
		// (The converse, a registry that really had advanced, is the ordinary-execution refusal in
		// rootinput/assignment_v2_test.go TestEpochGuardsAreAuthenticatedValuesNotConstants.)
		w.active = registryproof.Assignment{Set: true, ShardEpoch: 1, RootEpoch: x2RootEpoch, ActiveConfHash: common.Hash(w.hash[1])}
		defer func() {
			w.active = registryproof.Assignment{Set: true, ShardEpoch: 0, RootEpoch: 1, ActiveConfHash: common.Hash(w.hash[0])}
		}()
		b := w.path(nil, x2RootEpoch)
		err := b.build(params)
		require.ErrorIs(t, err, ErrParentWitnessInvalid, "builder")
		require.ErrorContains(t, err, "registry assignment 0/1", "builder: the proven registry still shows the old assignment")
		require.Zero(t, b.seen.buildCalls)
		f := w.path(nil, x2RootEpoch)
		status, err := f.a.Verify(context.Background(), block, params)
		require.ErrorIs(t, err, ErrParentWitnessInvalid, "follower")
		require.ErrorContains(t, err, "registry assignment 0/1", "follower")
		require.NotEqual(t, shardnode.StatusValid, status)
		require.Zero(t, f.seen.newCalls)
	})

	t.Run("reordered bodies in a folded span are refused by the fold", func(t *testing.T) {
		first, err := w.path(nil, x2RootEpoch).verifier.transitionFor(1, 2)
		require.NoError(t, err)
		one, err := handoff.DecodeEVMTransition(first)
		require.NoError(t, err)
		two := one
		two.OldRootEpoch, two.NewRootEpoch = 2, 3
		two.OldShardEpoch, two.NewShardEpoch = 1, 2
		two.OldActiveConfHash, two.NewActiveConfHash = one.NewActiveConfHash, [32]byte{9}
		_, err = handoff.FoldTransitions([]handoff.EVMTransition{one, two})
		require.NoError(t, err, "control: the steps fold in order")
		_, err = handoff.FoldTransitions([]handoff.EVMTransition{two, one})
		require.ErrorIs(t, err, handoff.ErrBoundary)
	})
}
