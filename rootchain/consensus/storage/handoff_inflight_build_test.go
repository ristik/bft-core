package storage

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/engineapi"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// engineDouble is the smallest Engine API + eth JSON-RPC double that the real engineapi.Adapter can build against. It is a
// test double, not an execution client: it answers forkchoiceUpdated (with payload attributes it returns a payloadId and
// remembers the parent the build was started on), holds getPayload on a channel barrier for the FIRST payload so a build stays
// open for as long as the test wants, and records every forkchoice the adapter moves (Commit). It never executes a payload;
// payload contents are canned, so nothing here proves the execution client's own semantics.
type engineDouble struct {
	t   *testing.T
	srv *httptest.Server

	genesis, genesisRoot []byte

	getPayloadEntered chan string   // the payloadId of the first getPayload, sent when the call arrives
	releaseFirst      chan struct{} // closed by the test to let the first getPayload return

	mu         sync.Mutex
	builds     []buildStart // forkchoiceUpdated with attributes, in arrival order
	commits    []string     // hex head of every forkchoiceUpdated without attributes
	payloadSeq int
	blockOf    map[string]string // payloadId -> block hash it returns
	served     int
}

type buildStart struct {
	parent    string
	payloadID string
}

func newEngineDouble(t *testing.T, genesis, genesisRoot []byte) *engineDouble {
	e := &engineDouble{t: t, genesis: genesis, genesisRoot: genesisRoot, getPayloadEntered: make(chan string, 4),
		releaseFirst: make(chan struct{}), blockOf: map[string]string{}}
	e.srv = httptest.NewServer(http.HandlerFunc(e.serve))
	t.Cleanup(e.srv.Close)
	return e
}

func hx(b []byte) string { return "0x" + hex.EncodeToString(b) }

func (e *engineDouble) serve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     json.RawMessage   `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var result any
	switch req.Method {
	case "eth_getBlockByHash", "eth_getBlockByNumber":
		// Only the genesis block exists on this chain: an abandoned payload is never imported, so it never has a header.
		result = map[string]any{"number": "0x0", "hash": hx(e.genesis), "parentHash": hx(make([]byte, 32)), "stateRoot": hx(e.genesisRoot), "timestamp": "0x0"}
	case "engine_forkchoiceUpdatedWithSealV1":
		var st struct {
			Head string `json:"headBlockHash"`
		}
		require.NoError(e.t, json.Unmarshal(req.Params[0], &st))
		require.NotEqual(e.t, "null", string(req.Params[1]), "a build carries payload attributes")
		e.mu.Lock()
		e.payloadSeq++
		id := fmt.Sprintf("0x%016x", e.payloadSeq)
		e.builds = append(e.builds, buildStart{parent: st.Head, payloadID: id})
		e.blockOf[id] = hx(bytes.Repeat([]byte{byte(0xc0 + e.payloadSeq)}, 32))
		e.mu.Unlock()
		result = map[string]any{"payloadStatus": map[string]any{"status": "VALID"}, "payloadId": id}
	case "engine_forkchoiceUpdatedV3":
		var st struct {
			Head string `json:"headBlockHash"`
		}
		require.NoError(e.t, json.Unmarshal(req.Params[0], &st))
		e.mu.Lock()
		e.commits = append(e.commits, st.Head)
		e.mu.Unlock()
		result = map[string]any{"payloadStatus": map[string]any{"status": "VALID"}}
	case "engine_getPayloadWithSealV1":
		var id string
		require.NoError(e.t, json.Unmarshal(req.Params[0], &id))
		e.mu.Lock()
		e.served++
		first := e.served == 1
		blockHash := e.blockOf[id]
		parent := ""
		for _, b := range e.builds {
			if b.payloadID == id {
				parent = b.parent
			}
		}
		e.mu.Unlock()
		if first {
			e.getPayloadEntered <- id
			select {
			case <-e.releaseFirst:
			case <-r.Context().Done():
				return
			}
		}
		result = map[string]any{
			"executionPayload": map[string]any{
				"parentHash": parent, "feeRecipient": hx(make([]byte, 20)), "stateRoot": hx(bytes.Repeat([]byte{0x33}, 32)),
				"receiptsRoot": hx(bytes.Repeat([]byte{0x44}, 32)), "logsBloom": "0x00", "prevRandao": hx(bytes.Repeat([]byte{0x55}, 32)),
				"blockNumber": "0x1", "gasLimit": "0x1c9c380", "gasUsed": "0x0", "timestamp": "0x1", "extraData": "0x00",
				"baseFeePerGas": "0x1", "blockHash": blockHash, "transactions": []string{}, "withdrawals": []any{},
				"blobGasUsed": "0x0", "excessBlobGas": "0x0",
			},
			"blockValue":    "0x0",
			"sealCompanion": map[string]any{"rootInput": "0x01", "witnesses": []string{}, "provenance": "build"},
		}
	default:
		e.t.Errorf("engineDouble: unexpected method %s", req.Method)
		http.Error(w, "unexpected", http.StatusBadRequest)
		return
	}
	raw, err := json.Marshal(result)
	require.NoError(e.t, err)
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, req.ID, raw)
}

func (e *engineDouble) buildStarts() []buildStart {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]buildStart(nil), e.builds...)
}

func (e *engineDouble) commitHeads() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.commits...)
}

// engineExecutor is the real engineapi.Adapter for Build, Seal, Head and Commit. Only Verify is replaced: the leader's
// self-verification would re-derive the root input and re-execute the payload, which this double cannot do (it never
// executes). That is a stated limit of this fixture, not a claim about Verify.
type engineExecutor struct{ *engineapi.Adapter }

func (engineExecutor) Verify(context.Context, shardnode.Block, shardnode.RoundParams) (shardnode.Status, error) {
	return shardnode.StatusValid, nil
}

type fixedTrustBases struct{ tb *types.RootTrustBaseV1 }

func (s fixedTrustBases) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return s.tb, nil
}

// bootstrapEngine builds the verifier context of a shard whose first block is under construction on the EVM genesis block,
// and the root certificates (genuinely signed by a root quorum) that authorize its first round in shard epochs 0 and 1.
func bootstrapEngine(t *testing.T, leader string) (v *engineapi.VerifierContext, genesisHash, genesisRoot []byte, certFor func(epoch uint64, rootRound uint64) (*types.UnicityCertificate, *certification.TechnicalRecord)) {
	t.Helper()
	c := certifiedchain.New(t, 3, 0)
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
	art, err := registrygenesis.PinnedArtifact()
	require.NoError(t, err)
	prepared, err := registrygenesis.PrepareGenesisJSON(certifiedchain.Config(3), c.Pins, art, source, registrygenesis.GenesisJSONLimits{})
	require.NoError(t, err)
	origin := prepared.Origin()
	snapshot, err := registryproof.Verify(origin.ProofContext(), origin.BlockHash(), origin.Evidence())
	require.NoError(t, err)
	verifier, err := c.Signer.Verifier()
	require.NoError(t, err)
	pk, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(t, err)
	certFor = func(epoch, rootRound uint64) (*types.UnicityCertificate, *certification.TechnicalRecord) {
		tr := certifiedchain.Technical(0)
		tr.Round, tr.Epoch, tr.Leader = 1, epoch, leader
		uc := c.Certify(c.Signer, &types.InputRecord{Version: 1}, tr, rootRound)
		uc.UnicitySeal.NetworkID = 3
		uc.UnicitySeal.Signatures = nil
		require.NoError(t, uc.UnicitySeal.Sign(id.String(), c.Signer))
		return uc, tr
	}
	v = &engineapi.VerifierContext{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, ShardConfHash: origin.FullShardConfHash().Bytes(), RootEpoch: 1,
		TrustBases: fixedTrustBases{tb: c.TrustBase}, Cursor: engineapi.CursorNotActivated(), GenesisOrigin: origin, BootstrapSnapshot: snapshot}
	return v, origin.BlockHash().Bytes(), origin.StateRoot().Bytes(), certFor
}

// order records the order in which the test's phases completed, so the overlap is asserted from events and not from timing.
type order struct {
	mu     sync.Mutex
	events []string
}

func (o *order) add(ev string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, ev)
}

func (o *order) list() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.events...)
}

type submissions struct {
	mu  sync.Mutex
	got []*certification.BlockCertificationRequest
}

func (s *submissions) Submit(_ context.Context, req *certification.BlockCertificationRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, req)
	return nil
}

func (s *submissions) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.got)
}

func (s *submissions) last() *certification.BlockCertificationRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.got[len(s.got)-1]
}

// W3b (#20) and AC1, stated precisely. The system does NOT cancel a builder on a handoff, and this change adds no
// cancellation: a proposal built across the freeze is ABANDONED. The root refuses to certify it (ErrHandoffFrozen) and the
// successor builds on the agreed certified parent. That is the project's simple-design choice, owner-overridable; see the
// comment at shardnode/round.go near Build/Seal.
//
// What runs, with the real code on each side:
//   - The shard side is a real shardnode.Round driving the real engineapi.Adapter against engineDouble. The leader's Build sends
//     forkchoiceUpdated with payload attributes and receives a non-nil payloadId; Seal's getPayload is then held on a channel.
//   - While getPayload is pending the root orders Prepare and Freeze, the Commit record, and the successor assignment is
//     installed and activated through the real activation path. The test asserts, from the recorded event order, that freeze,
//     install and activation ALL completed before the build was released.
//   - Then the build is released, the Round signs what it built, and the root refuses it. The successor's first block is built
//     by a second forkchoiceUpdated on the agreed certified parent P, and the abandoned payload is never moved to head.
//
// Limits: the engine double never executes a payload (canned payload fields) and the leader's self-Verify is stubbed, so no
// claim is made about the execution client or Adapter.Verify; the root's request verifier in addBlockWithRequests is the
// accepting mock used by the neighbouring tests, so successor certification is not a fully authenticated root proof.
func TestMembershipChangeDuringPayloadConstructionCannotCertifyTheProposalAndTheSuccessorResumesFromTheAgreedParent(t *testing.T) {
	ctx := context.Background()
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	a := f.addAggregator(t)
	f.changes = nil
	evm := f.oldKeys[0] // ev-a leads, and is kept by the successor set (nextKeys[0])

	verifier, genesisHash, genesisRoot, certFor := bootstrapEngine(t, evm.id)
	engine := newEngineDouble(t, genesisHash, genesisRoot)
	secret, err := engineapi.ParseSecret(strings.Repeat("ab", 32))
	require.NoError(t, err)
	adapter := engineapi.NewAdapter(engineapi.Config{EngineURL: engine.srv.URL, EthURL: engine.srv.URL, Secret: secret, Verifier: verifier}, nil)
	subs := &submissions{}
	round := shardnode.NewRound(evm.id, f.shard.PartitionID, types.ShardID{}, engineExecutor{adapter}, shardnode.NewLoopbackDisseminator(), evm.signer, subs, nil)

	// P is the agreed certified parent of the shard: the EVM genesis block (nothing of the shard is certified yet).
	f.parent = bytes.Clone(genesisHash)
	f.seedFees(t)
	parentHex := hx(genesisHash)

	// The leader's first build starts and stays open: HandleCertificate is inside Seal, whose getPayload is held.
	events := &order{}
	uc, tr := certFor(0, 4)
	done := make(chan error, 1)
	go func() { done <- round.HandleCertificate(ctx, uc, tr) }()
	var payloadID string
	select {
	case payloadID = <-engine.getPayloadEntered:
	case err := <-done:
		t.Fatalf("the round ended before a payload was requested: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("no getPayload arrived")
	}
	starts := engine.buildStarts()
	require.Len(t, starts, 1)
	require.NotEmpty(t, starts[0].payloadID, "forkchoiceUpdated with payload attributes returned a payloadId")
	require.Equal(t, starts[0].payloadID, payloadID, "getPayload is pending on exactly that payloadId")
	require.Equal(t, parentHex, starts[0].parent, "the build is on the agreed certified parent P")
	events.add("build-open")
	require.Equal(t, 0, subs.count(), "while the build is open nothing was signed")
	t.Cleanup(func() { // a failed assertion must not leak the held getPayload or the round goroutine
		select {
		case <-engine.releaseFirst:
		default:
			close(engine.releaseFirst)
		}
	})

	f.afterFreeze = func(t *testing.T) {
		events.add("freeze-complete")
		require.Equal(t, 0, subs.count(), "the freeze did not sign or release anything")
		// Separately, in the frozen window: the root refuses an old-set request for the EVM shard, and keeps certifying others.
		freezeBlock := mustBlock(t, f.store, 3)
		verify := mockIRVerifier{verify: func(_ uint64, req *rctypes.IRChangeReq) (*types.InputRecord, error) {
			return req.Requests[0].InputRecord, nil
		}}
		extend := func(reqs ...*rctypes.IRChangeReq) (*ExecutedBlock, error) {
			return freezeBlock.Extend(&rctypes.BlockData{Version: 2, Epoch: 1, Round: 4, Payload: &rctypes.Payload{Version: 2, Requests: reqs}},
				verify, f.orch, crypto.SHA256, logger.New(t))
		}
		_, err := extend(signedRequest(t, f.shard, evm))
		require.ErrorIs(t, err, ErrHandoffFrozen, "an old-epoch request for the frozen shard is refused by the root")
		ext, err := extend(signedRequest(t, a.key, a.oldKey))
		require.NoError(t, err)
		require.Contains(t, ext.ShardState.Changed, a.key, "other partitions are unaffected")
		require.NotContains(t, ext.ShardState.Changed, f.shard)
	}
	h := f.commitAssignment(t)

	anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	events.add("assignment-installed")
	s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	activation := addBlockWithRequests(t, s, 7, anchor)
	si := activation.ShardState.States[f.shard]
	require.EqualValues(t, 1, si.TR.Epoch, "the successor set is active")
	events.add("assignment-activated")
	require.Equal(t, 0, subs.count(), "the build is still open after activation")
	select {
	case err := <-done:
		t.Fatalf("the build ended before it was released: %v", err)
	default:
	}
	require.Equal(t, []string{"build-open", "freeze-complete", "assignment-installed", "assignment-activated"}, events.list(),
		"freeze, installation and activation all completed while the build was open")

	// Only now is the build released, by closing the barrier.
	events.add("build-released")
	close(engine.releaseFirst)
	require.NoError(t, <-done)
	require.Equal(t, 1, subs.count(), "the leader signed what it had built: the shard side does not know the freeze")
	abandoned := subs.last()
	require.NotEmpty(t, abandoned.InputRecord.BlockHash)
	require.Equal(t, engine.blockOf[payloadID], hx(abandoned.InputRecord.BlockHash), "the signed request names the held payload's block")

	// What stops the abandoned request once released. Inside the frozen window the root refuses ANY request for the shard
	// (ErrHandoffFrozen, asserted above); this request only exists after the activation, when the freeze has ended. From then on
	// it is one signature (the leader's, a member of the new set too) against the active set's quorum: the new set's other
	// members build and sign their own successor block, never this one, so it cannot be certified, and requestSignersAreActive
	// drops the old set's followers. The accept-all request verifier of the neighbouring tests would hide this, so the test
	// asserts the quorum arithmetic on the real activated ShardInfo and that the shard's certified parent did not move.
	require.Equal(t, evm.id, abandoned.NodeID, "the request carries the leader's signature alone")
	require.Less(t, uint64(1), si.GetQuorum(), "one signature is not the active set's quorum")
	require.Equal(t, genesisHash, []byte(si.IR.BlockHash), "the shard's certified parent is still P")

	// The successor (ev-a, kept by the new set) starts the first round of the new epoch: a second build on P, while the
	// abandoned payload was never made head.
	// The engine side's registry fixture only knows the epoch-0 assignment, so the successor's build is authorized by an
	// authenticated epoch-0 certificate: what is asserted here is the build's PARENT, not the new epoch's registry binding
	// (the storage side above asserts the epoch-1 activation).
	ucNew, trNew := certFor(0, 9)
	require.NoError(t, round.HandleCertificate(ctx, ucNew, trNew))
	starts = engine.buildStarts()
	require.Len(t, starts, 2, "the successor built again")
	require.Equal(t, parentHex, starts[1].parent, "the successor's build extends the agreed certified parent P")
	require.NotEqual(t, starts[0].payloadID, starts[1].payloadID)
	for _, head := range engine.commitHeads() {
		require.NotEqual(t, engine.blockOf[payloadID], head, "the abandoned payload never became head")
	}
	require.Equal(t, 2, subs.count())
	require.NotEqual(t, abandoned.InputRecord.BlockHash, subs.last().InputRecord.BlockHash)
}
