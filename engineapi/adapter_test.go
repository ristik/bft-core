package engineapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/shardnode"
)

// mockReth is a scripted stand-in for reth's two RPC surfaces (engine_* on
// one httptest.Server, eth_* on another — real reth serves them on
// different ports too). It is not a reth simulator: it returns exactly what
// each test tells it to, and its only job is proving that Client/EthClient/
// Adapter build the right requests, send the right auth header, and decode
// the right response shape. It cannot prove reth's own Engine API semantics
// match what this package assumes — that needs a live reth, unavailable in
// this environment; see docs/engine-api-adapter-plan.md's B1.1/B2/B3 gates.
type mockReth struct {
	t      *testing.T
	secret Secret

	// keyed by JSON-RPC method name
	handlers map[string]func(params json.RawMessage) (any, *rpcError)

	sawAuthHeader bool
}

func newMockReth(t *testing.T, secret Secret) *mockReth {
	return &mockReth{t: t, secret: secret, handlers: make(map[string]func(json.RawMessage) (any, *rpcError))}
}

func (m *mockReth) on(method string, h func(params json.RawMessage) (any, *rpcError)) {
	m.handlers[method] = h
}

func (m *mockReth) server(requireAuth bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requireAuth {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				m.t.Errorf("mockReth: missing bearer token on %s", r.URL.Path)
			} else {
				m.sawAuthHeader = true
			}
		}

		var req rpcRequest
		require.NoError(m.t, json.NewDecoder(r.Body).Decode(&req))

		h, ok := m.handlers[req.Method]
		if !ok {
			m.t.Fatalf("mockReth: no handler registered for %s", req.Method)
		}
		paramsJSON, err := json.Marshal(req.Params)
		require.NoError(m.t, err)

		result, rpcErr := h(paramsJSON)
		resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
		if rpcErr != nil {
			resp.Error = rpcErr
		} else {
			b, err := json.Marshal(result)
			require.NoError(m.t, err)
			resp.Result = b
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(m.t, json.NewEncoder(w).Encode(resp))
	}))
}

func fixedHash(b byte) data32 {
	var d data32
	for i := range d {
		d[i] = b
	}
	return d
}

// fixedHashBytes is fixedHash's slice form, for building shardnode.Hash
// values directly — an array literal's result isn't addressable, so
// fixedHash(b)[:] doesn't compile at a call site; this sidesteps that.
func fixedHashBytes(b byte) []byte {
	d := fixedHash(b)
	return d[:]
}

// newTestAdapter wires an Adapter against two mockReth-backed servers (one
// standing in for the authenticated :8551 engine surface, one for the
// plain :8545 eth surface — matching how a real deployment separates them).
func newTestAdapter(t *testing.T, engine, eth *mockReth) (*Adapter, func()) {
	return newTestAdapterWithVerifier(t, engine, eth, nil)
}

// newTestAdapterWithVerifier is newTestAdapter with an explicit derivation context, for the tests
// that drive Adapter.Build through the seal sibling.
func newTestAdapterWithVerifier(t *testing.T, engine, eth *mockReth, verifier *VerifierContext) (*Adapter, func()) {
	secret, err := ParseSecret(strings.Repeat("ab", 32))
	require.NoError(t, err)
	engine.secret = secret

	engineSrv := engine.server(true)
	ethSrv := eth.server(false)

	a := NewAdapter(Config{EngineURL: engineSrv.URL, EthURL: ethSrv.URL, Secret: secret, Verifier: verifier}, nil)
	return a, func() { engineSrv.Close(); ethSrv.Close() }
}

func TestAdapter_CheckCapabilities_Passes(t *testing.T) {
	engine := newMockReth(t, Secret{})
	engine.on("engine_exchangeCapabilities", func(json.RawMessage) (any, *rpcError) {
		return requiredCapabilities, nil
	})
	eth := newMockReth(t, Secret{})
	a, closeFn := newTestAdapter(t, engine, eth)
	defer closeFn()

	require.NoError(t, a.CheckCapabilities(context.Background()))
	require.True(t, engine.sawAuthHeader, "engine_* calls must carry the bearer token")
}

func TestAdapter_CheckCapabilities_FailsClosed_WhenMethodMissing(t *testing.T) {
	engine := newMockReth(t, Secret{})
	engine.on("engine_exchangeCapabilities", func(json.RawMessage) (any, *rpcError) {
		return []string{"engine_forkchoiceUpdatedV3"}, nil // missing getPayloadV3, newPayloadV3
	})
	eth := newMockReth(t, Secret{})
	a, closeFn := newTestAdapter(t, engine, eth)
	defer closeFn()

	err := a.CheckCapabilities(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "engine_getPayloadV3")
}

func TestAdapter_Head_ReadsFromEthNamespace(t *testing.T) {
	eth := newMockReth(t, Secret{})
	eth.on("eth_getBlockByNumber", func(p json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: 7, Hash: fixedHash(0x07), StateRoot: fixedHash(0x77)}, nil
	})
	a, closeFn := newTestAdapter(t, newMockReth(t, Secret{}), eth)
	defer closeFn()

	head, err := a.Head(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, 7, head.Number)
	h := fixedHash(0x07)
	require.Equal(t, shardnode.Hash(h[:]), head.Hash)
}

func TestAdapter_BuildSealCommit_NonQuietRound(t *testing.T) {
	t.Skip("U5d: v1 adapter fixture awaits migration to the RPC parent witness; v2 bootstrap is covered by adapter_v2_test.go")
	f := newDerivationFixture(t)
	uc, tr := f.cert(t, 4, 5, 50)

	parentHash := fixedHash(0x01)
	blockHash := fixedHash(0x02)
	stateRoot := fixedHash(0x03)
	var payloadID data = []byte{1, 2, 3, 4, 5, 6, 7, 8}
	const parentTimestamp = 999

	zeroHash := fixedHash(0x00)
	sealHash := fixedHash(0x99)
	parent := shardnode.BlockRef{Number: 4, Hash: shardnode.Hash(parentHash[:]), StateRoot: shardnode.Hash(zeroHash[:])}
	params := shardnode.RoundParams{
		Round: 5, Timestamp: 1000, SealHash: shardnode.Hash(sealHash[:]), Leader: tr.Leader, Parent: parent,
		AuthorizingCertificate: uc, AuthorizingTechnicalRecord: tr,
	}

	// The self-verify path authenticates the companion against the adapter's own verifier context,
	// so build the real canonical root input and commitment for this round and have the mock return
	// them as the block-bound companion. Seal fills the witnesses.
	derived := f.derive(t, params.Round, params.Parent.Hash, uc, tr)

	// The sealed payload must carry the same attributes Build would have requested (Verify's
	// self-check — called on the leader's own output too — recomputes and compares them), so derive
	// them the same way Adapter itself does, from the authenticated input.
	attrs := DeriveAttributes(derived.Input, ParentHeader{Timestamp: parentTimestamp})

	engine := newMockReth(t, Secret{})
	engine.on("engine_forkchoiceUpdatedWithSealV1", func(p json.RawMessage) (any, *rpcError) {
		return ForkchoiceUpdatedResponse{
			PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid},
			PayloadID:     &payloadID,
		}, nil
	})
	engine.on("engine_getPayloadWithSealV1", func(p json.RawMessage) (any, *rpcError) {
		return GetPayloadWithSealV1Response{
			ExecutionPayload: ExecutionPayloadV3{
				ParentHash:   parentHash,
				BlockHash:    blockHash,
				StateRoot:    stateRoot,
				BlockNumber:  5,
				Timestamp:    attrs.Timestamp,
				PrevRandao:   attrs.PrevRandao,
				FeeRecipient: attrs.SuggestedFeeRecipient,
				Transactions: []data{{0xde, 0xad}}, // one tx — non-quiet
				Withdrawals:  []WithdrawalV1{},
				LogsBloom:    data{},
				ExtraData:    derived.Commitment[:],
			},
			SealCompanion: SealCompanion{RootInput: derived.Encoded, Witnesses: []data{}, Provenance: "build"},
		}, nil
	})
	engine.on("engine_forkchoiceUpdatedV3", func(p json.RawMessage) (any, *rpcError) {
		return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}}, nil
	})
	engine.on("engine_newPayloadWithSealV1", func(p json.RawMessage) (any, *rpcError) {
		return PayloadStatusV1{Status: PayloadStatusValid}, nil
	})

	eth := newMockReth(t, Secret{})
	eth.on("eth_getBlockByHash", func(p json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: 4, Hash: parentHash, Timestamp: parentTimestamp}, nil
	})

	a, closeFn := newTestAdapterWithVerifier(t, engine, eth, f.verifier(CursorNotActivated()))
	defer closeFn()
	ctx := context.Background()

	id, err := a.Build(ctx, params)
	require.NoError(t, err)
	require.NotEmpty(t, id)

	block, err := a.Seal(ctx, id)
	require.NoError(t, err)
	require.Equal(t, shardnode.Hash(blockHash[:]), block.Hash)
	require.Equal(t, shardnode.Hash(stateRoot[:]), block.StateRoot)
	require.NotEmpty(t, block.Raw, "non-quiet block must carry a proposal envelope for dissemination")
	require.NotZero(t, block.BlockSize)

	// self-verify, as round.go does for the leader's own block
	status, err := a.Verify(ctx, block, params)
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusValid, status)

	status, err = a.Commit(ctx, block.Hash)
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusValid, status)
}

func TestAdapter_Seal_QuietRound_EchoesParentWithNilHash(t *testing.T) {
	t.Skip("U5d: v1 adapter fixture awaits migration to the RPC parent witness; v2 bootstrap is covered by adapter_v2_test.go")
	f := newDerivationFixture(t)
	uc, tr := f.cert(t, 4, 5, 50)

	parentHash := fixedHash(0x11)
	var payloadID data = []byte{9, 9, 9, 9, 9, 9, 9, 9}

	engine := newMockReth(t, Secret{})
	engine.on("engine_forkchoiceUpdatedWithSealV1", func(p json.RawMessage) (any, *rpcError) {
		return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}, PayloadID: &payloadID}, nil
	})
	engine.on("engine_getPayloadWithSealV1", func(p json.RawMessage) (any, *rpcError) {
		return GetPayloadWithSealV1Response{
			ExecutionPayload: ExecutionPayloadV3{
				ParentHash:   parentHash,
				Transactions: []data{}, // zero transactions — quiet
			},
			SealCompanion: SealCompanion{RootInput: data{0x01}, Witnesses: []data{}, Provenance: "build"},
		}, nil
	})

	eth := newMockReth(t, Secret{})
	eth.on("eth_getBlockByHash", func(p json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Timestamp: 500}, nil
	})

	a, closeFn := newTestAdapterWithVerifier(t, engine, eth, f.verifier(CursorNotActivated()))
	defer closeFn()
	ctx := context.Background()

	parentRef := shardnode.BlockRef{Number: 3, Hash: shardnode.Hash(parentHash[:]), StateRoot: shardnode.Hash(fixedHashBytes(0x33))}
	params := shardnode.RoundParams{
		Round: 5, Timestamp: 600, SealHash: shardnode.Hash(fixedHashBytes(0x99)), Leader: tr.Leader, Parent: parentRef,
		AuthorizingCertificate: uc, AuthorizingTechnicalRecord: tr,
	}

	id, err := a.Build(ctx, params)
	require.NoError(t, err)
	block, err := a.Seal(ctx, id)
	require.NoError(t, err)

	require.Equal(t, parentRef.Number, block.Number)
	require.Empty(t, block.Hash, "echoed Hash must be nil, not the parent's real hash — a real hash here would let a live execution client's genesis hash get reused as a later round's BlockHash; see Seal's comment and docs/troubleshooting.md")
	require.Equal(t, parentRef.StateRoot, block.StateRoot)
	require.Empty(t, block.Raw, "quiet block must carry no proposal envelope")

	// Verify must accept the echoed quiet block with no RPC call at all —
	// engine has no engine_newPayloadV3 handler registered, so if Verify
	// tried to call it, this test would fail with "no handler registered".
	status, err := a.Verify(ctx, block, params)
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusValid, status)
}

// TestAdapter_GenesisQuietRound_DoesNotAliasParentBlockHash reproduces the
// scenario a live single-validator run against real reth (v2.5.0) surfaced:
// round 1 is genesis (framework-forced non-quiet — see
// docs/shard-protocol.md §5 — regardless of what the executor itself
// changed), built with zero transactions. Before Seal started nulling Hash
// on its echo, round.go's blockHashOrFallback would see a non-empty
// block.Hash (the parent's own real hash) and use it directly as round 1's
// BlockHash — silently certifying a "new" block whose hash was actually
// genesis's own, already-existing hash. With Hash nil, blockHashOrFallback
// falls back to StateRoot instead, matching executortest.Fake's behavior
// (whose genesis head.Hash is nil for exactly this reason).
func TestAdapter_GenesisQuietRound_DoesNotAliasParentBlockHash(t *testing.T) {
	t.Skip("U5d: v1 adapter fixture awaits migration to the RPC parent witness; v2 bootstrap is covered by adapter_v2_test.go")
	f := newDerivationFixture(t)
	uc, tr := f.cert(t, 4, 5, 50)

	genesisHash := fixedHash(0x11)
	genesisRoot := shardnode.Hash(fixedHashBytes(0x22))
	var payloadID data = []byte{1, 2, 3, 4, 5, 6, 7, 8}

	engine := newMockReth(t, Secret{})
	engine.on("engine_forkchoiceUpdatedWithSealV1", func(p json.RawMessage) (any, *rpcError) {
		return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}, PayloadID: &payloadID}, nil
	})
	engine.on("engine_getPayloadWithSealV1", func(p json.RawMessage) (any, *rpcError) {
		return GetPayloadWithSealV1Response{
			ExecutionPayload: ExecutionPayloadV3{
				ParentHash:   genesisHash,
				Transactions: []data{}, // zero transactions, matching a fresh chain with no mempool activity
			},
			SealCompanion: SealCompanion{RootInput: data{0x01}, Witnesses: []data{}, Provenance: "build"},
		}, nil
	})

	eth := newMockReth(t, Secret{})
	eth.on("eth_getBlockByHash", func(p json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Timestamp: 0}, nil
	})

	a, closeFn := newTestAdapterWithVerifier(t, engine, eth, f.verifier(CursorNotActivated()))
	defer closeFn()
	ctx := context.Background()

	// genesis: Number 0, a real non-nil Hash (unlike Fake's own genesis,
	// which is nil by construction — a real execution client's genesis
	// always has one).
	genesisRef := shardnode.BlockRef{Number: 0, Hash: shardnode.Hash(genesisHash[:]), StateRoot: genesisRoot}
	params := shardnode.RoundParams{
		Round: 5, Timestamp: 1, SealHash: shardnode.Hash(fixedHashBytes(0x99)), Leader: tr.Leader, Parent: genesisRef,
		AuthorizingCertificate: uc, AuthorizingTechnicalRecord: tr,
	}

	id, err := a.Build(ctx, params)
	require.NoError(t, err)
	block, err := a.Seal(ctx, id)
	require.NoError(t, err)

	blockHash := shardnode.Hash(shardnode.BlockHashOrFallback(block, false)) // false: the framework forces genesis non-quiet regardless of executor state
	require.NotEqual(t, genesisRef.Hash, blockHash, "round 1's BlockHash must not alias genesis's own already-existing hash")
	require.Equal(t, genesisRoot, blockHash, "must fall back to StateRoot, exactly as executortest.Fake's own genesis round does")
}

// The payload-field comparison moved after authentication in W4, because the v1 expected values are
// a function of the bound certificate's root round and reference time. This pins that moving it did
// not drop it: a block with a valid, authenticated companion but a forged timestamp is still refused,
// and reth still never sees it.
func TestAdapter_Verify_RejectsTamperedAttributes_WithoutCallingNewPayload(t *testing.T) {
	t.Skip("U5d: v1 adapter fixture awaits migration to the RPC parent witness; v2 bootstrap is covered by adapter_v2_test.go")
	h := newCompanionHarness(t, CursorNotActivated())
	defer h.close()

	uc, tr := h.f.cert(t, 4, 5, 50)
	parent := shardnode.BlockRef{Number: 4, Hash: shardnode.Hash(fixedHashBytes(0x21))}
	params := paramsFor(parent, uc, tr)
	envelope, derived := companionEnvelope(t, h.f, params, uc, tr)

	// The companion and the commitment are genuine; only the payload's timestamp is a leader claiming
	// a bogus clock. It diverges from the v1 timestamp read out of the authenticated input.
	envelope.ExecutionPayload.Timestamp = quantity(999999)
	require.NotEqual(t, uint64(envelope.ExecutionPayload.Timestamp),
		uint64(DeriveAttributes(derived.Input, ParentHeader{Timestamp: 100}).Timestamp))

	status, err := h.adapter.Verify(context.Background(), blockFromEnvelope(t, envelope), params)
	require.NoError(t, err, "a field divergence stays StatusInvalid with a local warning, not an error return")
	require.Equal(t, shardnode.StatusInvalid, status)
	require.Zero(t, h.sealCalls, "a tampered payload must be refused before reth sees it")
}

func TestAdapter_Verify_MapsNewPayloadStatuses(t *testing.T) {
	t.Skip("U5d: v1 adapter fixture awaits migration to the RPC parent witness; v2 bootstrap is covered by adapter_v2_test.go")
	cases := []struct {
		payloadStatus PayloadStatus
		want          shardnode.Status
	}{
		{PayloadStatusValid, shardnode.StatusValid},
		{PayloadStatusSyncing, shardnode.StatusSyncing},
		{PayloadStatusAccepted, shardnode.StatusAccepted},
		{PayloadStatusInvalid, shardnode.StatusInvalid},
		{PayloadStatusInvalidBlockHash, shardnode.StatusInvalid},
	}

	for _, c := range cases {
		t.Run(string(c.payloadStatus), func(t *testing.T) {
			f := newDerivationFixture(t)
			uc, tr := f.cert(t, 4, 5, 50)
			parentHash := fixedHash(0x31)
			parent := shardnode.BlockRef{Number: 1, Hash: shardnode.Hash(parentHash[:])}
			params := shardnode.RoundParams{
				Round: 5, Timestamp: 200, SealHash: shardnode.Hash(fixedHashBytes(0x99)), Parent: parent,
				AuthorizingCertificate: uc, AuthorizingTechnicalRecord: tr,
			}
			derived := f.derive(t, params.Round, params.Parent.Hash, uc, tr)
			attrs := DeriveAttributes(derived.Input, ParentHeader{Timestamp: 100})

			engine := newMockReth(t, Secret{})
			engine.on("engine_newPayloadWithSealV1", func(p json.RawMessage) (any, *rpcError) {
				return PayloadStatusV1{Status: c.payloadStatus}, nil
			})
			eth := newMockReth(t, Secret{})
			eth.on("eth_getBlockByHash", func(p json.RawMessage) (any, *rpcError) {
				return blockHeaderJSON{Timestamp: 100}, nil
			})

			a, closeFn := newTestAdapterWithVerifier(t, engine, eth, f.verifier(CursorNotActivated()))
			defer closeFn()

			envelope := ProposalEnvelope{
				ExecutionPayload: ExecutionPayloadV3{
					ParentHash:   parentHash,
					Timestamp:    attrs.Timestamp,
					PrevRandao:   attrs.PrevRandao,
					FeeRecipient: attrs.SuggestedFeeRecipient,
					ExtraData:    derived.Commitment[:],
					Withdrawals:  []WithdrawalV1{},
					Transactions: []data{{0xaa}},
				},
				ExpectedBlobVersionedHashes: []data32{},
				SealCompanion:               companionPtr(f.sealCompanion(t, derived)),
			}
			raw, err := json.Marshal(envelope)
			require.NoError(t, err)

			block := shardnode.Block{ParentHash: shardnode.Hash(parentHash[:]), Raw: raw}
			status, err := a.Verify(context.Background(), block, params)
			require.NoError(t, err)
			require.Equal(t, c.want, status)
		})
	}
}

// companionPtr is &companion without the address-of-a-value noise at each call site.
func companionPtr(c SealCompanion) *SealCompanion { return &c }

// The D2 seal siblings are required only when a deployment selects the seal path. These four cases
// fix that boundary, because the interesting failure is the one where the requirement becomes
// unconditional by accident: that would fail startup against every stock client, for a path this
// adapter does not yet drive.

func TestAdapter_SealCapabilities_AreNotRequiredByDefault(t *testing.T) {
	engine := newMockReth(t, Secret{})
	engine.on("engine_exchangeCapabilities", func(json.RawMessage) (any, *rpcError) {
		return requiredCapabilities, nil // a stock client, no seal siblings
	})
	eth := newMockReth(t, Secret{})
	a, closeFn := newTestAdapter(t, engine, eth)
	defer closeFn()

	require.NoError(t, a.CheckCapabilities(context.Background()),
		"a stock client must still start: the seal path is not activated by this change")
}

func TestAdapter_SealCapabilities_FailClosed_WhenSelectedAndAbsent(t *testing.T) {
	engine := newMockReth(t, Secret{})
	engine.on("engine_exchangeCapabilities", func(json.RawMessage) (any, *rpcError) {
		return requiredCapabilities, nil
	})
	eth := newMockReth(t, Secret{})
	a, closeFn := newTestAdapter(t, engine, eth)
	defer closeFn()
	a.RequireSealCapabilities()

	err := a.CheckCapabilities(context.Background())
	require.Error(t, err)
	for _, m := range sealCapabilities {
		require.Contains(t, err.Error(), m, "every absent seal sibling is named")
	}
}

func TestAdapter_SealCapabilities_PassWhenSelectedAndOffered(t *testing.T) {
	engine := newMockReth(t, Secret{})
	engine.on("engine_exchangeCapabilities", func(json.RawMessage) (any, *rpcError) {
		return append(append([]string{}, requiredCapabilities...), sealCapabilities...), nil
	})
	eth := newMockReth(t, Secret{})
	a, closeFn := newTestAdapter(t, engine, eth)
	defer closeFn()
	a.RequireSealCapabilities()

	require.NoError(t, a.CheckCapabilities(context.Background()))
}

func TestAdapter_SealCapabilities_APartialSetIsMissing(t *testing.T) {
	// A client offering some of the three advertises a flow it cannot complete. ureth makes the
	// set atomic, so this is a client that should not exist; the check refuses it anyway rather
	// than trusting the other side to be well formed.
	partial := append(append([]string{}, requiredCapabilities...), sealCapabilities[0])
	engine := newMockReth(t, Secret{})
	engine.on("engine_exchangeCapabilities", func(json.RawMessage) (any, *rpcError) {
		return partial, nil
	})
	eth := newMockReth(t, Secret{})
	a, closeFn := newTestAdapter(t, engine, eth)
	defer closeFn()
	a.RequireSealCapabilities()

	err := a.CheckCapabilities(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), sealCapabilities[1])
	require.NotContains(t, err.Error(), sealCapabilities[0], "the offered one is not reported missing")
}
