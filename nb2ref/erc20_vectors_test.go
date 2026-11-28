package nb2ref

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

type erc20Vector struct {
	Asset, Type, Coin, Genesis, Vault, Recovery, Gamma, Domain string
	Held, Evidence, Verdict, Packet, Complete, ReturnProof     string
}

var erc20SemanticProfileHash = [32]byte(mustHex("f05dd5c3563165d73c1cf91a5af79ec7afcaa77edc90061c6e7666bf53a8b0b6"))

func TestERC20FlatReturnVectors(t *testing.T) {
	h := func(b []byte) string { return "0x" + hex.EncodeToString(b) }
	h32 := func(b [32]byte) string { return h(b[:]) }
	world, err := NewWorld(64, 16, 2)
	require.NoError(t, err)
	factory := Recipient20("erc20-factory")
	vaultInit := HE([]byte("erc20-vault-template"))
	recoveryInit := HE([]byte("erc20-recovery-template"))
	generation := HU([]byte("erc20-generation"))
	pins := HU([]byte("erc20-pins"))
	runtime := HE([]byte("erc20-recovery-runtime"))
	predict := func(salt, init [32]byte) [20]byte {
		sum := HE([]byte{0xff}, factory[:], salt[:], init[:])
		return [20]byte(sum[12:])
	}

	var vectors []erc20Vector
	var verifierA *FlatVerifier
	var evidenceA []byte
	for _, variant := range []struct {
		token   [20]byte
		genesis [32]byte
	}{
		{Recipient20("erc20-a"), world.Cfg.ExecutionGenesis},
		{Recipient20("erc20-b"), world.Cfg.ExecutionGenesis},
		{Recipient20("erc20-a"), HU([]byte("another-execution-genesis"))},
	} {
		var salt [32]byte
		copy(salt[12:], variant.token[:])
		cfg := *world.Cfg
		cfg.SemanticProfileHash = erc20SemanticProfileHash
		cfg.ExecutionGenesis = variant.genesis
		cfg.ERC20 = &ERC20Config{variant.token, generation, pins}
		cfg.Asset, cfg.Ty, cfg.Aid = ERC20AssetIDs(cfg.ChainID, variant.token, cfg.ExecutionGenesis)
		cfg.Vault = predict(salt, vaultInit)
		recovery := predict(HE(salt[:]), recoveryInit)
		w, v, _ := flatFixtureVerifierFor(t, FlatConfigBytes(&cfg), FlatDeployment{
			Salt: generation, Pins: pins, Runtime: runtime, Recovery: recovery,
		})
		draft, _ := flatFixtureRoot(t, w, v, 100, Key("erc20-root"))
		parent, children, allocations := flatFixtureSplit(t, w, v, draft, 40, 60)
		held, err := w.Finalize(children[0])
		require.NoError(t, err)
		heldEvidence, _ := flatFixtureEncode(t, []flatFixtureLevel{{nil, parent}, {allocations[0], held}})
		heldPart, err := v.VerifyFlatHeld(heldEvidence)
		require.NoError(t, err)
		require.Equal(t, u256u(40), heldPart.Amount)
		child := flatFixtureReturn(t, w, v, children[0], 0)
		evidence, records := flatFixtureEncode(t, []flatFixtureLevel{{nil, parent}, {allocations[0], child}})
		verdict, err := v.VerifyFlatReturn(evidence)
		require.NoError(t, err)
		require.Equal(t, cfg.Asset, verdict.Asset)
		require.Equal(t, "40", verdict.Amount.String())
		trace, event := flatFixtureRun(t, w, v, evidence, records, 16)
		require.Len(t, trace, 1)
		require.Equal(t, verdict, event.Verdict)

		pages, err := NewFlatEvidence(evidence)
		require.NoError(t, err)
		packet := FlatGapPacket{Header: pages.Header(), Kind: FlatCompleteEvent, Receipt: trace[0].ResultReceipt}
		redeem, err := packet.Calldata(FlatRedeemRecovered, 64)
		require.NoError(t, err)
		vectors = append(vectors, erc20Vector{
			Asset: h32(cfg.Asset), Type: h32(cfg.Ty), Coin: h32(cfg.Aid), Genesis: h32(cfg.ExecutionGenesis),
			Vault: h(cfg.Vault[:]), Recovery: h(recovery[:]), Gamma: h(w.Gamma), Domain: h32(v.domain),
			Held: h(heldEvidence), Evidence: h(evidence), Verdict: h(verdict.ABI()), Packet: h(trace[0].Payload), Complete: h(trace[0].Data), ReturnProof: h(redeem),
		})
		if verifierA == nil {
			verifierA, evidenceA = v, evidence
			continue
		}
		_, err = v.VerifyFlatReturn(evidenceA)
		require.ErrorIs(t, err, ErrMintType)
		_, err = verifierA.VerifyFlatReturn(evidence)
		require.ErrorIs(t, err, ErrMintType)
	}
	require.NotEqual(t, vectors[0].Asset, vectors[1].Asset)
	require.NotEqual(t, vectors[0].Coin, vectors[2].Coin)
	require.NotEqual(t, vectors[0].Type, vectors[2].Type)

	otherGeneration := *verifierA.cfg
	otherERC20 := *otherGeneration.ERC20
	otherGeneration.ERC20 = &otherERC20
	otherERC20.Generation = HU([]byte("other factory generation"))
	otherDeployment := verifierA.deployment
	otherDeployment.Salt = otherERC20.Generation
	otherVerifier, err := NewFlatVerifier(FlatConfigBytes(&otherGeneration), otherDeployment, verifierA.authority)
	require.NoError(t, err)
	_, err = otherVerifier.VerifyFlatReturn(evidenceA)
	require.ErrorIs(t, err, ErrMintDomain)

	if path := os.Getenv("NB2_ERC20_VECTORS"); path != "" {
		data, err := json.MarshalIndent(struct {
			Factory, VaultTemplate, RecoveryTemplate string
			Assets                                   []erc20Vector
		}{h(factory[:]), h32(vaultInit), h32(recoveryInit), vectors}, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, append(data, '\n'), 0o644))
	}
}
