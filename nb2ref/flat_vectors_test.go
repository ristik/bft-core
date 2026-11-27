package nb2ref

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-core/b1state"
)

const flatVectorDir = "../testvectors/nb2-continuation-v1.1"

func flatGolden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(flatVectorDir, name+".bin"))
	require.NoError(t, err)
	return data
}

func flatFixtureVerifier(t *testing.T) (*World, *FlatVerifier, b1ref.Words) {
	t.Helper()
	return flatFixtureVerifierFor(t, flatGolden(t, "gamma"), FlatDeployment{
		[32]byte(flatGolden(t, "generation-salt")), [32]byte(flatGolden(t, "pins")), HE([]byte{0x60, 3, 0}), [20]byte{18: 0xf2, 19: 0x02},
	})
}

func flatFixtureVerifierFor(t *testing.T, gamma []byte, deployment FlatDeployment) (*World, *FlatVerifier, b1ref.Words) {
	t.Helper()
	w, err := NewWorld(64, 16, 2)
	require.NoError(t, err)
	cfg, err := DecodeFlatConfig(gamma)
	require.NoError(t, err)
	require.Equal(t, w.Trust.ID(), cfg.RootGenesis)
	w.Cfg, w.Gamma = cfg, gamma
	var epochs []b1state.Entry
	for i, entry := range w.Entries {
		id, err := entry.EntryID()
		require.NoError(t, err)
		e := b1state.Entry{Epoch: entry.Epoch, BodyKind: 1, BodyID: id, Start: entry.EpochStart,
			SigningScheme: 1, SigningConfigHash: HU([]byte("fixture/signing-config"))}
		if i != 0 {
			e.BodyKind, e.ActivationCommitID = 2, HU([]byte("fixture/activation"))
		}
		if i+1 < len(w.Entries) {
			end := w.Entries[i+1].EpochStart
			e.End = &end
		}
		for _, member := range entry.RootNodes {
			e.Members = append(e.Members, b1state.Member{NodeID: member.NodeID, Key: [33]byte(member.SigKey), Weight: member.Stake})
		}
		require.NoError(t, e.Validate())
		epochs = append(epochs, e)
	}
	pins := b1ref.Pins{GenesisCommitment: HU([]byte("fixture/11/b1-genesis")), ProfileHash: HU([]byte("fixture/11/b1-profile"))}
	registry := b1ref.Model{GenesisCommitment: pins.GenesisCommitment, ProfileHash: pins.ProfileHash,
		Phase: 2, Network: cfg.Network, GenesisEpoch: 1, ImportedTip: 2, OriginReady: true,
		Origin: 2, RootRound: 10_000, Epochs: epochs}.Words()
	v, err := NewFlatVerifier(gamma, deployment, FlatAuthority{registry, pins})
	require.NoError(t, err)
	return w, v, registry
}

func TestFlatIndependentlyEncodedGoldens(t *testing.T) {
	_, v, _ := flatFixtureVerifier(t)
	expect := func(name string, got []byte) { t.Helper(); require.Equal(t, flatGolden(t, name), got, name) }
	expect("domain", v.domain[:])
	expect("gamma", FlatConfigBytes(v.cfg))
	require.Equal(t, v.domain, v.cfg.Domain())
	g := FlatHash("GEN", v.deployment.Salt[:], v.domain[:])
	expect("generation", g[:])
	var descriptors [6][]byte
	for i, name := range []string{"cert-batch-v2", "rsmt-member-v1", "seal-registry-layout", "cancun-b1", "build-index", "primitive-vectors"} {
		descriptors[i] = flatGolden(t, "descriptor-"+name)
	}
	release := FlatRelease(descriptors)
	expect("release", release[:])
	record := flatReader{raw: flatGolden(t, "pin-records")}
	var pins []FlatPin
	for range 5 {
		p := FlatPin{Role: record.u16(), Address: [20]byte(record.take(20)), Digest: record.hash()}
		pins = append(pins, p)
	}
	p, err := FlatPins(release, pins)
	require.NoError(t, err)
	expect("pins", p[:])
	ev, err := NewFlatEvidence(flatGolden(t, "prelude"))
	require.NoError(t, err)
	h := ev.Header()
	expect("page-root", h.Root[:])
	session := v.Session(h)
	expect("session", session[:])
	pad := func(v byte) [32]byte { return [32]byte(bytes.Repeat([]byte{v}, 32)) }
	link := FlatParentLink(v.domain, pad(0x11), pad(0x22), pad(0x33), pad(0x44), u256u(7))
	expect("parent-link", link[:])
	owner := mustHex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	child := MintTx{Network: 3, Recipient: SignaturePredicate(owner), Type: v.cfg.Ty,
		Justification: FlatChildReason(link), Data: ValueData(v.cfg.Aid, big.NewInt(1))}
	expect("child-mint", child.Bytes())
	hash := HU(child.Bytes())
	expect("child-mint-hash", hash[:])
	state := FlatState{Phase: FlatRootMint, Pos: 14, LevelsLeft: 1, SeenRoot: flatSparseDefaults[flatSIDTree][256], ClaimRoot: flatSparseDefaults[flatClaimTree][256]}
	expect("initial-state", state.Bytes())
	digest := state.Digest(session)
	expect("initial-state-digest", digest[:])
	for i, name := range []string{"run", "advance-gaps", "redeem-recovered"} {
		s := FlatEntry(i + 1).Selector()
		expect(name+"-signature", s[:])
	}
	for kind, name := range map[FlatEventKind]string{FlatProgressEvent: "progress", FlatCompleteEvent: "complete", FlatGapEvent: "gap"} {
		s := kind.Topic()
		expect(name+"-signature", s[:])
	}
}

type flatFixtureLevel struct {
	allocation []byte
	token      *Token
}
type flatSourceFixture struct {
	code       FlatOpcode
	start, end uint64
	sid        [32]byte
	claims     []flatClaim
	token      *Token
	transfer   int
}

func flatFixtureRoot(t *testing.T, w *World, v *FlatVerifier, value int64, key *secp256k1.PrivateKey) (*Draft, [32]byte) {
	return flatFixtureRootWithReceipt(t, w, v, value, key, ReceiptOpts{Type: 2, TxIndex: 3, FillerLogs: 2})
}

func flatFixtureRootWithReceipt(t *testing.T, w *World, v *FlatVerifier, value int64, key *secp256k1.PrivateKey, opts ReceiptOpts) (*Draft, [32]byte) {
	t.Helper()
	r := DepositIntentSecret(w.WalletKey, v.domain, 1)
	rho := Rho(v.domain, r)
	log := RawLog{Address: w.Cfg.Vault, Topics: [][32]byte{TopicDeposited, u256u(1)}, Data: DepositedData(v.domain, big.NewInt(value), rho, FirstOwner(key))}
	p, err := w.ReceiptProof(log, opts)
	require.NoError(t, err)
	j := ReceiptBacking{D: v.domain, N: 1, R: r, Proof: *p}
	m := MintTx{Network: w.Cfg.Network, Recipient: sigPred(key), Salt: DepositSalt(v.domain, 1, r), Type: w.Cfg.Ty,
		Justification: j.Bytes(), Data: ValueData(w.Cfg.Aid, big.NewInt(value))}
	return &Draft{Mint: m, Owners: []*secp256k1.PrivateKey{key}}, rho
}

func flatFixtureSplit(t *testing.T, w *World, v *FlatVerifier, parent *Draft, amounts ...int64) (*Token, []*Draft, [][]byte) {
	t.Helper()
	pid := TokenID(parent.Mint.Salt, parent.Mint.Network)
	leaves := make([]SumLeaf, 0, len(amounts))
	kids := make([]*Draft, 0, len(amounts))
	for i, amount := range amounts {
		key := Key(fmt.Sprintf("flat-child-%d-%x", i, pid[:4]))
		salt := HU([]byte("flat-split/child"), pid[:], flatU64(uint64(i)))
		m := MintTx{Network: w.Cfg.Network, Recipient: sigPred(key), Salt: salt, Type: w.Cfg.Ty,
			Data: ValueData(w.Cfg.Aid, big.NewInt(amount))}
		leaves = append(leaves, SumLeaf{TokenID(salt, m.Network), FlatOutput(pid, &m), big.NewInt(amount)})
		kids = append(kids, &Draft{Mint: m, Owners: []*secp256k1.PrivateKey{key}})
	}
	tree, err := BuildSumTree(leaves)
	require.NoError(t, err)
	manifest := SplitManifest{tree.Root()}
	data := manifest.Bytes()
	parent.Transfers = append(parent.Transfers, TransferTx{Recipient: BurnPredicate(HU(data)),
		Mask: HU([]byte("flat-split/burn"), pid[:]), Data: data})
	if parent.Cert == nil {
		parent.Cert = make(map[int]CertOpts)
	}
	parent.Cert[len(parent.Transfers)] = CertOpts{IRTime: DevTime + 10_000}
	tok, err := w.Finalize(parent)
	require.NoError(t, err)
	last := tok.Proofs[len(tok.Proofs)-1].CD
	amount, err := parseMintData(w.Cfg, parent.Mint.Data)
	require.NoError(t, err)
	link := FlatParentLink(v.domain, pid, StateID(last.Source, last.SourceHash), last.TxHash, manifest.Root, u256(amount))
	var proofs [][]byte
	for i, kid := range kids {
		kid.Mint.Justification = FlatChildReason(link)
		proof, ok := tree.Proof(leaves[i].Key)
		require.True(t, ok)
		proofs = append(proofs, proof.Bytes())
	}
	return tok, kids, proofs
}

func flatFixtureReturn(t *testing.T, w *World, v *FlatVerifier, d *Draft, index uint64) *Token {
	t.Helper()
	vd, err := parseMintData(w.Cfg, d.Mint.Data)
	require.NoError(t, err)
	d.Return(&ReturnData{D: v.domain, Asset: AssetUCT, Amount: vd, Recipient: Recipient20("flat-vector"), MinIndex: index})
	if d.Cert == nil {
		d.Cert = make(map[int]CertOpts)
	}
	d.Cert[len(d.Transfers)] = CertOpts{IRTime: DevTime + 10_000}
	tok, err := w.Finalize(d)
	require.NoError(t, err)
	return tok
}

func flatFixtureLineage(t *testing.T, w *World, v *FlatVerifier, transfers, splits int, held bool) []flatFixtureLevel {
	t.Helper()
	d, _ := flatFixtureRoot(t, w, v, 100, Key("flat-root"))
	d.Cert = make(map[int]CertOpts)
	for i := range transfers {
		owner := Key(fmt.Sprintf("flat-owner-%d", i%4))
		d.Transfer(sigPred(owner), owner)
		opts := CertOpts{IRTime: DevTime + 10_000}
		if i >= transfers/2 {
			opts.Committee, opts.Seal = w.Roots[1], &SealOpts{DevNetwork, 2, RotationRound + uint64(i)}
		}
		d.Cert[i+1] = opts
	}
	levels := make([]flatFixtureLevel, 0, splits+1)
	var allocation []byte
	for i := range splits {
		parent, kids, paths := flatFixtureSplit(t, w, v, d, int64(99-i), 1)
		levels = append(levels, flatFixtureLevel{allocation, parent})
		d, allocation = kids[0], paths[0]
	}
	if held {
		tok, err := w.Finalize(d)
		require.NoError(t, err)
		return append(levels, flatFixtureLevel{allocation, tok})
	}
	return append(levels, flatFixtureLevel{allocation, flatFixtureReturn(t, w, v, d, 7)})
}

func flatFixtureEncode(t *testing.T, levels []flatFixtureLevel) ([]byte, []flatSourceFixture) {
	t.Helper()
	evidence := cat([]byte("NB2L"), flatU16(0x0101), flatU64(uint64(len(levels))))
	var operations []flatSourceFixture
	for i, level := range levels {
		tok := level.token
		start := uint64(len(evidence))
		evidence = flatBlob(evidence, level.allocation)
		evidence = flatBlob(evidence, tok.mintRaw)
		evidence = flatBlob(evidence, tok.MintProof.Bytes())
		evidence = append(evidence, flatU64(uint64(len(tok.Transfers)))...)
		op := flatSourceFixture{code: FlatChildMint, start: start, end: uint64(len(evidence)),
			sid: expectedSID(t, tok.MintProof.CD), token: tok}
		if i == 0 {
			op.code, op.start = FlatRootMint, 0
			j, err := DecodeReceiptBacking(tok.Mint.Justification)
			require.NoError(t, err)
			op.claims = append(op.claims, expectedClaim(t, j.Proof.UC))
		}
		op.claims = append(op.claims, expectedClaim(t, tok.MintProof.UC))
		operations = append(operations, op)
		for j, proof := range tok.Proofs {
			start := uint64(len(evidence))
			evidence = flatBlob(evidence, CArr(tok.transfersRaw[j], proof.Bytes()))
			operations = append(operations, flatSourceFixture{code: FlatTransfer, start: start, end: uint64(len(evidence)),
				sid: expectedSID(t, proof.CD), claims: []flatClaim{expectedClaim(t, proof.UC)}, token: tok, transfer: j})
		}
	}
	return evidence, operations
}

type flatFixtureWallet struct {
	evidence *FlatEvidence
	seen     flatSparseTree
	claims   flatSparseTree
	values   map[[32]byte][32]byte
}

func newFlatFixtureWallet(e *FlatEvidence) *flatFixtureWallet {
	return &flatFixtureWallet{e, flatSparseTree{domain: flatSIDTree}, flatSparseTree{domain: flatClaimTree}, make(map[[32]byte][32]byte)}
}

func (w *flatFixtureWallet) packet(t *testing.T, prior *FlatState, receipt []byte, records []flatSourceFixture) FlatRunPacket {
	t.Helper()
	p := FlatRunPacket{Header: w.evidence.Header(), Prior: prior, Receipt: receipt}
	local := map[[32]byte]bool{}
	pages := map[uint64]bool{}
	for _, record := range records {
		op := FlatOperation{Code: record.code, SID: w.seen.opening(record.sid)}
		w.seen.insert(record.sid, flatSIDLeaf(record.sid))
		for _, c := range record.claims {
			if local[c.key] {
				op.Claims = append(op.Claims, FlatClaimOpening{Reuse: true})
				continue
			}
			old, exists := w.values[c.key]
			op.Claims = append(op.Claims, FlatClaimOpening{Present: exists, Old: old, Path: w.claims.opening(c.key)})
			w.claims.insert(c.key, flatClaimLeaf(c.key, c.value))
			w.values[c.key] = c.value
			local[c.key] = true
		}
		p.Operations = append(p.Operations, op)
		for i := record.start / FlatPageBytes; i <= (record.end-1)/FlatPageBytes; i++ {
			pages[i] = true
		}
	}
	indices := make([]uint64, 0, len(pages))
	for i := range pages {
		indices = append(indices, i)
	}
	sort.Slice(indices, func(i, j int) bool { return indices[i] < indices[j] })
	for _, i := range indices {
		page, err := w.evidence.Page(i)
		require.NoError(t, err)
		p.Pages = append(p.Pages, page)
	}
	return p
}

type flatFixtureTrace struct {
	Payload, OldState, NewState, Topics, Data, ResultReceipt []byte
}

func flatFixtureRun(t *testing.T, w *World, v *FlatVerifier, evidence []byte, records []flatSourceFixture, cuts int) ([]flatFixtureTrace, FlatEvent) {
	t.Helper()
	e, err := NewFlatEvidence(evidence)
	require.NoError(t, err)
	wallet := newFlatFixtureWallet(e)
	model := newExpectedLineage(v, evidence)
	require.Equal(t, model.pageRoot, e.Header().Root)
	var state *FlatState
	var prior []byte
	var trace []flatFixtureTrace
	var event FlatEvent
	for i := 0; i < len(records); {
		n := min(cuts, len(records)-i)
		// Isolate the child mint after the oversized parent. Its packet must
		// not carry an opening for earlier parent history.
		if cuts > 1 && len(evidence) > 32*FlatPageBytes && len(records) > 2 && records[len(records)-2].code == FlatChildMint {
			child := len(records) - 2
			if i == child {
				n = 1
			} else if i < child && i+n > child {
				n = child - i
			}
		}
		packet := wallet.packet(t, state, prior, records[i:i+n])
		data, err := packet.Calldata()
		require.NoError(t, err)
		frame, next, expected := flatFixtureFrame(t, w, v, model, packet, data, records[i:i+n],
			ReceiptOpts{Type: 2, TxIndex: 3, FillerLogs: 2, Rotated: i%2 == 1})
		prior = frame.ResultReceipt
		trace = append(trace, frame)
		state, event = next, expected
		i += n
	}
	return trace, event
}

func flatFixtureFrame(t *testing.T, w *World, v *FlatVerifier, model *expectedLineage, packet FlatRunPacket,
	data []byte, records []flatSourceFixture, opts ReceiptOpts,
) (flatFixtureTrace, *FlatState, FlatEvent) {
	t.Helper()
	next, event := model.packet(t, records)
	log := expectedLog(event, model.runtimeAddress)
	receipt, err := w.ReceiptProof(log, opts)
	require.NoError(t, err)
	f := flatFixtureTrace{Payload: data, Topics: bytes.Join([][]byte{log.Topics[0][:], log.Topics[1][:]}, nil),
		Data: log.Data, ResultReceipt: receipt.Bytes()}
	if packet.Prior != nil {
		f.OldState = expectedStateWire(*packet.Prior)
	}
	if next != nil {
		f.NewState = expectedStateWire(*next)
	}
	actual, err := v.RunFlat(data)
	require.NoError(t, err)
	require.Equal(t, log, actual.Event.Log(model.runtimeAddress))
	if next == nil {
		require.Nil(t, actual.State)
	} else {
		require.Equal(t, f.NewState, actual.State.Bytes())
	}
	return f, next, event
}

func flatFixtureExports(t *testing.T, name string, w *World, v *FlatVerifier, registry b1ref.Words, evidence, verdict []byte, trace []flatFixtureTrace) {
	t.Helper()
	dir := os.Getenv("NB2_FLAT_VECTOR_OUT")
	if dir == "" {
		return
	}
	p := filepath.Join(dir, name)
	writeFlatFixture(t, p, w, v, registry, evidence, verdict, trace)
}

func writeFlatFixture(t *testing.T, p string, w *World, v *FlatVerifier, registry b1ref.Words, evidence, verdict []byte, trace []flatFixtureTrace) {
	t.Helper()
	require.NoError(t, os.MkdirAll(p, 0755))
	var expected []byte
	if len(trace) > 0 {
		terminal := trace[len(trace)-1]
		require.Empty(t, terminal.NewState)
		require.Len(t, terminal.Data, 224)
		expected = terminal.Data[32:]
	}
	require.Equal(t, expected, verdict)
	for n, b := range map[string][]byte{"evidence.bin": evidence, "utb.cbor": w.Trust.Bundle, "verdict.bin": expected} {
		require.NoError(t, os.WriteFile(filepath.Join(p, n), b, 0644))
	}
	writeFlatContext(t, p, v, registry, evidence)
	writeFlatTrace(t, p, trace)
}

func writeFlatContext(t *testing.T, p string, v *FlatVerifier, registry b1ref.Words, evidence []byte) {
	t.Helper()
	slots := make(map[string]string, len(registry))
	for k, value := range registry {
		slots[hex.EncodeToString(k[:])] = hex.EncodeToString(value[:])
	}
	expectedContext := newExpectedLineage(v, evidence)
	r, err := json.MarshalIndent(struct {
		GenesisCommitment, RegistryProfile, RecoveryAddress, RecoveryRuntimeHash, Session, PageRoot string
		EvidenceLength                                                                              uint64
		Registry                                                                                    map[string]string
	}{fmt.Sprintf("%x", v.authority.Pins.GenesisCommitment), fmt.Sprintf("%x", v.authority.Pins.ProfileHash),
		fmt.Sprintf("%x", v.deployment.Recovery), fmt.Sprintf("%x", v.deployment.Runtime),
		fmt.Sprintf("%x", expectedContext.session), fmt.Sprintf("%x", expectedContext.pageRoot),
		uint64(len(evidence)), slots}, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(p, "context.json"), append(r, '\n'), 0644))
}

func writeFlatTrace(t *testing.T, p string, trace []flatFixtureTrace) {
	t.Helper()
	var payload []byte
	for _, f := range trace {
		for _, b := range [][]byte{f.Payload, f.OldState, f.NewState, f.Topics, f.Data, f.ResultReceipt} {
			payload = flatBlob(payload, b)
		}
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, err := gz.Write(payload)
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	require.NoError(t, os.WriteFile(filepath.Join(p, "trace.bin.gz"), compressed.Bytes(), 0644))
}

func mustFlatEvidence(t *testing.T, raw []byte) *FlatEvidence {
	t.Helper()
	e, err := NewFlatEvidence(raw)
	require.NoError(t, err)
	return e
}

func TestFlatSignedTranscripts(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		n, split int
	}{
		{"root", 0, 0}, {"transfers", 12, 0}, {"one-split", 5, 1},
		{"depth-20", 0, 20}, {"transfers-600", 600, 0}, {"parent-over-32-pages", 600, 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			w, v, registry := flatFixtureVerifier(t)
			levels := flatFixtureLineage(t, w, v, scenario.n, scenario.split, false)
			evidence, records := flatFixtureEncode(t, levels)
			verdict, err := v.VerifyFlatReturn(evidence)
			require.NoError(t, err)
			trace, event := flatFixtureRun(t, w, v, evidence, records, 16)
			require.Equal(t, FlatCompleteEvent, event.Kind)
			require.Equal(t, verdict.ABI(), event.Verdict.ABI())
			if len(records) < 100 {
				_, event := flatFixtureRun(t, w, v, evidence, records, 1)
				require.Equal(t, verdict.ABI(), event.Verdict.ABI())
			}
			if scenario.name == "parent-over-32-pages" {
				child := records[len(records)-2]
				require.Equal(t, FlatChildMint, child.code)
				require.Greater(t, child.start/FlatPageBytes, uint64(32))
				packet, err := DecodeFlatRun(trace[len(trace)-2].Payload)
				require.NoError(t, err)
				require.Len(t, packet.Operations, 1)
				require.Equal(t, FlatChildMint, packet.Operations[0].Code)
				require.Equal(t, child.start, packet.Prior.Pos)
				require.Len(t, packet.Pages, int((child.end-1)/FlatPageBytes-child.start/FlatPageBytes+1))
				for _, page := range packet.Pages {
					require.GreaterOrEqual(t, page.Index, child.start/FlatPageBytes)
					require.LessOrEqual(t, page.Index, (child.end-1)/FlatPageBytes)
				}
			}
			t.Logf("%d bytes, %d sources, %d packets", len(evidence), len(records), len(trace))
			flatFixtureExports(t, scenario.name, w, v, registry, evidence, verdict.ABI(), trace)
		})
	}
}

func TestFlatHeldAndSiblingWitnesses(t *testing.T) {
	w, v, registry := flatFixtureVerifier(t)
	d, _ := flatFixtureRoot(t, w, v, 100, Key("flat-siblings"))
	root, kids, paths := flatFixtureSplit(t, w, v, d, 25, 35, 40)
	for i := range kids {
		child, err := w.Finalize(kids[i])
		require.NoError(t, err)
		e, ops := flatFixtureEncode(t, []flatFixtureLevel{{nil, root}, {paths[i], child}})
		holding, err := v.VerifyFlatHeld(e)
		require.NoError(t, err)
		expected, event := newExpectedLineage(v, e).packet(t, ops)
		require.Equal(t, FlatProgressEvent, event.Kind)
		want := FlatHolding{Owner: expected.Owner, State: expected.State, TokenID: expected.TokenID, Amount: expected.Amount}
		require.Equal(t, want, holding)
		_, err = v.VerifyFlatReturn(e)
		require.ErrorIs(t, err, ErrNoTransfers)
		name := fmt.Sprintf("held-sibling-%d", i)
		flatFixtureExports(t, name, w, v, registry, e, nil, nil)
		if dir := os.Getenv("NB2_FLAT_VECTOR_OUT"); dir != "" {
			wire := bytes.Join([][]byte{want.Owner[:], want.State[:], want.TokenID[:], want.Amount[:]}, nil)
			require.NoError(t, os.WriteFile(filepath.Join(dir, name, "holding.bin"), wire, 0644))
		}
		bad, _ := flatFixtureEncode(t, []flatFixtureLevel{{nil, root}, {paths[(i+1)%len(paths)], child}})
		_, err = v.VerifyFlatHeld(bad)
		require.ErrorIs(t, err, ErrSplitProof)
	}
}

// The replacement receipt is independently certified from the already
// authenticated event. The only replay inputs are E, the published cuts
// and the last durable checkpoint.
func TestFlatRestartFromRebuiltScratchAndAlternateReceipt(t *testing.T) {
	w, v, _ := flatFixtureVerifier(t)
	raw, records := flatFixtureEncode(t, flatFixtureLineage(t, w, v, 330, 1, false))
	trace, complete := flatFixtureRun(t, w, v, raw, records, 16)
	base := trace[18]
	state, err := DecodeFlatState(base.NewState)
	require.NoError(t, err)
	e := mustFlatEvidence(t, raw)
	ev, err := v.event(e.Header(), FlatProgressEvent, base.ResultReceipt)
	require.NoError(t, err)
	replacement := flatCertifiedEvent(t, w, v, ev, ReceiptOpts{Rotated: true, Type: 2, TxIndex: 4})
	require.NotEqual(t, base.ResultReceipt, replacement)
	wallet := newFlatFixtureWallet(e)
	i := 0
	for _, old := range trace[:19] {
		p, err := DecodeFlatRun(old.Payload)
		require.NoError(t, err)
		n := len(p.Operations)
		wallet.packet(t, nil, nil, records[i:i+n])
		i += n
	}
	require.Equal(t, state.Pos, records[i].start)
	require.Equal(t, state.SeenRoot, wallet.seen.lookup(256, [32]byte{}))
	require.Equal(t, state.ClaimRoot, wallet.claims.lookup(256, [32]byte{}))
	prior := &state
	for _, next := range trace[19:] {
		old, err := DecodeFlatRun(next.Payload)
		require.NoError(t, err)
		n := len(old.Operations)
		raw, err := wallet.packet(t, prior, replacement, records[i:i+n]).Calldata()
		require.NoError(t, err)
		result, err := v.RunFlat(raw)
		require.NoError(t, err)
		log := result.Event.Log(v.deployment.Recovery)
		require.Equal(t, next.Data, log.Data)
		prior, replacement = result.State, next.ResultReceipt
		i += n
		if result.Event.Kind == FlatCompleteEvent {
			require.Equal(t, complete.Verdict.ABI(), result.Event.Verdict.ABI())
		}
	}
	require.Equal(t, len(records), i)
	require.Nil(t, prior)
}
