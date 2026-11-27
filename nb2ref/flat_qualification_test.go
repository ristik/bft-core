package nb2ref

import (
	"bytes"
	"crypto"
	"fmt"
	"maps"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-go-base/types"
)

// extendQualificationCertificate certifies a deliberately deep path with the
// fixture's full weighted committee. No live authority or deployment is used.
func extendQualificationCertificate(t *testing.T, committee *Committee, uc *types.UnicityCertificate) {
	t.Helper()
	tree := uc.UnicityTreeCertificate
	tree.HashSteps = make([]*types.PathItem, 32)
	for i := range tree.HashSteps {
		hash := HU([]byte(fmt.Sprintf("qualification/unicity/%d", i)))
		tree.HashSteps[i] = &types.PathItem{Key: tree.Partition + types.PartitionID(i+1), Hash: hash[:]}
	}
	shard, err := uc.ShardTreeCertificate.ComputeCertificateHash(uc.InputRecord, uc.TRHash, uc.ShardConfHash, crypto.SHA256)
	require.NoError(t, err)
	root, err := tree.EvalAuthPath(shard, crypto.SHA256)
	require.NoError(t, err)
	uc.UnicitySeal.Hash = root
	uc.UnicitySeal.Signatures = nil
	for _, member := range committee.members {
		require.NoError(t, uc.UnicitySeal.Sign(member.info.NodeID, member.signer))
	}
	require.Len(t, uc.UnicitySeal.Signatures, 16)
}

func TestFlatJointNativeQualification(t *testing.T) {
	w, err := NewWorld(64, 16, 1)
	require.NoError(t, err)
	first, err := NewCommittee("qualification-old", 16, 3, 2)
	require.NoError(t, err)
	second, err := NewCommittee("qualification-tip", 16, 2, 3)
	require.NoError(t, err)
	genesis, err := first.Genesis(DevNetwork, 1, 1)
	require.NoError(t, err)
	successor, err := first.Successor(genesis, second, RotationRound)
	require.NoError(t, err)
	pin, err := genesis.EntryID()
	require.NoError(t, err)
	bundle, err := TrustBundle(genesis, successor)
	require.NoError(t, err)
	w.Trust, err = LoadTrustInput(bundle, pin)
	require.NoError(t, err)
	w.Roots = []*Committee{first, second}
	w.Entries = []*types.RootTrustBaseV2{genesis, successor}
	w.Agg.Committee = first

	_, old, _ := flatFixtureVerifier(t)
	cfg := *old.cfg
	cfg.RootGenesis = pin
	cfg.Ty, cfg.Aid = FlatAssetIDs(&cfg)
	gamma, deployment := FlatConfigBytes(&cfg), old.deployment
	if dir := os.Getenv("NB2_FLAT_QUALIFICATION_GRAPH"); dir != "" {
		gamma = supplementRead(t, dir, "gamma.bin")
		deployment = readFlatFixtureDeployment(t, dir)
	}
	w, v, registry := flatFixtureVerifierWithWorld(t, w, gamma, deployment)

	receipt := ReceiptOpts{Type: 2, TxIndex: 127, FillerLogs: 1, MutReceipt: func(r *RawReceipt) {
		r.Logs[0].Data = bytes.Repeat([]byte{0xa5}, 48_000)
	}}
	deposit, predecessor := receipt, receipt
	deposit.TamperUC = func(uc *types.UnicityCertificate) { extendQualificationCertificate(t, first, uc) }
	predecessor.Rotated = true
	predecessor.TamperUC = func(uc *types.UnicityCertificate) { extendQualificationCertificate(t, second, uc) }
	fullPath := func(proof *InclusionProof) {
		sid := StateID(proof.CD.Source, proof.CD.SourceHash)
		uc, err := decodeUC(proof.UC)
		require.NoError(t, err)
		var shard types.ShardID
		require.NoError(t, shard.UnmarshalCBOR(CBytes(append(sid[:], 0x80))))
		require.Equal(t, uint(256), shard.Length())
		uc.ShardTreeCertificate.Shard = shard
		uc.ShardTreeCertificate.SiblingHashes = make([][]byte, 256)
		for i := range uc.ShardTreeCertificate.SiblingHashes {
			hash := HU([]byte(fmt.Sprintf("qualification/shard/%d", i)))
			uc.ShardTreeCertificate.SiblingHashes[i] = hash[:]
		}
		pdr := FixturePDR(DevNetwork, DevAggPartition, shard, 0, "qualification-shard")
		uc.ShardConfHash, err = pdr.Hash(crypto.SHA256)
		require.NoError(t, err)
		extendQualificationCertificate(t, first, uc)
		proof.UC, err = types.Cbor.Marshal(uc)
		require.NoError(t, err)
		t.Logf("child certificate bytes=%d signatures=16 shard siblings=256 unicity steps=32", len(proof.UC))
	}

	const name = "packed-joint-native-qualification"
	flatLargeCombinedWitnesses(t, w, v, registry, flatLargeWitnessOptions{
		name: name, deposit: deposit, predecessor: predecessor, resumePages: 32, denseSparse: true,
		prepareChild: func(draft *Draft) {
			for i := range 14 {
				key := Key(fmt.Sprintf("qualification/owner/%d", i))
				draft.Transfer(sigPred(key), key)
			}
		},
		extendChild: func(child *Token) {
			fullPath(&child.MintProof)
			for i := range 7 {
				flatFixtureExpandRSMT(t, w, &child.Proofs[i], 256)
			}
		},
	})
	if dir := os.Getenv("NB2_FLAT_VECTOR_OUT"); dir != "" {
		generation := FlatHash("GEN", v.deployment.Salt[:], v.domain[:])
		for file, data := range map[string][]byte{
			"gamma.bin": gamma, "domain.bin": v.domain[:], "generation.bin": generation[:],
			"pins.bin": v.deployment.Pins[:],
		} {
			require.NoError(t, os.WriteFile(filepath.Join(dir, name, file), data, 0644))
		}
	}
}

// flatFixtureDenseResume certifies a synthetic prior state to stress sparse
// witness widths without requiring source keys with chosen hash preimages.
func flatFixtureDenseResume(t *testing.T, w *World, v *FlatVerifier, registry b1ref.Words,
	evidence *FlatEvidence, wire []byte, prior FlatState, records []flatSourceFixture,
	verdict *Verdict, opts flatLargeWitnessOptions,
) {
	t.Helper()
	scratch := newFlatFixtureWallet(evidence)
	scratch.packet(t, nil, nil, records[:2])
	actualSIDs := make(map[[32]byte]bool)
	actualClaims := make(map[[32]byte]bool)
	for _, record := range records {
		actualSIDs[record.sid] = true
		for _, claim := range record.claims {
			actualClaims[claim.key] = true
		}
	}
	for i, record := range records[2:14] {
		siblings := 256
		if i == 11 {
			siblings = 220
		}
		for bit := range siblings {
			key := record.sid
			key[bit/8] ^= byte(0x80) >> uint(bit%8)
			if !actualSIDs[key] {
				scratch.seen.insert(key, flatSIDLeaf(key))
			}
			for _, claim := range record.claims {
				key := claim.key
				key[bit/8] ^= byte(0x80) >> uint(bit%8)
				if !actualClaims[key] {
					value := HU([]byte("qualification/sparse/"), key[:])
					scratch.claims.insert(key, flatClaimLeaf(key, value))
				}
			}
		}
	}
	prior.SeenRoot = scratch.seen.lookup(256, [32]byte{})
	prior.ClaimRoot = scratch.claims.lookup(256, [32]byte{})
	certifyState := func(state FlatState, session [32]byte) []byte {
		progress := FlatEvent{Kind: FlatProgressEvent, Session: session, Seq: state.Seq, StateDigest: state.Digest(session)}
		predecessor, err := w.ReceiptProof(progress.Log(v.deployment.Recovery), opts.predecessor)
		require.NoError(t, err)
		return predecessor.Bytes()
	}
	baseSession := v.Session(evidence.Header())
	baseReceipt := certifyState(prior, baseSession)
	for _, tc := range []struct {
		name      string
		cut       int
		deepPages bool
	}{{"-sparse", 16, false}, {"-sparse-split", 8, false}, {"-sparse-deep-pages", 8, true}} {
		wallet := *scratch
		wallet.values = maps.Clone(scratch.values)
		for height := range wallet.seen.nodes {
			wallet.seen.nodes[height] = maps.Clone(scratch.seen.nodes[height])
			wallet.claims.nodes[height] = maps.Clone(scratch.claims.nodes[height])
		}
		initial, header := prior, evidence.Header()
		session, receipt := baseSession, baseReceipt
		var shiftedPages map[uint64]FlatPage
		if tc.deepPages {
			var shift uint64
			shift, header, shiftedPages = flatQualificationDeepPages(t, evidence)
			initial.Pos += shift
			session = v.Session(header)
			receipt = certifyState(initial, session)
		}
		state := &initial
		var trace []flatFixtureTrace
		for i := 2; i < len(records); i += tc.cut {
			packet := wallet.packet(t, state, receipt, records[i:min(i+tc.cut, len(records))])
			if tc.deepPages {
				packet.Header = header
				for j, page := range packet.Pages {
					packet.Pages[j] = shiftedPages[page.Index]
				}
			}
			calldata, err := packet.Calldata()
			require.NoError(t, err)
			if tc.cut == 16 {
				require.Len(t, packet.Pages, 32)
				require.Len(t, packet.Operations, 16)
				require.Len(t, packet.Operations[0].SID.Siblings, 256)
				require.Len(t, packet.Operations[0].Claims[0].Path.Siblings, 256)
				require.Greater(t, len(calldata), 385_000)
			}
			actual, err := v.RunFlat(calldata)
			require.NoError(t, err)
			require.Equal(t, session, actual.Event.Session)
			require.Equal(t, state.Seq+1, actual.Event.Seq)
			event := actual.Event.Log(v.deployment.Recovery)
			result, err := w.ReceiptProof(event, opts.predecessor)
			require.NoError(t, err)
			frame := flatFixtureTrace{Payload: calldata, OldState: state.Bytes(),
				Topics: bytes.Join([][]byte{event.Topics[0][:], event.Topics[1][:]}, nil),
				Data:   event.Data, ResultReceipt: result.Bytes()}
			state, receipt = actual.State, frame.ResultReceipt
			if state != nil {
				frame.NewState = state.Bytes()
			} else {
				require.Equal(t, FlatCompleteEvent, actual.Event.Kind)
				require.Equal(t, verdict.ABI(), actual.Event.Verdict.ABI())
			}
			trace = append(trace, frame)
			t.Logf("dense sparse Resume %s calldata=%d bytes", tc.name, len(calldata))
		}
		require.Nil(t, state)
		flatFixtureExports(t, opts.name+tc.name, w, v, registry, wire, verdict.ABI(), trace)
		if dir := os.Getenv("NB2_FLAT_VECTOR_OUT"); tc.deepPages && dir != "" {
			// evidence.bin contains only the ordinary control. The cold trace
			// uses this separate synthetic header and certified checkpoint.
			name := filepath.Join(dir, opts.name+tc.name, "synthetic-header.bin")
			require.NoError(t, os.WriteFile(name, header.appendTo(nil), 0644))
		}
	}
}

// flatQualificationDeepPages commits to the original witness bytes at the end
// of a synthetic object with 52-step page paths. The unopened prefix is a
// commitment only. The fixture does not claim eligibility of its full lineage.
func flatQualificationDeepPages(t *testing.T, evidence *FlatEvidence) (uint64, FlatHeader, map[uint64]FlatPage) {
	t.Helper()
	originalLength := evidence.Header().Length
	shift := (math.MaxUint64 - originalLength) &^ (FlatPageBytes - 1)
	header := FlatHeader{Length: shift + originalLength}
	depth := flatPageDepth(header.Length)
	require.Equal(t, 52, depth)
	pages := make(map[uint64]FlatPage)
	nodes := make(map[uint64][32]byte)
	for index := range flatPageCount(originalLength) {
		page, err := evidence.Page(index)
		require.NoError(t, err)
		page.Index += shift / FlatPageBytes
		page.Siblings = make([][32]byte, depth)
		pages[index] = page
		nodes[page.Index] = flatPageLeaf(header.Length, page.Index, page.Data)
	}
	for height := range depth {
		next := make(map[uint64][32]byte)
		for _, page := range pages {
			index := page.Index >> height
			sibling, found := nodes[index^1]
			if !found {
				sibling = flatPagePadding[height]
				if ((index ^ 1) << height) < flatPageCount(header.Length) {
					sibling = HU([]byte("qualification/unopened-pages/"), flatU64(uint64(height)), flatU64(index^1))
				}
			}
			page.Siblings[height] = sibling
			if index&1 == 0 {
				next[index>>1] = flatPageNode(nodes[index], sibling)
			} else {
				next[index>>1] = flatPageNode(sibling, nodes[index])
			}
		}
		nodes = next
	}
	header.Root = nodes[0]
	for _, page := range pages {
		require.True(t, page.verifies(header))
	}
	return shift, header, pages
}
