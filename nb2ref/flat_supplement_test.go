package nb2ref

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-go-base/types"
)

const flatSupplement = "../testvectors/nb2-continuation-v1.1-supplement"

func supplementRead(t *testing.T, dir, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	require.NoError(t, err)
	return raw
}

func supplementWrite(t *testing.T, dir, name string, raw []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), raw, 0644))
}

func readFlatFixtureDeployment(t *testing.T, input string) FlatDeployment {
	t.Helper()
	var identity struct {
		RecoveryAddress, RecoveryRuntimeHash, Pins string
	}
	require.NoError(t, json.Unmarshal(supplementRead(t, input, "deployment.json"), &identity))
	decode := func(s string, n int) []byte {
		b, err := hex.DecodeString(s)
		require.NoError(t, err)
		require.Len(t, b, n)
		return b
	}
	return FlatDeployment{
		Salt:     [32]byte(supplementRead(t, input, "generation-salt.bin")),
		Pins:     [32]byte(decode(identity.Pins, 32)),
		Runtime:  [32]byte(decode(identity.RecoveryRuntimeHash, 32)),
		Recovery: [20]byte(decode(identity.RecoveryAddress, 20)),
	}
}

func TestFlatSupplement(t *testing.T) {
	dir := os.Getenv("NB2_FLAT_SUPPLEMENT_OUT")
	input := dir
	if dir == "" {
		input, dir = flatSupplement, t.TempDir()
	}
	deployment := readFlatFixtureDeployment(t, input)
	gamma := supplementRead(t, input, "gamma.bin")

	// Keep each scenario independent of the signing counters of the others.
	t.Run("rollover", func(t *testing.T) {
		w, v, registry := flatFixtureVerifierFor(t, gamma, deployment)
		flatSupplementRollover(t, dir, w, v, registry)
	})
	t.Run("conflict", func(t *testing.T) {
		w, v, registry := flatFixtureVerifierFor(t, gamma, deployment)
		flatSupplementConflict(t, dir, w, v, registry)
	})
	if input != dir {
		require.NoError(t, filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
			require.NoError(t, err)
			if !entry.IsDir() {
				rel, err := filepath.Rel(dir, path)
				require.NoError(t, err)
				published, regenerated := supplementRead(t, input, rel), supplementRead(t, dir, rel)
				// Go releases can encode the same trace with different DEFLATE blocks.
				if filepath.Ext(rel) == ".gz" {
					published, regenerated = supplementGunzip(t, published), supplementGunzip(t, regenerated)
				}
				require.True(t, bytes.Equal(published, regenerated), "%s differs", rel)
			}
			return nil
		}))
	}
}

func supplementGunzip(t *testing.T, raw []byte) []byte {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(raw))
	require.NoError(t, err)
	trace, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	return trace
}

func flatSupplementRollover(t *testing.T, out string, w *World, v *FlatVerifier, registry b1ref.Words) {
	// A full packet contains the deposit, the mint, and 15 transfers.
	// The remaining sources also leave a trailing page to authenticate but not use.
	levels := flatFixtureLineage(t, w, v, 24, 0, false)
	evidence, records := flatFixtureEncode(t, levels)
	batches := supplementRolloverBatches(t, records[:16])
	for _, req := range batches {
		verdict, err := b1ref.Cert(req, registry, v.authority.Pins)
		require.NoError(t, err)
		require.True(t, verdict.Valid, "%v", verdict.Why)
	}
	trace, complete := flatFixtureRun(t, w, v, evidence, records, 16)
	actual, err := v.VerifyFlatReturn(evidence)
	require.NoError(t, err)
	require.Equal(t, expectedVerdictWire(complete.Verdict), actual.ABI())
	dir := filepath.Join(out, "b1-rollover")
	writeFlatFixture(t, dir, w, v, registry, evidence, expectedVerdictWire(complete.Verdict), trace)
	supplementWrite(t, dir, "batch-1.bin", batches[0])
	supplementWrite(t, dir, "batch-2.bin", batches[1])

	// Keep the UC and membership folds intact, but deprive one seal of quorum.
	tok := levels[0].token
	uc, err := decodeUC(tok.MintProof.UC)
	require.NoError(t, err)
	for signer, sig := range uc.UnicitySeal.Signatures {
		uc.UnicitySeal.Signatures[signer] = make([]byte, len(sig))
	}
	tok.MintProof.UC, err = types.Cbor.Marshal(uc)
	require.NoError(t, err)
	evidence, records = flatFixtureEncode(t, levels)
	batches = supplementRolloverBatches(t, records[:16])
	bad, err := b1ref.Cert(batches[0], registry, v.authority.Pins)
	require.NoError(t, err)
	require.False(t, bad.Valid)
	require.ErrorIs(t, bad.Why, b1ref.ErrQuorum)
	good, err := b1ref.Cert(batches[1], registry, v.authority.Pins)
	require.NoError(t, err)
	require.True(t, good.Valid, "%v", good.Why)

	e := mustFlatEvidence(t, evidence)
	packet := newFlatFixtureWallet(e).packet(t, nil, nil, records[:16])
	badStep := supplementCalldata(t, packet)
	result, err := v.RunFlat(badStep)
	require.Nil(t, result)
	require.ErrorIs(t, err, ErrFlatStep)
	require.ErrorIs(t, err, b1ref.ErrQuorum)
	unused, err := e.Page(flatPageCount(uint64(len(evidence))) - 1)
	require.NoError(t, err)
	require.Greater(t, unused.Index, packet.Pages[len(packet.Pages)-1].Index)
	packet.Pages = append(packet.Pages, unused)
	badPage := supplementCalldata(t, packet)
	result, err = v.RunFlat(badPage)
	require.Nil(t, result)
	require.ErrorIs(t, err, ErrFlatPage)

	dir = filepath.Join(out, "b1-rollover-refusals")
	require.NoError(t, os.MkdirAll(dir, 0755))
	writeFlatContext(t, dir, v, registry, evidence)
	supplementWrite(t, dir, "evidence.bin", evidence)
	supplementWrite(t, dir, "batch-1.bin", batches[0])
	supplementWrite(t, dir, "batch-2.bin", batches[1])
	supplementWrite(t, dir, "BadStep.calldata.bin", badStep)
	supplementWrite(t, dir, "BadPage.calldata.bin", badPage)
}

func supplementRolloverBatches(t *testing.T, records []flatSourceFixture) [2][]byte {
	t.Helper()
	var claims []flatClaim
	for _, rec := range records {
		claims = append(claims, rec.claims...)
	}
	require.Len(t, claims, b1ref.MaxClaims+1)
	reqs := [2][]byte{flatBatchWire(claims[:b1ref.MaxClaims]), flatBatchWire(claims[b1ref.MaxClaims:])}
	for i, req := range reqs {
		grp, err := b1ref.Group(req)
		require.NoError(t, err)
		require.Equal(t, []uint64{16, 1}[i], grp.K)
		require.Equal(t, grp.K, grp.S)
	}
	// Seal count S is per call. Also rule out a duplicate across the rollover boundary.
	for _, earlier := range claims[:b1ref.MaxClaims] {
		require.NotEqual(t, supplementSeal(t, earlier), supplementSeal(t, claims[b1ref.MaxClaims]))
	}
	return reqs
}

func supplementSeal(t *testing.T, claim flatClaim) []byte {
	t.Helper()
	shardLen := int(claim.wire[4])<<8 | int(claim.wire[5])
	uc, err := decodeUC(claim.wire[6+shardLen+3*32+4:])
	require.NoError(t, err)
	raw, err := types.Cbor.Marshal(uc.UnicitySeal)
	require.NoError(t, err)
	return raw
}

func supplementCalldata(t *testing.T, packet FlatRunPacket) []byte {
	t.Helper()
	raw, err := packet.Calldata()
	require.NoError(t, err)
	return raw
}

func flatSupplementConflict(t *testing.T, out string, w *World, v *FlatVerifier, registry b1ref.Words) {
	w.Agg.PDRs = []*types.PartitionDescriptionRecord{FixturePDR(DevNetwork, DevAggPartition, types.ShardID{}, 0, "flat-conflict")}
	levels := flatFixtureLineage(t, w, v, 2, 0, false)
	tok := levels[0].token
	proofs := append([]*InclusionProof{&tok.MintProof}, ptrs(tok.Proofs)...)
	var leaves []Leaf
	for _, p := range proofs {
		leaves = append(leaves, Leaf{StateID(p.CD.Source, p.CD.SourceHash), LeafValue(p.CD.TxHash, p.T)})
	}
	view, err := w.Agg.Certify(leaves, CertOpts{IRTime: DevTime + 10_000})
	require.NoError(t, err)
	for _, i := range []int{0, 2} {
		p := proofs[i]
		p.UC, p.Bitmap, p.Siblings = view[i].UC, view[i].Bitmap, view[i].Siblings
	}
	// Keep the signed seal and the RSMT state root, but change the certified
	// input record. This synthetic second value cannot pass the B1 fold.
	uc, err := decodeUC(proofs[2].UC)
	require.NoError(t, err)
	uc.InputRecord.RoundNumber++
	proofs[2].UC, err = types.Cbor.Marshal(uc)
	require.NoError(t, err)

	evidence, records := flatFixtureEncode(t, levels)
	first, second := records[0].claims[1], records[2].claims[0]
	require.Equal(t, supplementSeal(t, first), supplementSeal(t, second))
	require.Equal(t, first.key, second.key)
	require.NotEqual(t, first.value, second.value)
	verdict, err := b1ref.Cert(flatBatchWire([]flatClaim{second}), registry, v.authority.Pins)
	require.NoError(t, err)
	require.False(t, verdict.Valid)

	e := mustFlatEvidence(t, evidence)
	wallet := newFlatFixtureWallet(e)
	model := newExpectedLineage(v, evidence)
	firstPacket := wallet.packet(t, nil, nil, records[:1])
	start, prior, _ := flatFixtureFrame(t, w, v, model, firstPacket, supplementCalldata(t, firstPacket), records[:1], ReceiptOpts{})
	require.NotNil(t, prior)
	// A retry with the original predecessor processes only the valid transfer.
	retryPacket := wallet.packet(t, prior, start.ResultReceipt, records[1:2])
	retry, _, _ := flatFixtureFrame(t, w, v, model, retryPacket, supplementCalldata(t, retryPacket), records[1:2], ReceiptOpts{})
	wallet = newFlatFixtureWallet(e)
	wallet.packet(t, nil, nil, records[:1])
	badPacket := wallet.packet(t, prior, start.ResultReceipt, records[1:3])
	require.NotEqual(t, first.key, records[1].claims[0].key)
	opening := badPacket.Operations[1].Claims[0]
	require.False(t, opening.Reuse)
	require.True(t, opening.Present)
	require.Equal(t, first.value, opening.Old)

	// The same authenticated opening works for the committed value, and
	// rejects the conflicting value before it can enter the native batch.
	scratch := flatPacketClaims{root: prior.ClaimRoot, cache: make(map[[32]byte][32]byte)}
	use := badPacket.Operations[0].Claims[0]
	require.NoError(t, scratch.apply(records[1].claims[0], use))
	root := scratch.root
	require.ErrorIs(t, scratch.apply(second, opening), ErrFlatStep)
	require.Equal(t, root, scratch.root)
	require.Len(t, scratch.batch, 1)
	require.NoError(t, scratch.apply(first, opening))
	require.Equal(t, root, scratch.root)

	bad := supplementCalldata(t, badPacket)
	for _, raw := range [][]byte{bad, retry.Payload} {
		decoded, err := DecodeFlatRun(raw)
		require.NoError(t, err)
		require.Equal(t, start.ResultReceipt, decoded.Receipt)
		require.Equal(t, start.NewState, decoded.Prior.Bytes())
	}
	result, err := v.RunFlat(bad)
	require.Nil(t, result)
	require.ErrorIs(t, err, ErrFlatStep)
	replayed, err := v.RunFlat(retry.Payload)
	require.NoError(t, err)
	require.Equal(t, retry.NewState, replayed.State.Bytes())

	dir := filepath.Join(out, "cross-cut-conflict")
	require.NoError(t, os.MkdirAll(dir, 0755))
	writeFlatContext(t, dir, v, registry, evidence)
	writeFlatTrace(t, dir, []flatFixtureTrace{start, retry})
	supplementWrite(t, dir, "evidence.bin", evidence)
	supplementWrite(t, dir, "BadStep.calldata.bin", bad)
	supplementWrite(t, dir, "last-usable-predecessor.cbor", start.ResultReceipt)
	supplementWrite(t, dir, "committed-claim.bin", first.wire)
	supplementWrite(t, dir, "conflicting-claim.bin", second.wire)
}
