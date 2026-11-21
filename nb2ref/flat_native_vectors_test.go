package nb2ref

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestFlatCappedRootReceipt(t *testing.T) {
	w, v, registry := flatFixtureVerifier(t)
	opts := ReceiptOpts{Type: 2, TxIndex: 3, FillerLogs: 1,
		MutReceipt: func(receipt *RawReceipt) { receipt.Logs[0].Data = bytes.Repeat([]byte{0xaa}, 48_000) }}
	d, _ := flatFixtureRootWithReceipt(t, w, v, 100, Key("flat-cap-root"), opts)
	token := flatFixtureReturn(t, w, v, d, 7)
	raw, records := flatFixtureEncode(t, v, []flatFixtureLevel{{nil, token}})
	j, err := DecodeReceiptBacking(token.Mint.Justification)
	require.NoError(t, err)
	leaf := j.Proof.Nodes[len(j.Proof.Nodes)-1]
	require.Greater(t, len(leaf), 48_000)
	require.LessOrEqual(t, len(leaf), MaxReceiptLeafNodeLen)
	verdict, err := v.VerifyFlatReturn(raw)
	require.NoError(t, err)
	trace, done := flatFixtureRun(t, w, v, raw, records, 1)
	require.Equal(t, verdict.ABI(), done.Verdict.ABI())
	flatFixtureExports(t, "capped-root", w, v, registry, raw, verdict.ABI(), trace)
	j.Proof.Nodes[len(j.Proof.Nodes)-1] = make([]byte, MaxReceiptLeafNodeLen+1)
	_, err = DecodeDepositProof(j.Proof.Bytes())
	require.ErrorIs(t, err, ErrInputTooLarge)
}

func TestFlatSharedClaimsAndAuthorityVariants(t *testing.T) {
	w, v, registry := flatFixtureVerifier(t)
	w.Agg.PDRs = []*types.PartitionDescriptionRecord{FixturePDR(DevNetwork, DevAggPartition, types.ShardID{}, 0, "flat-batch")}
	levels := flatFixtureLineage(t, w, v, 3, 0, false)
	tok := levels[0].token
	proofs := append([]*InclusionProof{&tok.MintProof}, ptrs(tok.Proofs)...)
	var leaves []Leaf
	for _, p := range proofs {
		leaves = append(leaves, Leaf{StateID(p.CD.Source, p.CD.SourceHash), LeafValue(p.CD.TxHash, p.T)})
	}
	view, err := w.Agg.Certify(leaves, CertOpts{IRTime: DevTime + 10_000})
	require.NoError(t, err)
	for i, p := range proofs {
		p.UC, p.Bitmap, p.Siblings = view[i].UC, view[i].Bitmap, view[i].Siblings
	}
	raw, records := flatFixtureEncode(t, v, levels)
	whole, err := v.VerifyFlatReturn(raw)
	require.NoError(t, err)
	mixed, complete := flatFixtureRun(t, w, v, raw, records, 3)
	require.Equal(t, whole.ABI(), complete.Verdict.ABI())
	first, err := DecodeFlatRun(mixed[0].Payload)
	require.NoError(t, err)
	require.True(t, first.Operations[1].Claims[0].Reuse)
	second, err := DecodeFlatRun(mixed[1].Payload)
	require.NoError(t, err)
	require.True(t, second.Operations[0].Claims[0].Present)
	require.False(t, second.Operations[0].Claims[0].Reuse)
	flatFixtureExports(t, "shared-claim", w, v, registry, raw, whole.ABI(), mixed)

	older, err := decodeUC(proofs[len(proofs)-1].UC)
	require.NoError(t, err)
	older.UnicitySeal.Signatures["unsigned-fixture-extra"] = make([]byte, 65)
	proofs[len(proofs)-1].UC, err = types.Cbor.Marshal(older)
	require.NoError(t, err)
	alt, records := flatFixtureEncode(t, v, levels)
	require.NotEqual(t, v.Session(mustFlatEvidence(t, raw).Header()), v.Session(mustFlatEvidence(t, alt).Header()))
	target, err := v.VerifyFlatReturn(alt)
	require.NoError(t, err)
	require.Equal(t, whole.ABI(), target.ABI())
	mixed, complete = flatFixtureRun(t, w, v, alt, records, 2)
	require.Equal(t, whole.ABI(), complete.Verdict.ABI())
	flatFixtureExports(t, "alternate-certificate", w, v, registry, alt, whole.ABI(), mixed)

	// Re-presenting an equivalent deposit certificate changes signed root bytes.
	j, err := DecodeReceiptBacking(tok.Mint.Justification)
	require.NoError(t, err)
	cert, err := decodeUC(j.Proof.UC)
	require.NoError(t, err)
	cert.UnicitySeal.Signatures["unsigned-fixture-extra"] = make([]byte, 65)
	j.Proof.UC, err = types.Cbor.Marshal(cert)
	require.NoError(t, err)
	tok.Mint.Justification = j.Bytes()
	tok.mintRaw = tok.Mint.Bytes()
	modified, _ := flatFixtureEncode(t, v, levels)
	_, err = v.VerifyFlatReturn(modified)
	require.ErrorIs(t, err, ErrCDMismatch)
}

func TestFlatAuthenticatedOriginAndMissingAuthority(t *testing.T) {
	w, v, registry := flatFixtureVerifier(t)
	raw, _ := flatFixtureEncode(t, v, flatFixtureLineage(t, w, v, 12, 0, false))
	for _, tc := range []struct {
		name string
		edit func(b1ref.Words)
		want error
	}{
		{"future-origin-round", func(r b1ref.Words) { r[b1ref.FixedSlot("clock.rootRound")] = u256u(1000) }, b1ref.ErrFuture},
		{"missing-rotated-epoch", func(r b1ref.Words) { delete(r, b1ref.EntrySlot(2, 0)) }, b1ref.ErrRegistryMissingEpoch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			words := make(b1ref.Words, len(registry))
			for k, v := range registry {
				words[k] = v
			}
			tc.edit(words)
			check, err := NewFlatVerifier(w.Gamma, v.deployment, FlatAuthority{Registry: words, Pins: v.authority.Pins})
			require.NoError(t, err)
			_, err = check.VerifyFlatReturn(raw)
			require.ErrorIs(t, err, tc.want, fmt.Sprintf("registry mutation %s", tc.name))
		})
	}
}

func TestFlatLargeCombinedWitnesses(t *testing.T) {
	w, v, registry := flatFixtureVerifier(t)
	w.Agg.PDRs = []*types.PartitionDescriptionRecord{FixturePDR(DevNetwork, DevAggPartition, types.ShardID{}, 0, "flat-max-path")}
	largeReceipt := ReceiptOpts{Type: 2, TxIndex: 3, FillerLogs: 1, MutReceipt: func(r *RawReceipt) {
		r.Logs[0].Data = bytes.Repeat([]byte{0xa5}, 48_000)
	}}
	parent, _ := flatFixtureRootWithReceipt(t, w, v, 257, Key("flat-full-proof-root"), largeReceipt)
	parentID := TokenID(parent.Mint.Salt, parent.Mint.Network)
	key := Key("flat-full-proof-child")
	mint := MintTx{Network: v.cfg.Network, Type: v.cfg.Ty, Recipient: sigPred(key), Salt: HU([]byte("flat-full-proof-salt")),
		Data: ValueData(v.cfg.Aid, big.NewInt(1))}
	id := TokenID(mint.Salt, mint.Network)
	allocation := []SumLeaf{{Key: id, Data: FlatOutput(parentID, &mint), Value: big.NewInt(1)}}
	for i := range 256 {
		sibling := id
		sibling[i/8] ^= byte(0x80) >> uint(i%8)
		allocation = append(allocation, SumLeaf{Key: sibling, Data: HU(sibling[:]), Value: big.NewInt(1)})
	}
	tree, err := BuildSumTree(allocation)
	require.NoError(t, err)
	sumProof, ok := tree.Proof(id)
	require.True(t, ok)
	require.Len(t, sumProof, 256)
	m := SplitManifest{tree.Root()}
	data := m.Bytes()
	parent.Transfers = append(parent.Transfers, TransferTx{Recipient: BurnPredicate(HU(data)), Mask: HU([]byte("flat-full-proof-burn")), Data: data})
	root, err := w.Finalize(parent)
	require.NoError(t, err)
	split := root.Proofs[0].CD
	link := FlatParentLink(v.domain, parentID, StateID(split.Source, split.SourceHash), split.TxHash, m.Root, u256u(257))
	mint.Justification = FlatChildReason(link)
	child := flatFixtureReturn(t, w, v, &Draft{Mint: mint, Owners: []*secp256k1.PrivateKey{key}}, 7)
	p := &child.MintProof
	sid := StateID(p.CD.Source, p.CD.SourceHash)
	leaves := []Leaf{{SID: sid, Value: LeafValue(p.CD.TxHash, p.T)}}
	for i := range 256 {
		sibling := sid
		sibling[i/8] ^= byte(0x80) >> uint(i%8)
		leaves = append(leaves, Leaf{SID: sibling, Value: HU(sibling[:])})
	}
	proofs, err := w.Agg.Certify(leaves, CertOpts{IRTime: DevTime + 10_000})
	require.NoError(t, err)
	require.Len(t, proofs[0].Siblings, 256)
	p.UC, p.Bitmap, p.Siblings = proofs[0].UC, proofs[0].Bitmap, proofs[0].Siblings
	raw, records := flatFixtureEncode(t, v, []flatFixtureLevel{{nil, root}, {sumProof.Bytes(), child}})
	want, err := v.VerifyFlatReturn(raw)
	require.NoError(t, err)
	e := mustFlatEvidence(t, raw)
	scratch := newFlatFixtureWallet(e)
	var trace []flatFixtureTrace
	var prior *FlatState
	var receipt []byte
	for _, cuts := range [][]flatSourceFixture{records[:2], records[2:]} {
		packet, err := scratch.packet(t, prior, receipt, cuts).Calldata()
		require.NoError(t, err)
		res, err := v.RunFlat(packet)
		require.NoError(t, err)
		log := res.Event.Log(v.deployment.Recovery)
		receipt = flatCertifiedEvent(t, w, v, res.Event, largeReceipt)
		require.Greater(t, len(receipt), 48_000)
		f := flatFixtureTrace{Payload: packet, Topics: cat(log.Topics[0][:], log.Topics[1][:]), Data: log.Data, ResultReceipt: receipt}
		if prior != nil {
			f.OldState = prior.Bytes()
		}
		if res.State != nil {
			f.NewState = res.State.Bytes()
		} else {
			require.Equal(t, want.ABI(), res.Event.Verdict.ABI())
		}
		trace = append(trace, f)
		prior = res.State
	}
	flatFixtureExports(t, "combined-large-receipt-and-paths", w, v, registry, raw, want.ABI(), trace)
	t.Logf("complete packet %d bytes with 256 allocation steps, 256 RSMT siblings and a %d-byte predecessor", len(trace[1].Payload), len(trace[0].ResultReceipt))
}
