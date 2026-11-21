package nb2ref

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func flatRecordRefusal(t *testing.T, name string, data []byte, stage string, prior []byte) {
	t.Helper()
	dir := os.Getenv("NB2_FLAT_VECTOR_OUT")
	if dir == "" {
		return
	}
	dir = filepath.Join(dir, "refusals", name)
	require.NoError(t, os.MkdirAll(dir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "calldata.bin"), data, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "stage.txt"), []byte(stage+"\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "last-usable-predecessor.cbor"), prior, 0644))
}

func TestFlatPacketRefusalOrderAndRetry(t *testing.T) {
	w, v, _ := flatFixtureVerifier(t)
	evidence, records := flatFixtureEncode(t, v, flatFixtureLineage(t, w, v, 6, 0, false))
	e := mustFlatEvidence(t, evidence)
	wallet := newFlatFixtureWallet(e)
	start := wallet.packet(t, nil, nil, records[:1])
	startBytes, err := start.Calldata()
	require.NoError(t, err)
	progress, err := v.RunFlat(startBytes)
	require.NoError(t, err)
	prior := flatCertifiedEvent(t, w, v, progress.Event, ReceiptOpts{Type: 2})
	resume := wallet.packet(t, progress.State, prior, records[1:])
	data, err := resume.Calldata()
	require.NoError(t, err)
	require.Greater(t, len(resume.Pages), 1)
	refuse := func(name string, data []byte, want error, stage string) {
		t.Helper()
		r, err := v.RunFlat(data)
		require.Nil(t, r, name)
		require.ErrorIs(t, err, want, name)
		flatRecordRefusal(t, name, data, stage, prior)
	}

	raw, err := FlatRun.DecodeCalldata(data)
	require.NoError(t, err)
	firstPage := 42 + 1 + FlatStateBytes + 4 + len(prior) + 1
	receiptAt := 42 + 1 + FlatStateBytes + 4
	badReceipt := func(b []byte) { b[receiptAt] ^= 0xff }

	mut := bytes.Clone(raw)
	badReceipt(mut)
	binary.BigEndian.PutUint64(mut[firstPage:], flatPageCount(e.Header().Length))
	wire, err := FlatRun.Calldata(mut)
	require.NoError(t, err)
	refuse("out-of-range-index-before-predecessor", wire, ErrFlatPacket, "BadPacket")
	wire, err = FlatRun.Calldata(mut[:firstPage+7])
	require.NoError(t, err)
	refuse("truncated-page-index", wire, ErrFlatPacket, "BadPacket")

	p := resume
	p.Pages = append([]FlatPage(nil), resume.Pages...)
	p.Pages[0], p.Pages[1] = p.Pages[1], p.Pages[0]
	wire, err = p.Calldata()
	require.NoError(t, err)
	refuse("unordered-pages", wire, ErrFlatPage, "BadPage")
	rawUnordered, err := FlatRun.DecodeCalldata(wire)
	require.NoError(t, err)
	rawUnordered = bytes.Clone(rawUnordered)
	badReceipt(rawUnordered)
	wire, err = FlatRun.Calldata(rawUnordered)
	require.NoError(t, err)
	refuse("bad-predecessor-before-page-order", wire, ErrFlatPredecessor, "BadPredecessor")
	wire, err = FlatRun.Calldata(append(rawUnordered, 0))
	require.NoError(t, err)
	refuse("bad-suffix-before-predecessor", wire, ErrFlatPacket, "BadPacket")

	p = resume
	p.Pages = resume.Pages[:len(resume.Pages)-1]
	wire, err = p.Calldata()
	require.NoError(t, err)
	refuse("missing-page", wire, ErrFlatPage, "BadPage")
	p = resume
	p.Operations = append([]FlatOperation(nil), resume.Operations...)
	p.Operations[len(p.Operations)-1].SID.Siblings = append([][32]byte(nil), p.Operations[len(p.Operations)-1].SID.Siblings...)
	p.Operations[len(p.Operations)-1].SID.Siblings[0][0] ^= 1
	wire, err = p.Calldata()
	require.NoError(t, err)
	refuse("last-sparse-opening-atomic", wire, ErrFlatStep, "BadStep")
	p = resume
	p.Operations = append(append([]FlatOperation(nil), resume.Operations...), resume.Operations[0])
	wire, err = p.Calldata()
	require.NoError(t, err)
	refuse("declared-op-after-complete", wire, ErrFlatStep, "BadStep")
	p = resume
	p.Operations = append([]FlatOperation(nil), resume.Operations...)
	p.Operations[0].Code = FlatChildMint
	wire, err = p.Calldata()
	require.NoError(t, err)
	refuse("wrong-known-opcode", wire, ErrFlatStep, "BadStep")

	h := FlatHeader{Length: 4097}
	wire, err = FlatRun.Calldata(append(append(h.appendTo(nil), 0, 1), flatU64(2)...))
	require.NoError(t, err)
	refuse("4097-padding-is-not-a-page", wire, ErrFlatPacket, "BadPacket")

	badPredecessors := []struct {
		name   string
		change func(e *FlatEvent, o *ReceiptOpts)
	}{
		{"wrong-seq", func(e *FlatEvent, o *ReceiptOpts) { e.Seq++ }},
		{"wrong-state", func(e *FlatEvent, o *ReceiptOpts) { e.StateDigest[0] ^= 1 }},
		{"wrong-session", func(e *FlatEvent, o *ReceiptOpts) { e.Session[0] ^= 1 }},
		{"wrong-emitter", func(e *FlatEvent, o *ReceiptOpts) { o.MutLog = func(log *RawLog) { log.Address[0] ^= 1 } }},
		{"wrong-log-index", func(e *FlatEvent, o *ReceiptOpts) { o.MutProof = func(p *DepositProof) { p.LogIndex++ } }},
		{"bad-header", func(e *FlatEvent, o *ReceiptOpts) {
			o.MutProof = func(p *DepositProof) { p.Header[len(p.Header)-1] ^= 1 }
		}},
		{"bad-receipt-path", func(e *FlatEvent, o *ReceiptOpts) { o.MutProof = func(p *DepositProof) { p.Nodes[0][0] ^= 1 } }},
		{"failed-receipt", func(e *FlatEvent, o *ReceiptOpts) { o.MutReceipt = func(r *RawReceipt) { r.Status = nil } }},
	}
	for _, bad := range badPredecessors {
		out, opts := progress.Event, ReceiptOpts{Type: 2}
		bad.change(&out, &opts)
		p := resume
		p.Receipt = flatCertifiedEvent(t, w, v, out, opts)
		wire, err := p.Calldata()
		require.NoError(t, err)
		refuse(bad.name, wire, ErrFlatPredecessor, "BadPredecessor")
	}

	fresh := resume
	fresh.Receipt = flatCertifiedEvent(t, w, v, progress.Event, ReceiptOpts{Type: 2, Rotated: true, TxIndex: 2})
	wire, err = fresh.Calldata()
	require.NoError(t, err)
	a, err := v.RunFlat(wire)
	require.NoError(t, err)
	b, err := v.RunFlat(data)
	require.NoError(t, err)
	require.Equal(t, a.Event.Verdict.ABI(), b.Event.Verdict.ABI())
}

func TestFlatPageProofAndTransportBoundaries(t *testing.T) {
	for _, length := range []int{4095, 4096, 4097, 3*4096 + 1} {
		e := mustFlatEvidence(t, bytes.Repeat([]byte{1}, length))
		for i := range flatPageCount(e.Header().Length) {
			page, err := e.Page(i)
			require.NoError(t, err)
			require.True(t, page.verifies(e.Header()))
		}
	}
	max := FlatMaxCalldata - 68
	max -= max % 32
	wire, err := FlatRun.Calldata(make([]byte, max))
	require.NoError(t, err)
	require.LessOrEqual(t, len(wire), FlatMaxCalldata)
	_, err = FlatRun.DecodeCalldata(wire)
	require.NoError(t, err)
	_, err = FlatRun.Calldata(make([]byte, max+1))
	require.ErrorIs(t, err, ErrFlatPacket)
	wire, err = FlatRun.Calldata([]byte{1})
	require.NoError(t, err)
	wire[len(wire)-1] = 1
	_, err = FlatRun.DecodeCalldata(wire)
	require.ErrorIs(t, err, ErrFlatPacket)
	require.Equal(t, 52, flatPageDepth(math.MaxUint64))
	_, err = flatGapEnd(MaxSegment, 1)
	require.ErrorIs(t, err, ErrFlatStep)
	_, err = flatNextSeq(math.MaxUint64)
	require.ErrorIs(t, err, ErrFlatStep)
}

func TestFlatSparseConflictsAcrossCuts(t *testing.T) {
	key, a, b := [32]byte{1}, [32]byte{2}, [32]byte{3}
	first := flatPacketClaims{root: flatSparseDefaults[flatClaimTree][256], cache: map[[32]byte][32]byte{}}
	require.NoError(t, first.apply(flatClaim{key: key, value: a}, FlatClaimOpening{}))
	require.NoError(t, first.apply(flatClaim{key: key, value: a}, FlatClaimOpening{Reuse: true}))
	require.ErrorIs(t, first.apply(flatClaim{key: key, value: b}, FlatClaimOpening{Reuse: true}), ErrFlatStep)
	second := flatPacketClaims{root: first.root, cache: map[[32]byte][32]byte{}}
	require.ErrorIs(t, second.apply(flatClaim{key: key, value: b}, FlatClaimOpening{Present: true, Old: a}), ErrFlatStep)
	require.NoError(t, second.apply(flatClaim{key: key, value: a}, FlatClaimOpening{Present: true, Old: a}))
	require.Equal(t, first.root, second.root)
	require.Len(t, second.batch, 1, "persistent claims still require native verification")
	root := flatSparseDefaults[flatSIDTree][256]
	root, err := flatSIDTree.update(root, key, [32]byte{}, flatSIDLeaf(key), FlatSparseOpening{})
	require.NoError(t, err)
	_, err = flatSIDTree.update(root, key, [32]byte{}, flatSIDLeaf(key), FlatSparseOpening{})
	require.True(t, errors.Is(err, ErrFlatStep))
}
