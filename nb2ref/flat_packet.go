package nb2ref

import (
	"encoding/binary"
	"math"
)

type FlatClaimOpening struct {
	Reuse   bool
	Present bool
	Old     [32]byte
	Path    FlatSparseOpening
}

func (r *flatReader) claim() (o FlatClaimOpening) {
	switch r.u8() {
	case 0:
		switch r.u8() {
		case 0:
		case 1:
			o.Present, o.Old = true, r.hash()
		default:
			r.err = ErrFlatPacket
		}
		o.Path = r.sparse()
	case 1:
		o.Reuse = true
	default:
		r.err = ErrFlatPacket
	}
	return o
}

func (o FlatClaimOpening) appendTo(out []byte) ([]byte, error) {
	if o.Reuse {
		if o.Present || o.Old != ([32]byte{}) || o.Path.Bitmap != ([32]byte{}) || len(o.Path.Siblings) != 0 {
			return nil, ErrFlatPacket
		}
		return append(out, 1), nil
	}
	if !o.Path.shape() || (!o.Present && o.Old != ([32]byte{})) {
		return nil, ErrFlatPacket
	}
	if o.Present {
		out = append(out, 0, 1)
		out = append(out, o.Old[:]...)
	} else {
		out = append(out, 0, 0)
	}
	return o.Path.appendTo(out), nil
}

type FlatOperation struct {
	Code   FlatOpcode
	SID    FlatSparseOpening
	Claims []FlatClaimOpening
}

func (o FlatOpcode) claimCount() int {
	switch o {
	case FlatRootMint:
		return 2
	case FlatChildMint, FlatTransfer:
		return 1
	default:
		return 0
	}
}

type FlatRunPacket struct {
	Header     FlatHeader
	Prior      *FlatState
	Receipt    []byte
	Pages      []FlatPage
	Operations []FlatOperation
}

func (p FlatRunPacket) Calldata() ([]byte, error) {
	if p.Header.Length < flatPreludeBytes || len(p.Pages) == 0 || len(p.Pages) > FlatMaxPages ||
		len(p.Operations) == 0 || len(p.Operations) > FlatMaxOperations || len(p.Receipt) > FlatMaxReceipt {
		return nil, ErrFlatPacket
	}
	out := p.Header.appendTo(nil)
	if p.Prior == nil {
		if len(p.Receipt) != 0 {
			return nil, ErrFlatPacket
		}
		out = append(out, 0)
	} else {
		out = append(out, 1)
		out = append(out, p.Prior.Bytes()...)
		out = flatBlob(out, p.Receipt)
	}
	out = append(out, byte(len(p.Pages)))
	for _, page := range p.Pages {
		if page.Index >= flatPageCount(p.Header.Length) || len(page.Data) != flatPageLen(p.Header.Length, page.Index) ||
			len(page.Siblings) != flatPageDepth(p.Header.Length) {
			return nil, ErrFlatPacket
		}
		out = binary.BigEndian.AppendUint64(out, page.Index)
		out = append(out, page.Data...)
		for _, sibling := range page.Siblings {
			out = append(out, sibling[:]...)
		}
	}
	out = append(out, byte(len(p.Operations)))
	for _, op := range p.Operations {
		if !op.SID.shape() || op.Code.claimCount() == 0 || op.Code.claimCount() != len(op.Claims) {
			return nil, ErrFlatPacket
		}
		out = op.SID.appendTo(append(out, byte(op.Code)))
		for _, opening := range op.Claims {
			var err error
			out, err = opening.appendTo(out)
			if err != nil {
				return nil, err
			}
		}
	}
	return FlatRun.Calldata(out)
}

func DecodeFlatRun(data []byte) (FlatRunPacket, error) {
	raw, err := FlatRun.DecodeCalldata(data)
	if err != nil {
		return FlatRunPacket{}, err
	}
	r := flatReader{raw: raw}
	p := FlatRunPacket{Header: r.header()}
	switch r.u8() {
	case 0:
	case 1:
		s, err := DecodeFlatState(r.take(FlatStateBytes))
		if err != nil {
			return FlatRunPacket{}, err
		}
		p.Prior, p.Receipt = &s, r.blob(FlatMaxReceipt)
	default:
		return FlatRunPacket{}, ErrFlatPacket
	}
	count := int(r.u8())
	if r.err != nil || count < 1 || count > FlatMaxPages {
		return FlatRunPacket{}, ErrFlatPacket
	}
	depth := flatPageDepth(p.Header.Length)
	for range count {
		index := r.u64()
		if r.err != nil {
			return FlatRunPacket{}, r.err
		}
		if index >= flatPageCount(p.Header.Length) {
			return FlatRunPacket{}, ErrFlatPacket
		}
		page := FlatPage{Index: index, Data: r.take(flatPageLen(p.Header.Length, index))}
		for range depth {
			page.Siblings = append(page.Siblings, r.hash())
		}
		p.Pages = append(p.Pages, page)
	}
	n := int(r.u8())
	if r.err != nil || n < 1 || n > FlatMaxOperations {
		return FlatRunPacket{}, ErrFlatPacket
	}
	for range n {
		op := FlatOperation{Code: FlatOpcode(r.u8())}
		claims := op.Code.claimCount()
		if claims == 0 {
			return FlatRunPacket{}, ErrFlatPacket
		}
		op.SID = r.sparse()
		for range claims {
			op.Claims = append(op.Claims, r.claim())
		}
		p.Operations = append(p.Operations, op)
	}
	if !r.done() {
		return FlatRunPacket{}, ErrFlatPacket
	}
	return p, nil
}

type FlatEventKind uint8

const (
	FlatCompleteEvent FlatEventKind = iota + 1
	FlatGapEvent
	FlatProgressEvent
)

func (kind FlatEventKind) Topic() [32]byte {
	switch kind {
	case FlatCompleteEvent:
		return HE([]byte("NB2Complete11(bytes32,uint64,bytes32,bytes32,uint64,bytes32,address,uint256)"))
	case FlatGapEvent:
		return HE([]byte("NB2Gap11(bytes32,uint64,bytes32,bytes32,uint64,bytes32,address,uint256,uint64,bytes32)"))
	case FlatProgressEvent:
		return HE([]byte("NB2Progress11(bytes32,uint64,bytes32)"))
	default:
		return [32]byte{}
	}
}

type FlatEvent struct {
	Kind        FlatEventKind
	Session     [32]byte
	Seq         uint64
	StateDigest [32]byte
	Verdict     *Verdict
	NextSegment uint64
	Head        [32]byte
}

func (e FlatEvent) Log(emitter [20]byte) RawLog {
	seq := u256u(e.Seq)
	data := seq[:]
	switch e.Kind {
	case FlatProgressEvent:
		data = append(data, e.StateDigest[:]...)
	case FlatCompleteEvent, FlatGapEvent:
		data = append(data, e.Verdict.ABI()...)
		if e.Kind == FlatGapEvent {
			next := u256u(e.NextSegment)
			data = append(data, next[:]...)
			data = append(data, e.Head[:]...)
		}
	}
	return RawLog{Address: emitter, Topics: [][32]byte{e.Kind.Topic(), e.Session}, Data: data}
}

func flatDecodeEvent(log *ReceiptLog, kind FlatEventKind, session [32]byte) (FlatEvent, error) {
	words := 0
	switch kind {
	case FlatProgressEvent:
		words = 2
	case FlatCompleteEvent:
		words = 7
	case FlatGapEvent:
		words = 9
	}
	if words == 0 || len(log.Topics) != 2 || log.Topics[0] != kind.Topic() || log.Topics[1] != session ||
		len(log.Data) != words*32 || !zeroFlat(log.Data[:24]) {
		return FlatEvent{}, ErrFlatPredecessor
	}
	e := FlatEvent{Kind: kind, Session: session, Seq: binary.BigEndian.Uint64(log.Data[24:32])}
	if e.Seq == 0 {
		return FlatEvent{}, ErrFlatPredecessor
	}
	if kind == FlatProgressEvent {
		e.StateDigest = [32]byte(log.Data[32:64])
		return e, nil
	}
	v, ok := decodeVerdictABI(log.Data[32:224])
	if !ok || v.MinSegment > MaxSegment {
		return FlatEvent{}, ErrFlatPredecessor
	}
	e.Verdict = v
	if kind == FlatGapEvent {
		e.NextSegment = binary.BigEndian.Uint64(log.Data[248:256])
		if !zeroFlat(log.Data[224:248]) || e.NextSegment < v.MinSegment || e.NextSegment > MaxSegment {
			return FlatEvent{}, ErrFlatPredecessor
		}
		e.Head = [32]byte(log.Data[256:])
	}
	return e, nil
}

type FlatGapPacket struct {
	Header    FlatHeader
	Kind      FlatEventKind
	Receipt   []byte
	StartHead *[32]byte
	Proofs    [][]byte
}

func (p FlatGapPacket) Calldata(entry FlatEntry, k uint64) ([]byte, error) {
	n := len(p.Proofs)
	if p.Header.Length < flatPreludeBytes || (entry != FlatAdvanceGaps && entry != FlatRedeemRecovered) ||
		(p.Kind != FlatCompleteEvent && p.Kind != FlatGapEvent) || len(p.Receipt) > FlatMaxReceipt ||
		n > FlatMaxGaps || (entry == FlatAdvanceGaps && n == 0) ||
		(p.StartHead != nil) != (p.Kind == FlatCompleteEvent && n > 0) {
		return nil, ErrFlatPacket
	}
	out := append(p.Header.appendTo(nil), byte(p.Kind))
	out = flatBlob(out, p.Receipt)
	out = binary.BigEndian.AppendUint16(out, uint16(n))
	if p.StartHead != nil {
		out = append(out, p.StartHead[:]...)
	}
	for _, proof := range p.Proofs {
		if len(proof) != GapProofLen(k) {
			return nil, ErrFlatPacket
		}
		out = append(out, proof...)
	}
	return entry.Calldata(out)
}

func DecodeFlatGap(data []byte, entry FlatEntry, k uint64) (FlatGapPacket, error) {
	if entry != FlatAdvanceGaps && entry != FlatRedeemRecovered {
		return FlatGapPacket{}, ErrFlatPacket
	}
	raw, err := entry.DecodeCalldata(data)
	if err != nil {
		return FlatGapPacket{}, err
	}
	r := flatReader{raw: raw}
	p := FlatGapPacket{Header: r.header(), Kind: FlatEventKind(r.u8()), Receipt: r.blob(FlatMaxReceipt)}
	n := int(r.u16())
	if r.err != nil || n > FlatMaxGaps || (entry == FlatAdvanceGaps && n == 0) ||
		(p.Kind != FlatCompleteEvent && p.Kind != FlatGapEvent) {
		return FlatGapPacket{}, ErrFlatPacket
	}
	if p.Kind == FlatCompleteEvent && n != 0 {
		head := r.hash()
		p.StartHead = &head
	}
	for range n {
		p.Proofs = append(p.Proofs, r.take(GapProofLen(k)))
	}
	if !r.done() {
		return FlatGapPacket{}, ErrFlatPacket
	}
	return p, nil
}

func flatNextSeq(n uint64) (uint64, error) {
	if n == math.MaxUint64 {
		return 0, ErrFlatStep
	}
	return n + 1, nil
}
