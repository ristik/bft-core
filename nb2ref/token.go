package nb2ref

import (
	"math/bits"
)

// The SDK token wire (protocol/interop.md "SDK wire", unchanged), from bridgeprofile/token.go and sdktoken.go:
//
//	P     = tag(39032, [1, b(encode_uint(type)), b(params)])
//	M     = tag(39041, [2, network, P0, b(salt32), b(ty32), b(J), b(data), e])
//	T     = tag(39045, [2, Pnext, b(mask32), dataOrNull, e])
//	CD    = tag(39031, [2, Psource, b(sourceHash32), b(txHash32), e, b(unlock65)])
//	Token = tag(39040, [2, [M, proof0], [[T1, proof1], ...]])
//	proof = tag(39033, [1, CD, t, b(bitmap32 || siblings32...), UC])
//
// Decoding fails with the 14.1 encoding rules; a predicate outside the profile is Predicate.

// Predicate is an encoded predicate.
type Predicate struct {
	Type   uint64
	Params []byte
}

// Bytes is the exact tagged encoding; the code byte string is the CBOR uint of the type (01 or 02).
func (p Predicate) Bytes() []byte {
	return CTag(TagPredicate, CArr(CUint(EngineBuiltIn), CBytes(CUint(p.Type)), CBytes(p.Params)))
}

// SignaturePredicate locks a state to a compressed key.
func SignaturePredicate(key33 []byte) Predicate { return Predicate{PredSignature, key33} }

// BurnPredicate locks a state permanently to a 32-byte reason hash.
func BurnPredicate(reasonHash [32]byte) Predicate { return Predicate{PredBurn, reasonHash[:]} }

func decodePredicate(it *item) (Predicate, error) {
	c, err := it.tagContent(TagPredicate)
	if err != nil {
		return Predicate{}, err
	}
	if err := c.array(3); err != nil {
		return Predicate{}, err
	}
	if !c.kids[0].isUint() || !c.kids[1].isBytes() || !c.kids[2].isBytes() {
		return Predicate{}, ErrShape
	}
	if c.kids[0].arg != EngineBuiltIn {
		return Predicate{}, ErrPredicate
	}
	code := c.kids[1].data
	if len(code) != 1 || (code[0] != PredSignature && code[0] != PredBurn) {
		return Predicate{}, ErrPredicate
	}
	p := Predicate{Type: uint64(code[0]), Params: c.kids[2].data}
	switch p.Type {
	case PredSignature:
		if _, err := ParseKey(p.Params); err != nil {
			return Predicate{}, err
		}
	case PredBurn:
		if len(p.Params) != 32 {
			return Predicate{}, ErrPredicate
		}
	}
	return p, nil
}

// MintTx is a mint transaction.
type MintTx struct {
	Network       uint16
	Recipient     Predicate
	Salt, Type    [32]byte
	Justification []byte
	Data          []byte
	Deadline      Deadline
}

// Bytes is the exact encoding.
func (m *MintTx) Bytes() []byte {
	return CTag(TagMint, CArr(CUint(TxVersion), CUint(uint64(m.Network)), m.Recipient.Bytes(),
		CBytes(m.Salt[:]), CBytes(m.Type[:]), CNullOr(m.Justification), CNullOr(m.Data), CDeadline(m.Deadline)))
}

// TransferTx is a transfer; its source is reconstructed, never on the wire.
type TransferTx struct {
	Recipient Predicate
	Mask      [32]byte
	Data      []byte // nil is null
	Deadline  Deadline
}

// Bytes is the exact encoding.
func (t *TransferTx) Bytes() []byte {
	return CTag(TagTransfer, CArr(CUint(TxVersion), t.Recipient.Bytes(), CBytes(t.Mask[:]), CNullOr(t.Data), CDeadline(t.Deadline)))
}

// Certification is CD.
type Certification struct {
	Source     Predicate
	SourceHash [32]byte
	TxHash     [32]byte
	Deadline   Deadline
	Unlock     []byte
}

// Bytes is the exact encoding.
func (c *Certification) Bytes() []byte {
	return CTag(TagCertification, CArr(CUint(CertVersion), c.Source.Bytes(), CBytes(c.SourceHash[:]),
		CBytes(c.TxHash[:]), CDeadline(c.Deadline), CBytes(c.Unlock)))
}

// InclusionProof is a certified inclusion proof.
type InclusionProof struct {
	CD       Certification
	T        uint64
	Bitmap   [32]byte
	Siblings [][32]byte
	UC       []byte // the canonical native UnicityCertificate, an inline item
}

// Bytes is the exact encoding.
func (p *InclusionProof) Bytes() []byte {
	path := append([]byte{}, p.Bitmap[:]...)
	for _, s := range p.Siblings {
		path = append(path, s[:]...)
	}
	return CTag(TagInclusion, CArr(CUint(InclusionVersion), p.CD.Bytes(), CUint(p.T), CBytes(path), p.UC))
}

// Token is an SDK token.
type Token struct {
	Mint      MintTx
	MintProof InclusionProof
	Transfers []TransferTx
	Proofs    []InclusionProof

	mintRaw      []byte
	transfersRaw [][]byte
}

// Bytes is the exact encoding. The transactions are written from their exact bytes (as decoded or as signed), so a vector
// can carry a transaction encoding the structs cannot express.
func (t *Token) Bytes() []byte {
	mint := t.mintRaw
	if mint == nil {
		mint = t.Mint.Bytes()
	}
	pairs := make([][]byte, len(t.Transfers))
	for i := range t.Transfers {
		raw := t.Transfers[i].Bytes()
		if i < len(t.transfersRaw) && t.transfersRaw[i] != nil {
			raw = t.transfersRaw[i]
		}
		pairs[i] = CArr(raw, t.Proofs[i].Bytes())
	}
	return CTag(TagToken, CArr(CUint(TokenVersion), CArr(mint, t.MintProof.Bytes()), CArr(pairs...)))
}

// DecodeToken strictly decodes a token from its exact bytes.
func DecodeToken(b []byte) (*Token, error) {
	it, err := scanNative(b)
	if err != nil {
		return nil, err
	}
	return decodeTokenItem(it, b)
}

func decodeTokenItem(it *item, b []byte) (*Token, error) {
	c, err := it.tagContent(TagToken)
	if err != nil {
		return nil, err
	}
	if err := c.array(3); err != nil {
		return nil, err
	}
	if err := c.kids[0].version(TokenVersion); err != nil {
		return nil, err
	}
	g := &c.kids[1]
	if err := g.array(2); err != nil {
		return nil, err
	}
	if c.kids[2].major != majArray {
		return nil, ErrShape
	}
	t := &Token{}
	if err := decodeMint(&g.kids[0], &t.Mint); err != nil {
		return nil, err
	}
	t.mintRaw = g.kids[0].raw(b)
	mp, err := decodeProof(&g.kids[1], b)
	if err != nil {
		return nil, err
	}
	t.MintProof = *mp
	for i := range c.kids[2].kids {
		p := &c.kids[2].kids[i]
		if err := p.array(2); err != nil {
			return nil, err
		}
		var tx TransferTx
		if err := decodeTransfer(&p.kids[0], &tx); err != nil {
			return nil, err
		}
		pr, err := decodeProof(&p.kids[1], b)
		if err != nil {
			return nil, err
		}
		t.Transfers = append(t.Transfers, tx)
		t.Proofs = append(t.Proofs, *pr)
		t.transfersRaw = append(t.transfersRaw, p.kids[0].raw(b))
	}
	return t, nil
}

func decodeMint(it *item, m *MintTx) error {
	c, err := it.tagContent(TagMint)
	if err != nil {
		return err
	}
	if err := c.array(8); err != nil {
		return err
	}
	k := c.kids
	if err := k[0].version(TxVersion); err != nil {
		return err
	}
	nw, err := k[1].uintIn(1, 65535)
	if err != nil {
		return err
	}
	m.Network = uint16(nw)
	if m.Recipient, err = decodePredicate(&k[2]); err != nil {
		return err
	}
	if err := k[3].fixed(m.Salt[:]); err != nil {
		return err
	}
	if err := k[4].fixed(m.Type[:]); err != nil {
		return err
	}
	if m.Justification, err = nullableBytes(&k[5]); err != nil {
		return err
	}
	if m.Data, err = nullableBytes(&k[6]); err != nil {
		return err
	}
	m.Deadline, err = k[7].deadline()
	return err
}

func decodeTransfer(it *item, t *TransferTx) error {
	c, err := it.tagContent(TagTransfer)
	if err != nil {
		return err
	}
	if err := c.array(5); err != nil {
		return err
	}
	k := c.kids
	if err := k[0].version(TxVersion); err != nil {
		return err
	}
	if t.Recipient, err = decodePredicate(&k[1]); err != nil {
		return err
	}
	if err := k[2].fixed(t.Mask[:]); err != nil {
		return err
	}
	if t.Data, err = nullableBytes(&k[3]); err != nil {
		return err
	}
	t.Deadline, err = k[4].deadline()
	return err
}

func decodeCD(it *item) (*Certification, error) {
	c, err := it.tagContent(TagCertification)
	if err != nil {
		return nil, err
	}
	if err := c.array(6); err != nil {
		return nil, err
	}
	if err := c.kids[0].version(CertVersion); err != nil {
		return nil, err
	}
	var cd Certification
	if cd.Source, err = decodePredicate(&c.kids[1]); err != nil {
		return nil, err
	}
	if err := c.kids[2].fixed(cd.SourceHash[:]); err != nil {
		return nil, err
	}
	if err := c.kids[3].fixed(cd.TxHash[:]); err != nil {
		return nil, err
	}
	if cd.Deadline, err = c.kids[4].deadline(); err != nil {
		return nil, err
	}
	if cd.Unlock, err = c.kids[5].bstr(); err != nil {
		return nil, err
	}
	return &cd, nil
}

func decodeProof(it *item, b []byte) (*InclusionProof, error) {
	c, err := it.tagContent(TagInclusion)
	if err != nil {
		return nil, err
	}
	if err := c.array(5); err != nil {
		return nil, err
	}
	k := c.kids
	if err := k[0].version(InclusionVersion); err != nil {
		return nil, err
	}
	cd, err := decodeCD(&k[1])
	if err != nil {
		return nil, err
	}
	p := &InclusionProof{CD: *cd}
	if p.T, err = k[2].uintIn(0, ^uint64(0)); err != nil {
		return nil, err
	}
	path, err := k[3].bstr()
	if err != nil {
		return nil, err
	}
	if len(path) < 32 || len(path)%32 != 0 {
		return nil, ErrLength
	}
	copy(p.Bitmap[:], path[:32])
	pop := 0
	for _, x := range p.Bitmap {
		pop += bits.OnesCount8(x)
	}
	if len(path) != 32+32*pop {
		return nil, ErrLength
	}
	for i := 0; i < pop; i++ {
		var s [32]byte
		copy(s[:], path[32+32*i:])
		p.Siblings = append(p.Siblings, s)
	}
	if k[4].major != majTag {
		return nil, ErrShape
	}
	if k[4].end-k[4].start > maxProofUCBytes {
		return nil, ErrInputTooLarge
	}
	p.UC = k[4].raw(b)
	return p, nil
}

// maxProofUCBytes bounds an aggregator certificate (the native scan's own bound).
const maxProofUCBytes = 24 << 10

// StateID is sid = H(C(Psource, b(sourceHash32))).
func StateID(source Predicate, sourceHash [32]byte) [32]byte {
	return HU(CArr(source.Bytes(), CBytes(sourceHash[:])))
}

// ResultState is the output state H(C(b(I(sourceHash)), b(mask))); a mint's mask is the token ID.
func ResultState(sourceHash [32]byte, mask []byte) [32]byte {
	return HU(CArr(CBytes(Imprint(sourceHash)), CBytes(mask)))
}

// LeafValue is v = H(C(b(txHash32), t)).
func LeafValue(txHash [32]byte, t uint64) [32]byte { return HU(CArr(CBytes(txHash[:]), CUint(t))) }

// TokenID is id = H(C(b(salt), network)).
func TokenID(salt [32]byte, network uint16) [32]byte {
	return HU(CArr(CBytes(salt[:]), CUint(uint64(network))))
}

var tokenIDSuffix = HU([]byte("TOKENID"))

// MintSourceHash is h0 = H(C(b(id), b(H("TOKENID")))).
func MintSourceHash(id [32]byte) [32]byte { return HU(CArr(CBytes(id[:]), CBytes(tokenIDSuffix[:]))) }

// ValueData is tag(39050, [1, [[b(aid32), b(v)]], null]).
func ValueData(aid [32]byte, v interface{ Bytes() []byte }) []byte {
	return CTag(TagValue, CArr(CUint(ValueVersion), CArr(CArr(CBytes(aid[:]), CBytes(v.Bytes()))), CNull))
}
