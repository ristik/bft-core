package bridgeprofile

import "math/bits"

// This file is the oracle's strict SDK 3.0.1 token codec: the whole token
// tag(39040,[2,[M,proof0],[[T1,proof1],...]]) and the inclusion proof
// tag(39033,[1,CD,t,b(bitmap32||siblings32...),UC]). It is not part of the
// kernel relation, which sees only the projection (History). The projection
// tuples [M,CD,t] are not SDK certified-transaction tuples: a certified
// transaction is exactly [tx,proof], and there is no separate reference-time
// slot in the token.

// InclusionProof is a certified inclusion proof. Pending or non-certified
// aggregator responses are not proofs and have no encoding here.
type InclusionProof struct {
	CD       Certification
	T        uint64 // reference time; part of the certified leaf, never a UC timestamp
	Bitmap   [32]byte
	Siblings [][32]byte
	UC       []byte // the canonical native UnicityCertificate, an inline CBOR item
}

// pathBytes is bitmap || siblings.
func (p *InclusionProof) pathBytes() []byte {
	out := append([]byte{}, p.Bitmap[:]...)
	for _, s := range p.Siblings {
		out = append(out, s[:]...)
	}
	return out
}

// Bytes is the exact encoding of the inclusion proof.
func (p *InclusionProof) Bytes() []byte {
	return CTag(TagInclusion, CArr(CUint(InclusionVersion), p.CD.Bytes(), CUint(p.T), CBytes(p.pathBytes()), p.UC))
}

// Token is a decoded SDK token: a mint, its proof and certified transfers.
type Token struct {
	Mint      MintTx
	MintProof InclusionProof
	Transfers []TransferTx
	Proofs    []InclusionProof

	mintRaw      []byte
	transfersRaw [][]byte
}

// Bytes is the exact encoding of the token.
func (t *Token) Bytes() []byte {
	pairs := make([][]byte, len(t.Transfers))
	for i := range t.Transfers {
		pairs[i] = CArr(t.Transfers[i].Bytes(), t.Proofs[i].Bytes())
	}
	return CTag(TagToken, CArr(CUint(TokenVersion), CArr(t.Mint.Bytes(), t.MintProof.Bytes()), CArr(pairs...)))
}

func decodeProof(it *item, b []byte, steps *uint64) (*InclusionProof, error) {
	c, err := it.tagContent(TagInclusion)
	if err != nil {
		return nil, err
	}
	// Arity 5: version, CD, t, path, UC. All certified-leaf fields mandatory.
	if !c.isArray(5) {
		return nil, ErrShape
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
	if p.T, err = k[2].uintMax(^uint64(0)); err != nil {
		return nil, err
	}
	if !k[3].isBytes() {
		return nil, ErrShape
	}
	path := k[3].data
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
	if *steps += uint64(pop); *steps > MaxPathSteps {
		return nil, ErrTooManyPaths
	}
	for i := 0; i < pop; i++ {
		var s [32]byte
		copy(s[:], path[32+32*i:])
		p.Siblings = append(p.Siblings, s)
	}
	if k[4].end-k[4].start > MaxProofUCBytes {
		return nil, ErrInputTooLarge
	}
	if k[4].major != majTag {
		return nil, ErrShape
	}
	p.UC = k[4].raw(b)
	return p, nil
}

// DecodeToken strictly decodes an entire SDK token. Every proof is mandatory
// and complete; trailing bytes, extra slots and a separate third
// reference-time slot are rejected.
func DecodeToken(b []byte) (*Token, error) {
	if len(b) > MaxTokenBytes {
		return nil, ErrInputTooLarge
	}
	root, err := scanOneNative(b)
	if err != nil {
		return nil, err
	}
	c, err := root.tagContent(TagToken)
	if err != nil {
		return nil, err
	}
	if !c.isArray(3) {
		return nil, ErrShape
	}
	if err := c.kids[0].version(TokenVersion); err != nil {
		return nil, err
	}
	g := &c.kids[1]
	if !g.isArray(2) {
		return nil, ErrShape
	}
	if c.kids[2].major != majArray {
		return nil, ErrShape
	}
	if len(c.kids[2].kids) > MaxTransfers {
		return nil, ErrTooManyTx
	}
	t := &Token{}
	if err := decodeMint(&g.kids[0], b, &t.Mint); err != nil {
		return nil, err
	}
	t.mintRaw = g.kids[0].raw(b)
	var steps uint64
	mp, err := decodeProof(&g.kids[1], b, &steps)
	if err != nil {
		return nil, err
	}
	t.MintProof = *mp
	for i := range c.kids[2].kids {
		p := &c.kids[2].kids[i]
		if !p.isArray(2) {
			return nil, ErrShape
		}
		var tx TransferTx
		if err := decodeTransfer(&p.kids[0], &tx); err != nil {
			return nil, err
		}
		pr, err := decodeProof(&p.kids[1], b, &steps)
		if err != nil {
			return nil, err
		}
		t.Transfers = append(t.Transfers, tx)
		t.Proofs = append(t.Proofs, *pr)
		t.transfersRaw = append(t.transfersRaw, p.kids[0].raw(b))
	}
	return t, nil
}

// Project is the B2 projection of a decoded token: the same tagged
// transactions and CDs, with each t taken solely from its proof.
func (t *Token) Project() *History {
	h := &History{Mint: t.Mint, MintCD: t.MintProof.CD, MintTime: t.MintProof.T, mintRaw: t.mintRaw}
	h.Transfers = append(h.Transfers, t.Transfers...)
	for i := range t.Proofs {
		h.CDs = append(h.CDs, t.Proofs[i].CD)
		h.Times = append(h.Times, t.Proofs[i].T)
	}
	h.transfersRaw = append(h.transfersRaw, t.transfersRaw...)
	return h
}

// ProjectToken strictly decodes the whole SDK token and returns the exact
// projection bytes the kernel consumes.
func ProjectToken(b []byte) ([]byte, error) {
	t, err := DecodeToken(b)
	if err != nil {
		return nil, err
	}
	return t.Project().Bytes(), nil
}

// TokenFromHistory assembles an SDK token from a projection and one proof per
// certified transaction. Each proof's CD and t must be the projection's; the
// builder copies them so the two cannot disagree.
func TokenFromHistory(h *History, proofs []InclusionProof) *Token {
	t := &Token{Mint: h.Mint, Transfers: append([]TransferTx{}, h.Transfers...)}
	for i := range proofs {
		if i == 0 {
			proofs[i].CD, proofs[i].T = h.MintCD, h.MintTime
			t.MintProof = proofs[i]
		} else {
			proofs[i].CD, proofs[i].T = h.CDs[i-1], h.Times[i-1]
			t.Proofs = append(t.Proofs, proofs[i])
		}
	}
	t.mintRaw = h.Mint.Bytes()
	for i := range t.Transfers {
		t.transfersRaw = append(t.transfersRaw, t.Transfers[i].Bytes())
	}
	return t
}
