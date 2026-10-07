package bridgeprofile

import (
	"bytes"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Predicate is the encoded predicate tag(39032,[1,b(encode_uint(type)),b(params)]).
type Predicate struct {
	Type   uint64 // PredSignature or PredBurn
	Params []byte
}

// Bytes is the exact tagged encoding. The code byte string is the CBOR uint of
// the type, so the built-in codes are 01 and 02.
func (p Predicate) Bytes() []byte {
	return CTag(TagPredicate, CArr(CUint(EngineBuiltIn), CBytes(CUint(p.Type)), CBytes(p.Params)))
}

// SignaturePredicate locks a state to a compressed secp256k1 key.
func SignaturePredicate(key33 []byte) Predicate { return Predicate{PredSignature, key33} }

// BurnPredicate locks a state permanently; the profile requires params to be
// exactly 32 bytes H(R).
func BurnPredicate(reasonHash [32]byte) Predicate { return Predicate{PredBurn, reasonHash[:]} }

func decodePredicate(it *item) (Predicate, error) {
	c, err := it.tagContent(TagPredicate)
	if err != nil {
		return Predicate{}, err
	}
	if !c.isArray(3) {
		return Predicate{}, ErrShape
	}
	if !c.kids[0].isUint() {
		return Predicate{}, ErrShape
	}
	if c.kids[0].arg != EngineBuiltIn {
		return Predicate{}, ErrPredicate
	}
	if !c.kids[1].isBytes() || !c.kids[2].isBytes() {
		return Predicate{}, ErrShape
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

// MintTx is a decoded mint
// M = tag(39041,[2,network,P0,b(salt),b(type),b(justification),b(data),e]).
type MintTx struct {
	Network       uint16
	Recipient     Predicate
	Salt, Type    [32]byte
	Justification []byte
	Data          []byte
	Deadline      Deadline
}

// Bytes is the exact encoding of the mint transaction.
func (m *MintTx) Bytes() []byte {
	return CTag(TagMint, CArr(CUint(TxVersion), CUint(uint64(m.Network)), m.Recipient.Bytes(),
		CBytes(m.Salt[:]), CBytes(m.Type[:]), CNullOr(m.Justification), CNullOr(m.Data), CDeadline(m.Deadline)))
}

// TransferTx is a decoded transfer T = tag(39045,[2,Pnext,b(mask32),dataOrNull,e]).
// The source hash and source predicate are reconstructed, never on the wire.
type TransferTx struct {
	Recipient Predicate
	Mask      [32]byte
	Data      []byte // nil means null
	Deadline  Deadline
}

// Bytes is the exact encoding of the transfer transaction.
func (t *TransferTx) Bytes() []byte {
	return CTag(TagTransfer, CArr(CUint(TxVersion), t.Recipient.Bytes(), CBytes(t.Mask[:]), CNullOr(t.Data), CDeadline(t.Deadline)))
}

// Certification is CD = tag(39031,[2,Psource,b(sourceHash32),b(txHash32),e,b(unlock65)]).
// Its deadline sits before the unlock and must equal the transaction's.
type Certification struct {
	Source     Predicate
	SourceHash [32]byte
	TxHash     [32]byte
	Deadline   Deadline
	Unlock     []byte
}

// Bytes is the exact encoding of the certification data.
func (c *Certification) Bytes() []byte {
	return CTag(TagCertification, CArr(CUint(CertVersion), c.Source.Bytes(), CBytes(c.SourceHash[:]),
		CBytes(c.TxHash[:]), CDeadline(c.Deadline), CBytes(c.Unlock)))
}

func decodeCD(it *item) (*Certification, error) {
	c, err := it.tagContent(TagCertification)
	if err != nil {
		return nil, err
	}
	if !c.isArray(6) {
		return nil, ErrShape
	}
	if err := c.kids[0].version(CertVersion); err != nil {
		return nil, err
	}
	var cd Certification
	if cd.Source, err = decodePredicate(&c.kids[1]); err != nil {
		return nil, err
	}
	if err := fixed(&c.kids[2], cd.SourceHash[:]); err != nil {
		return nil, err
	}
	if err := fixed(&c.kids[3], cd.TxHash[:]); err != nil {
		return nil, err
	}
	if cd.Deadline, err = c.kids[4].deadline(); err != nil {
		return nil, err
	}
	if !c.kids[5].isBytes() {
		return nil, ErrShape
	}
	cd.Unlock = c.kids[5].data
	return &cd, nil
}

// History is the compact B2 projection
// C([M,CD0,t0],[[T1,CD1,t1],...]) holding the unchanged tagged transaction and
// CD items and each proof's reference time t. These are projection tuples, not
// SDK certified-transaction tuples. Every t is untrusted until the exported
// leaf value is proven under an admitted root.
type History struct {
	Mint      MintTx
	MintCD    Certification
	MintTime  uint64
	Transfers []TransferTx
	CDs       []Certification
	Times     []uint64

	mintRaw      []byte
	transfersRaw [][]byte
}

// Bytes encodes the history. Decoded histories re-encode to the input.
func (h *History) Bytes() []byte {
	triples := make([][]byte, len(h.Transfers))
	for i := range h.Transfers {
		triples[i] = CArr(h.Transfers[i].Bytes(), h.CDs[i].Bytes(), CUint(h.Times[i]))
	}
	return CArr(CArr(h.Mint.Bytes(), h.MintCD.Bytes(), CUint(h.MintTime)), CArr(triples...))
}

// DecodeHistory strictly decodes a history. Mint and transfer wire fields are
// decoded against the exact literal shapes; reconstructed-source fields are
// checked by the relation, not here. The transfer count is bounded before
// transfers are decoded.
func DecodeHistory(b []byte) (*History, error) {
	if len(b) > MaxSemanticBytes {
		return nil, ErrInputTooLarge
	}
	root, err := scanOne(b)
	if err != nil {
		return nil, err
	}
	if !root.isArray(2) || !root.kids[0].isArray(3) || root.kids[1].major != majArray {
		return nil, ErrShape
	}
	if len(root.kids[1].kids) > MaxTransfers {
		return nil, ErrTooManyTx
	}
	h := &History{}
	m := &root.kids[0]
	if err := decodeMint(&m.kids[0], b, &h.Mint); err != nil {
		return nil, err
	}
	h.mintRaw = m.kids[0].raw(b)
	cd, err := decodeCD(&m.kids[1])
	if err != nil {
		return nil, err
	}
	h.MintCD = *cd
	if h.MintTime, err = m.kids[2].uintMax(^uint64(0)); err != nil {
		return nil, err
	}
	for i := range root.kids[1].kids {
		p := &root.kids[1].kids[i]
		if !p.isArray(3) {
			return nil, ErrShape
		}
		var t TransferTx
		if err := decodeTransfer(&p.kids[0], &t); err != nil {
			return nil, err
		}
		cd, err := decodeCD(&p.kids[1])
		if err != nil {
			return nil, err
		}
		rt, err := p.kids[2].uintMax(^uint64(0))
		if err != nil {
			return nil, err
		}
		h.Transfers = append(h.Transfers, t)
		h.CDs = append(h.CDs, *cd)
		h.Times = append(h.Times, rt)
		h.transfersRaw = append(h.transfersRaw, p.kids[0].raw(b))
	}
	return h, nil
}

func nullableBytes(it *item) ([]byte, error) {
	if it.null {
		return nil, nil
	}
	if !it.isBytes() {
		return nil, ErrShape
	}
	return it.data, nil
}

func decodeMint(it *item, _ []byte, m *MintTx) error {
	c, err := it.tagContent(TagMint)
	if err != nil {
		return err
	}
	if !c.isArray(8) {
		return ErrShape
	}
	k := c.kids
	if err := k[0].version(TxVersion); err != nil {
		return err
	}
	nw, err := k[1].uintMax(0xffff)
	if err != nil {
		return err
	}
	m.Network = uint16(nw)
	if m.Recipient, err = decodePredicate(&k[2]); err != nil {
		return err
	}
	if err := fixed(&k[3], m.Salt[:]); err != nil {
		return err
	}
	if err := fixed(&k[4], m.Type[:]); err != nil {
		return err
	}
	if m.Justification, err = nullableBytes(&k[5]); err != nil {
		return err
	}
	if m.Data, err = nullableBytes(&k[6]); err != nil {
		return err
	}
	if m.Deadline, err = k[7].deadline(); err != nil {
		return err
	}
	return nil
}

func decodeTransfer(it *item, t *TransferTx) error {
	c, err := it.tagContent(TagTransfer)
	if err != nil {
		return err
	}
	if !c.isArray(5) {
		return ErrShape
	}
	k := c.kids
	if err := k[0].version(TxVersion); err != nil {
		return err
	}
	if t.Recipient, err = decodePredicate(&k[1]); err != nil {
		return err
	}
	if err := fixed(&k[2], t.Mask[:]); err != nil {
		return err
	}
	if t.Data, err = nullableBytes(&k[3]); err != nil {
		return err
	}
	if t.Deadline, err = k[4].deadline(); err != nil {
		return err
	}
	return nil
}

// LeafValue is the certified leaf value v = H(C(b(txHash32), t)). Neither the
// txHash alone nor a 34-byte imprint is the value; the raw 32 bytes go to RSMT
// membership.
func LeafValue(txHash [32]byte, t uint64) [32]byte {
	return H(CArr(CBytes(txHash[:]), CUint(t)))
}

// Leaf is one inclusion obligation (sid, txHash, t, v). The relation exports
// it; it does not assert inclusion.
type Leaf struct {
	SID           [32]byte
	TxHash        [32]byte
	ReferenceTime uint64
	Value         [32]byte
}

// Result is the kernel output (cfg, nonce, amount, tokenId, salt,
// firstPredicateHash, lockDigest, releaseTo, nullifier, Leaf[]). Prepare
// returns no leaves and zero release fields; mint returns one leaf and zero
// release fields.
type Result struct {
	Cfg                [32]byte
	Nonce              uint64
	Amount             *big.Int
	TokenID            [32]byte
	Salt               [32]byte
	FirstPredicateHash [32]byte
	LockDigest         [32]byte
	ReleaseTo          [20]byte
	Nullifier          [32]byte
	Leaves             []Leaf
}

// StateID is sid = H(C(Psource, b(sourceHash32))) with the predicate nested as
// a tagged item.
func StateID(source Predicate, sourceHash [32]byte) [32]byte {
	return H(CArr(source.Bytes(), CBytes(sourceHash[:])))
}

// ResultState is the output state hash H(C(b(I(sourceHash)), b(mask))).
func ResultState(sourceHash [32]byte, mask []byte) [32]byte {
	return H(CArr(CBytes(Imprint(sourceHash)), CBytes(mask)))
}

// PrepareLock validates a lock request and derives the values the vault
// compares with its own: salt, token ID, first predicate hash and lock digest.
// P0 must be a signature predicate with a valid key; amount positive and at
// most 32 bytes; n nonzero.
func PrepareLock(cfg *Cfg, n uint64, amount *big.Int, p0 []byte) (*Result, error) {
	if n == 0 || amount == nil || amount.Sign() <= 0 || len(amount.Bytes()) > MaxAmountBytes {
		return nil, ErrLockInput
	}
	if len(p0) > MaxSemanticBytes {
		return nil, ErrInputTooLarge
	}
	root, err := scanOne(p0)
	if err != nil {
		return nil, err
	}
	pred, err := decodePredicate(root)
	if err != nil {
		return nil, err
	}
	if pred.Type != PredSignature || !bytes.Equal(pred.Bytes(), p0) {
		return nil, ErrPredicate
	}
	ch := cfg.Hash()
	res := &Result{Cfg: ch, Nonce: n, Amount: new(big.Int).Set(amount)}
	res.Salt = DeriveSalt(ch, n)
	res.TokenID = DeriveTokenID(res.Salt, cfg.Network)
	res.FirstPredicateHash = H(p0)
	res.LockDigest = LockDigest(ch, n, LockRecord(cfg.ZeroAddress, cfg.Ty, cfg.Aid, amount, res.TokenID, res.FirstPredicateHash))
	if res.LockDigest == ([32]byte{}) {
		return nil, ErrZeroDigest
	}
	return res, nil
}

// VerifyMint is the mint operation: the history must hold zero transfers.
func VerifyMint(cfg *Cfg, history []byte) (*Result, error) {
	h, err := DecodeHistory(history)
	if err != nil {
		return nil, err
	}
	if len(h.Transfers) != 0 {
		return nil, ErrHasTransfers
	}
	res, _, err := verifyHistory(cfg, h)
	return res, err
}

// VerifyReturn is the return operation: at least the final burn is required.
func VerifyReturn(cfg *Cfg, history []byte) (*Result, error) {
	h, err := DecodeHistory(history)
	if err != nil {
		return nil, err
	}
	if len(h.Transfers) == 0 {
		return nil, ErrNoTransfers
	}
	res, _, err := verifyHistory(cfg, h)
	return res, err
}

// verifyHistory reconstructs every source state and owner, checks byte equality
// with each CD, recomputes txHash and sid, validates the unlock against the
// reconstructed source key and exports every leaf.
func verifyHistory(cfg *Cfg, h *History) (*Result, [32]byte, error) {
	ch := cfg.Hash()
	var zero [32]byte
	m := &h.Mint
	if m.Network != cfg.Network {
		return nil, zero, ErrMintShape
	}
	if m.Recipient.Type != PredSignature {
		return nil, zero, ErrMintShape
	}
	if m.Type != cfg.Ty {
		return nil, zero, ErrMintType
	}
	n, _, err := ParseJustification(cfg, m.Justification)
	if err != nil {
		return nil, zero, err
	}
	salt := DeriveSalt(ch, n)
	if m.Salt != salt {
		return nil, zero, ErrMintSalt
	}
	id := DeriveTokenID(salt, cfg.Network)
	amount, err := parseMintData(cfg, m.Data)
	if err != nil {
		return nil, zero, err
	}
	p0 := m.Recipient.Bytes()
	res := &Result{Cfg: ch, Nonce: n, Amount: amount, TokenID: id, Salt: salt, FirstPredicateHash: H(p0)}
	res.LockDigest = LockDigest(ch, n, LockRecord(cfg.ZeroAddress, cfg.Ty, cfg.Aid, amount, id, res.FirstPredicateHash))
	if res.LockDigest == zero {
		return nil, zero, ErrZeroDigest
	}

	// Mint: source predicate is the universal minter, source hash is h0.
	mk, err := MinterKey(id)
	if err != nil {
		return nil, zero, err
	}
	minterPred := SignaturePredicate(mk.PubKey().SerializeCompressed())
	h0 := MintSourceHash(id)
	seen := map[[32]byte]bool{}
	leaf, err := checkStep(minterPred, h0, h.mintRaw, m.Deadline, &h.MintCD, h.MintTime, mk.PubKey(), seen)
	if err != nil {
		return nil, zero, err
	}
	res.Leaves = append(res.Leaves, leaf)
	state := ResultState(h0, id[:])
	owner := m.Recipient

	for i := range h.Transfers {
		t := &h.Transfers[i]
		last := i == len(h.Transfers)-1
		// owner is the mint recipient or the previous intermediate recipient,
		// both already required to be signature predicates, so ParseKey cannot fail.
		key, _ := ParseKey(owner.Params)
		leaf, err := checkStep(owner, state, h.transfersRaw[i], t.Deadline, &h.CDs[i], h.Times[i], key, seen)
		if err != nil {
			return nil, zero, err
		}
		res.Leaves = append(res.Leaves, leaf)
		if last {
			if err := checkReturn(cfg, res, t); err != nil {
				return nil, zero, err
			}
			btid := BurnID(leaf.SID, leaf.TxHash)
			res.Nullifier = Nullifier(ch, btid)
			if res.Nullifier == zero {
				return nil, zero, ErrZeroDigest
			}
		} else {
			if t.Recipient.Type != PredSignature {
				return nil, zero, ErrBurnNotFinal
			}
			if t.Data != nil {
				return nil, zero, ErrTransferData
			}
		}
		state = ResultState(state, t.Mask[:])
		owner = t.Recipient
	}
	return res, state, nil
}

func checkStep(source Predicate, sourceHash [32]byte, txRaw []byte, e Deadline, cd *Certification, t uint64, key *secp256k1.PublicKey, seen map[[32]byte]bool) (Leaf, error) {
	if !bytes.Equal(cd.Source.Bytes(), source.Bytes()) || cd.SourceHash != sourceHash {
		return Leaf{}, ErrCDMismatch
	}
	txHash := H(txRaw)
	if cd.TxHash != txHash {
		return Leaf{}, ErrCDMismatch
	}
	// The CD deadline must equal the transaction deadline exactly, including
	// null; a null deadline is never synthesised into a value.
	if cd.Deadline != e {
		return Leaf{}, ErrDeadlineMismatch
	}
	if err := VerifyUnlock(key, sourceHash, txHash, cd.Unlock); err != nil {
		return Leaf{}, err
	}
	// An explicit deadline binds the reference time: t < e, equality rejects.
	// No clock, EVM block time or current root round is consulted.
	if e.Set && t >= e.At {
		return Leaf{}, ErrDeadlineExpired
	}
	sid := StateID(source, sourceHash)
	if seen[sid] {
		return Leaf{}, ErrRepeatedSID
	}
	seen[sid] = true
	return Leaf{SID: sid, TxHash: txHash, ReferenceTime: t, Value: LeafValue(txHash, t)}, nil
}

// ParseJustification requires the exact lock reason J matching Cfg and a
// nonzero nonce, scans the embedded LockProof structure within its bounds and
// binds its cfg, and rejects external backing (39047), null, the pre-3.0
// pointer-only reason and any other kind. It authenticates nothing: the
// historical backing is verified offline by VerifyLockProof.
func ParseJustification(cfg *Cfg, j []byte) (uint64, *LockProof, error) {
	if j == nil {
		return 0, nil, ErrMintJustif
	}
	if len(j) > MaxJustificationBytes {
		return 0, nil, ErrJustificationTooLarge
	}
	root, err := scanOne(j)
	if err != nil {
		return 0, nil, ErrMintJustif
	}
	c, err := root.tagContent(TagMintLock)
	if err != nil || !c.isArray(6) {
		return 0, nil, ErrMintJustif
	}
	if c.kids[0].version(LockReasonVersion) != nil {
		return 0, nil, ErrMintJustif
	}
	chain, err := c.kids[1].uintMax(^uint64(0))
	if err != nil || chain != cfg.ChainID {
		return 0, nil, ErrMintJustif
	}
	var vault, zero [20]byte
	if fixed(&c.kids[2], vault[:]) != nil || vault != cfg.Vault || fixed(&c.kids[3], zero[:]) != nil || zero != cfg.ZeroAddress {
		return 0, nil, ErrMintJustif
	}
	n, err := c.kids[4].uintMax(^uint64(0))
	if err != nil || n == 0 {
		return 0, nil, ErrMintJustif
	}
	lp, err := decodeLockProof(&c.kids[5])
	if err != nil {
		return 0, nil, err
	}
	if lp.Cfg != cfg.Hash() {
		return 0, nil, ErrLockProofCfg
	}
	if !bytes.Equal(MintJustification(chain, vault, zero, n, lp), j) {
		return 0, nil, ErrMintJustif
	}
	return n, lp, nil
}

// parseMintData requires the exact value envelope
// tag(39050,[1,[[b(aid32),b(amount)]],null]) for the configured asset: one
// inline entry, minimal positive amount, null memo/extension slot.
func parseMintData(cfg *Cfg, d []byte) (*big.Int, error) {
	if d == nil {
		return nil, ErrMintData
	}
	root, err := scanOne(d)
	if err != nil {
		return nil, ErrMintData
	}
	c, err := root.tagContent(TagValue)
	if err != nil || !c.isArray(3) || c.kids[0].version(ValueVersion) != nil || !c.kids[2].null {
		return nil, ErrMintData
	}
	assets := &c.kids[1]
	if assets.major != majArray || len(assets.kids) != 1 || !assets.kids[0].isArray(2) {
		return nil, ErrMintData
	}
	e := assets.kids[0].kids
	var aid [32]byte
	if fixed(&e[0], aid[:]) != nil || aid != cfg.Aid {
		return nil, ErrMintData
	}
	amt, err := e[1].amount()
	if err != nil {
		return nil, ErrMintData
	}
	return amt, nil
}

// checkReturn validates the terminal transfer: Pnext is Burn(H(R)) with R the
// exact data, amount the whole genesis amount, recipient nonzero and not the
// vault, fee fields fixed.
func checkReturn(cfg *Cfg, res *Result, t *TransferTx) error {
	if t.Recipient.Type != PredBurn {
		return ErrNotBurn
	}
	if t.Data == nil {
		return ErrReturnData
	}
	root, err := scanOne(t.Data)
	if err != nil {
		return ErrReturnData
	}
	c, err := root.tagContent(TagReturnReason)
	if err != nil || !c.isArray(11) {
		return ErrReturnData
	}
	k := c.kids
	if k[0].version(ReturnVersion) != nil {
		return ErrReturnData
	}
	chain, err := k[1].uintMax(^uint64(0))
	if err != nil || chain != cfg.ChainID {
		return ErrReturnData
	}
	var vault, zero, recip [20]byte
	var ty, aid [32]byte
	if fixed(&k[2], vault[:]) != nil || vault != cfg.Vault ||
		fixed(&k[3], zero[:]) != nil || zero != cfg.ZeroAddress ||
		fixed(&k[4], ty[:]) != nil || ty != cfg.Ty ||
		fixed(&k[5], aid[:]) != nil || aid != cfg.Aid ||
		fixed(&k[6], recip[:]) != nil {
		return ErrReturnData
	}
	amt, err := k[7].amount()
	if err != nil || amt.Cmp(res.Amount) != 0 {
		return ErrReturnAmount
	}
	var zero2 [20]byte
	if fixed(&k[8], zero2[:]) != nil || zero2 != cfg.ZeroAddress || !k[9].isBytes() || len(k[9].data) != 0 || !k[10].isUint() || k[10].arg != 0 {
		return ErrReturnData
	}
	if recip == ([20]byte{}) || recip == cfg.Vault {
		return ErrReturnRecip
	}
	// Every field above is typed and compared; the strict scanner fixes the
	// heads, so the bytes equal ReturnReason(...) by construction.
	if h := H(t.Data); !bytes.Equal(t.Recipient.Params, h[:]) {
		return ErrBurnReason
	}
	res.ReleaseTo = recip
	return nil
}
