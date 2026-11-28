package nb2ref

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
)

// FlatConfigBytes encodes protocol 10 Γ. The legacy NB2 codec remains separate
// for replay of its frozen corpus.
func FlatConfigBytes(c *Config) []byte { return c.bytesWithVersion(2) }

func FlatAssetIDs(c *Config) (ty, aid [32]byte) {
	stem := identityString(c.Network, c.RootGenesis, c.ExecutionGenesis, c.ChainID)
	return HU([]byte("unicity-bridge:unicity-native-nb2-11:" + stem)),
		HU([]byte("unicity-bridge-coin:unicity-native-nb2-11:" + stem))
}

func DecodeFlatConfig(gamma []byte) (*Config, error) {
	version := uint64(2)
	if len(gamma) != 0 && gamma[0] == 0x96 {
		version = 3
	}
	c, err := decodeConfig(gamma, CandidateParams, version)
	if err != nil {
		return nil, err
	}
	c.wireVersion = version
	asset := AssetUCT
	ty, aid := FlatAssetIDs(c)
	if e := c.ERC20; e != nil {
		asset, ty, aid = ERC20AssetIDs(c.ChainID, e.Token, c.ExecutionGenesis)
	}
	if c.Ty != ty || c.Aid != aid || c.Asset != asset {
		return nil, ErrConfigShape
	}
	return c, nil
}

// FlatVerifier is the protocol 10 oracle, pinned to a deployment and a
// snapshot of authenticated authority. A later packet can use a newer view.
type FlatVerifier struct {
	cfg        *Config
	domain     [32]byte
	deployment FlatDeployment
	authority  FlatAuthority
}

func NewFlatVerifier(gamma []byte, deployment FlatDeployment, authority FlatAuthority) (*FlatVerifier, error) {
	cfg, err := DecodeFlatConfig(gamma)
	if err != nil {
		return nil, err
	}
	if e := cfg.ERC20; e != nil && (deployment.Salt != e.Generation || deployment.Pins != e.Pins) {
		return nil, ErrConfigShape
	}
	if err := flatRegistryNetwork(authority.Registry, cfg.Network); err != nil {
		return nil, err
	}
	return &FlatVerifier{cfg: cfg, domain: HU(gamma), deployment: deployment, authority: authority}, nil
}

func (v *FlatVerifier) Session(h FlatHeader) [32]byte {
	return v.deployment.Session(v.cfg, v.domain, h)
}

func FlatParentLink(domain, parentID, sid, tx, manifest, amount [32]byte) [32]byte {
	return HU(cat([]byte("UNICITY/NB2/1.1/PARENT"), domain[:], parentID[:], sid[:], tx[:], manifest[:], amount[:]))
}

func FlatChildReason(link [32]byte) []byte {
	return CTag(TagSplitJustification, CArr(CUint(2), CBytes(link[:])))
}

func FlatOutput(parentID [32]byte, m *MintTx) [32]byte {
	id := TokenID(m.Salt, m.Network)
	return HU(CArr(CBytes([]byte("UNICITY_NB2_11_OUTPUT")), CBytes(parentID[:]), CUint(uint64(m.Network)),
		CBytes(m.Recipient.Bytes()), CBytes(m.Salt[:]), CBytes(id[:]), CBytes(m.Type[:]), CBytes(m.Data), CDeadline(m.Deadline)))
}

type flatRecordReader struct {
	pos  uint64
	read func(uint64, int) ([]byte, error)
}

func (r *flatRecordReader) take(n int) ([]byte, error) {
	b, err := r.read(r.pos, n)
	if err == nil {
		r.pos += uint64(n)
	}
	return b, err
}
func (r *flatRecordReader) blob(max int) ([]byte, error) {
	b, err := r.take(4)
	if err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(max) {
		return nil, ErrInputTooLarge
	}
	return r.take(int(n))
}
func (r *flatRecordReader) prelude() (uint64, error) {
	b, err := r.take(flatPreludeBytes)
	if err != nil {
		return 0, err
	}
	if string(b[:4]) != "NB2L" || binary.BigEndian.Uint16(b[4:6]) != FlatWireVersion {
		return 0, ErrEvidenceShape
	}
	count := binary.BigEndian.Uint64(b[6:])
	if count == 0 {
		return 0, ErrEvidenceShape
	}
	return count, nil
}

type flatMint struct {
	tx         MintTx
	hash       [32]byte
	proof      *InclusionProof
	allocation SumProof
	transfers  uint64
}

func (r *flatRecordReader) mint(root bool) (flatMint, error) {
	var m flatMint
	allocationCap, mintCap := FlatMaxAllocation, FlatMaxChildMint
	if root {
		allocationCap, mintCap = 0, FlatMaxRootMint
	}
	alloc, err := r.blob(allocationCap)
	if err != nil {
		return m, err
	}
	tx, err := r.blob(mintCap)
	if err != nil {
		return m, err
	}
	proof, err := r.blob(FlatMaxPair - 8)
	if err != nil {
		return m, err
	}
	count, err := r.take(8)
	if err != nil {
		return m, err
	}
	if !root {
		m.allocation, err = decodeFlatAllocation(alloc)
		if err != nil {
			return m, err
		}
	}
	item, err := scanOne(tx)
	if err != nil {
		return m, err
	}
	if err := decodeMint(item, &m.tx); err != nil {
		return m, err
	}
	if m.tx.Justification == nil || m.tx.Data == nil {
		return m, ErrMintShape
	}
	pi, err := scanNative(proof)
	if err != nil {
		return m, err
	}
	m.proof, err = decodeProof(pi, proof)
	m.hash, m.transfers = HU(tx), binary.BigEndian.Uint64(count)
	return m, err
}

type flatTransfer struct {
	tx    TransferTx
	hash  [32]byte
	proof *InclusionProof
}

func (r *flatRecordReader) transfer() (flatTransfer, error) {
	var t flatTransfer
	data, err := r.blob(FlatMaxPair)
	if err != nil {
		return t, err
	}
	pair, err := scanNative(data)
	if err != nil {
		return t, err
	}
	if err := pair.array(2); err != nil {
		return t, err
	}
	if err := decodeTransfer(&pair.kids[0], &t.tx); err != nil {
		return t, err
	}
	t.hash = HU(pair.kids[0].raw(data))
	t.proof, err = decodeProof(&pair.kids[1], data)
	return t, err
}

type FlatHolding struct {
	Owner                  [33]byte
	State, TokenID, Amount [32]byte
}

type flatParent struct {
	ID, Amount, Link, Manifest [32]byte
}

func (v *FlatVerifier) mint(m flatMint, parent *flatParent, insert func([32]byte) error, use flatClaimUse) (FlatHolding, error) {
	var holding FlatHolding
	tx := &m.tx
	if tx.Network != v.cfg.Network || tx.Recipient.Type != PredSignature {
		return holding, ErrMintShape
	}
	if tx.Type != v.cfg.Ty {
		return holding, ErrMintType
	}
	amount, err := parseMintData(v.cfg, tx.Data)
	if err != nil {
		return holding, err
	}
	id := TokenID(tx.Salt, tx.Network)
	if parent == nil {
		j, err := DecodeReceiptBacking(tx.Justification)
		if err != nil {
			return holding, err
		}
		if _, err := verifyFundedMint(v.cfg, v.domain, tx, j, func(p *DepositProof) (*ReceiptLog, error) {
			return v.receipt(v.cfg.Vault, p, use)
		}); err != nil {
			return holding, err
		}
	} else {
		if !bytes.Equal(tx.Justification, FlatChildReason(parent.Link)) {
			return holding, ErrSplitJustif
		}
		sum, ok := m.allocation.Verify(id, FlatOutput(parent.ID, tx), amount, parent.Manifest)
		if !ok {
			return holding, ErrSplitProof
		}
		if sum.Cmp(new(big.Int).SetBytes(parent.Amount[:])) != 0 {
			return holding, ErrSplitSum
		}
	}
	minter, err := MinterKey(id)
	if err != nil {
		return holding, err
	}
	h0 := MintSourceHash(id)
	if _, err := v.certified(sigPred(minter), h0, m.hash, tx.Deadline, m.proof, insert, use); err != nil {
		return holding, err
	}
	copy(holding.Owner[:], tx.Recipient.Params)
	holding.State, holding.TokenID, holding.Amount = ResultState(h0, id[:]), id, u256(amount)
	return holding, nil
}

func (h *FlatHolding) continueWith(t flatTransfer) error {
	if t.tx.Recipient.Type != PredSignature {
		return ErrBurnNotFinal
	}
	if t.tx.Data != nil {
		return ErrTransferData
	}
	copy(h.Owner[:], t.tx.Recipient.Params)
	h.State = ResultState(h.State, t.tx.Mask[:])
	return nil
}

func (v *FlatVerifier) split(h FlatHolding, t flatTransfer, sid [32]byte) (*flatParent, error) {
	if t.tx.Recipient.Type != PredBurn || t.tx.Data == nil {
		return nil, ErrSplitBurn
	}
	m, err := DecodeSplitManifest(t.tx.Data)
	if err != nil {
		return nil, err
	}
	if h := HU(t.tx.Data); !bytes.Equal(t.tx.Recipient.Params, h[:]) {
		return nil, ErrBurnReason
	}
	return &flatParent{h.TokenID, h.Amount, FlatParentLink(v.domain, h.TokenID, sid, t.hash, m.Root, h.Amount), m.Root}, nil
}

func (v *FlatVerifier) returnVerdict(h FlatHolding, t flatTransfer, sid [32]byte) (*Verdict, error) {
	amount := new(big.Int).SetBytes(h.Amount[:])
	r, err := checkReturnAt(v.cfg, v.domain, &t.tx, amount)
	if err != nil {
		return nil, err
	}
	return &Verdict{v.domain, RedemptionID(v.domain, BurnTransitionID(sid, t.hash)), r.MinIndex, r.Asset, r.Recipient, amount}, nil
}

// VerifyFlatReturn is the independent whole-evidence walk. It uses ordinary
// in-memory maps and never builds or opens a continuation packet.
func (v *FlatVerifier) VerifyFlatReturn(evidence []byte) (*Verdict, error) {
	_, verdict, err := v.verifyWhole(evidence, false)
	return verdict, err
}

// VerifyFlatHeld authenticates a signature-owned terminal state, including an
// unspent mint. It never creates a redemption verdict.
func (v *FlatVerifier) VerifyFlatHeld(evidence []byte) (FlatHolding, error) {
	holding, _, err := v.verifyWhole(evidence, true)
	return holding, err
}

func (v *FlatVerifier) verifyWhole(evidence []byte, held bool) (FlatHolding, *Verdict, error) {
	var holding FlatHolding
	var verdict *Verdict
	r := flatRecordReader{read: func(pos uint64, n int) ([]byte, error) {
		if pos > uint64(len(evidence)) || uint64(n) > uint64(len(evidence))-pos {
			return nil, ErrTruncated
		}
		return evidence[pos : pos+uint64(n)], nil
	}}
	count, err := r.prelude()
	if err != nil {
		return holding, nil, err
	}
	sources, claims := make(map[[32]byte]bool), make(map[[32]byte][32]byte)
	insert := func(sid [32]byte) error {
		if sources[sid] {
			return ErrRepeatedSID
		}
		sources[sid] = true
		return nil
	}
	use := func(c flatClaim) error {
		if old, ok := claims[c.key]; ok {
			if old != c.value {
				return ErrCertStructure
			}
			return nil
		}
		if err := v.authority.verify([]flatClaim{c}); err != nil {
			return err
		}
		claims[c.key] = c.value
		return nil
	}
	var parent *flatParent
	for i := uint64(0); i < count; i++ {
		m, err := r.mint(i == 0)
		if err != nil {
			return FlatHolding{}, nil, err
		}
		isFinal := i == count-1
		if m.transfers == 0 && (!held || !isFinal) {
			return FlatHolding{}, nil, ErrNoTransfers
		}
		holding, err = v.mint(m, parent, insert, use)
		if err != nil {
			return FlatHolding{}, nil, err
		}
		for j := uint64(0); j < m.transfers; j++ {
			t, err := r.transfer()
			if err != nil {
				return FlatHolding{}, nil, err
			}
			sid, err := v.certified(SignaturePredicate(holding.Owner[:]), holding.State, t.hash, t.tx.Deadline, t.proof, insert, use)
			if err != nil {
				return FlatHolding{}, nil, err
			}
			switch {
			case j < m.transfers-1 || held && isFinal:
				err = holding.continueWith(t)
			case !isFinal:
				parent, err = v.split(holding, t, sid)
			default:
				verdict, err = v.returnVerdict(holding, t, sid)
			}
			if err != nil {
				return FlatHolding{}, nil, err
			}
		}
	}
	if r.pos != uint64(len(evidence)) {
		return FlatHolding{}, nil, ErrTrailing
	}
	return holding, verdict, nil
}

type FlatRunResult struct {
	State *FlatState // nil on completion
	Event FlatEvent
}

func (v *FlatVerifier) RunFlat(data []byte) (*FlatRunResult, error) {
	packet, err := DecodeFlatRun(data)
	if err != nil {
		return nil, err
	}
	s := FlatState{Phase: FlatRootMint, SeenRoot: flatSparseDefaults[flatSIDTree][256], ClaimRoot: flatSparseDefaults[flatClaimTree][256]}
	session := v.Session(packet.Header)
	if packet.Prior != nil {
		s = *packet.Prior
		e, err := v.event(packet.Header, FlatProgressEvent, packet.Receipt)
		if err != nil {
			return nil, err
		}
		if !s.validResume(packet.Header.Length) || s.Seq != e.Seq || s.Digest(session) != e.StateDigest {
			return nil, ErrFlatPredecessor
		}
	}
	pages := flatPageReader{length: packet.Header.Length, byIndex: make(map[uint64][]byte), used: make(map[uint64]bool)}
	for i, p := range packet.Pages {
		if (i != 0 && packet.Pages[i-1].Index >= p.Index) || !p.verifies(packet.Header) {
			return nil, ErrFlatPage
		}
		pages.byIndex[p.Index] = p.Data
	}
	r := flatRecordReader{pos: s.Pos, read: pages.read}
	if packet.Prior == nil {
		s.LevelsLeft, err = r.prelude()
		if err != nil {
			return nil, flatStepError(err)
		}
	}
	claims := flatPacketClaims{root: s.ClaimRoot, cache: make(map[[32]byte][32]byte)}
	var verdict *Verdict
	for _, op := range packet.Operations {
		if verdict != nil || s.Phase != op.Code {
			return nil, ErrFlatStep
		}
		verdict, err = v.stepFlat(&s, &r, op, &claims, packet.Header.Length)
		if err != nil {
			return nil, flatStepError(err)
		}
	}
	if len(pages.used) != len(packet.Pages) {
		return nil, ErrFlatPage
	}
	if err := v.authority.verify(claims.batch); err != nil {
		return nil, flatStepError(err)
	}
	s.Seq, err = flatNextSeq(s.Seq)
	if err != nil {
		return nil, err
	}
	if verdict != nil {
		return &FlatRunResult{Event: FlatEvent{Kind: FlatCompleteEvent, Session: session, Seq: s.Seq, Verdict: verdict}}, nil
	}
	s.Pos, s.ClaimRoot = r.pos, claims.root
	return &FlatRunResult{&s, FlatEvent{Kind: FlatProgressEvent, Session: session, Seq: s.Seq, StateDigest: s.Digest(session)}}, nil
}

func (s FlatState) validResume(length uint64) bool {
	if s.Pos < flatPreludeBytes || s.Pos > length || s.LevelsLeft == 0 || s.Amount == ([32]byte{}) {
		return false
	}
	switch s.Phase {
	case FlatChildMint:
		return s.TransfersLeft == 0 && s.Owner == ([33]byte{}) && s.State == ([32]byte{})
	case FlatTransfer:
		_, err := ParseKey(s.Owner[:])
		return err == nil && s.TransfersLeft != 0 && s.ParentLink == ([32]byte{}) && s.ParentManifest == ([32]byte{})
	default:
		return false
	}
}

func flatStepError(err error) error {
	if errors.Is(err, ErrFlatPage) {
		return err
	}
	return errors.Join(ErrFlatStep, err)
}

func (v *FlatVerifier) stepFlat(s *FlatState, r *flatRecordReader, op FlatOperation, claims *flatPacketClaims, length uint64) (*Verdict, error) {
	insert := func(sid [32]byte) error {
		next, err := flatSIDTree.update(s.SeenRoot, sid, [32]byte{}, flatSIDLeaf(sid), op.SID)
		if err == nil {
			s.SeenRoot = next
		}
		return err
	}
	index := 0
	use := func(c flatClaim) error {
		proof := op.Claims[index]
		index++
		return claims.apply(c, proof)
	}
	if op.Code != FlatTransfer {
		m, err := r.mint(op.Code == FlatRootMint)
		if err != nil {
			return nil, err
		}
		if m.transfers == 0 {
			return nil, ErrNoTransfers
		}
		var parent *flatParent
		if op.Code == FlatChildMint {
			parent = &flatParent{s.TokenID, s.Amount, s.ParentLink, s.ParentManifest}
		}
		holding, err := v.mint(m, parent, insert, use)
		if err != nil {
			return nil, err
		}
		s.Owner, s.State, s.TokenID, s.Amount = holding.Owner, holding.State, holding.TokenID, holding.Amount
		s.ParentLink, s.ParentManifest = [32]byte{}, [32]byte{}
		s.Phase, s.TransfersLeft = FlatTransfer, m.transfers
		return nil, nil
	}
	t, err := r.transfer()
	if err != nil {
		return nil, err
	}
	if s.TransfersLeft == 0 || s.LevelsLeft == 0 {
		return nil, ErrFlatStep
	}
	h := FlatHolding{s.Owner, s.State, s.TokenID, s.Amount}
	sid, err := v.certified(SignaturePredicate(h.Owner[:]), h.State, t.hash, t.tx.Deadline, t.proof, insert, use)
	if err != nil {
		return nil, err
	}
	s.TransfersLeft--
	if s.TransfersLeft > 0 {
		if err := h.continueWith(t); err != nil {
			return nil, err
		}
		s.Owner, s.State = h.Owner, h.State
		return nil, nil
	}
	if s.LevelsLeft > 1 {
		p, err := v.split(h, t, sid)
		if err != nil {
			return nil, err
		}
		s.ParentLink, s.ParentManifest = p.Link, p.Manifest
		s.Owner, s.State = [33]byte{}, [32]byte{}
		s.LevelsLeft--
		s.Phase = FlatChildMint
		return nil, nil
	}
	if r.pos != length {
		return nil, ErrTrailing
	}
	return v.returnVerdict(h, t, sid)
}
