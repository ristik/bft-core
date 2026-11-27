package nb2ref

import (
	"bytes"
	"math/big"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier/rsmt"
)

// The token verifier relation (section 11.2): verifyReturn(Γ, evidence) under the trust-base history.
//
// Order, frozen here so a multi-fault input classifies the same way in every implementation:
//  1. Γ (ConfigShape).
//  2. evidence = C(1, Token): the outer pair is EvidenceShape; the token and every nested item fail with the 14.1 rules.
//  3. The walk from the returned part to the root: a mint reason tagged 39044 is a split reason (SplitJustif, SplitProofCount,
//     SplitProofShape and the inline parent token's wire rules); 39051 ends the walk; anything else is MintReason.
//  4. The root's J (section 6.2, in its order).
//  5. Root first, every token of the walk: mint fields (MintShape, MintType, MintData), NoTransfers, then mint and each transfer
//     in order (CDMismatch, DeadlineMismatch, the unlock rules, DeadlineExpired, RepeatedSID, then its inclusion proof:
//     UnsupportedCertificateEncoding, SealNetwork, CertStructure, SealRoot, NoEntryForEpoch/SealEpoch, QuorumNotMet (on chain
//     the last three are one boolean and report QuorumNotMet),
//     InclusionProof, ReferenceTime), each intermediate transfer's recipient (BurnNotFinal) and data (TransferData); a parent's
//     terminal split burn (SplitBurn, SplitManifest); after each child, its allocation edge (SplitProof, SplitSum).
//  6. The part's terminal burn: NotBurn, ReturnData, ReturnIndex, ReturnDomain, ReturnAsset, ReturnAmount, ReturnRecipient,
//     BurnReason.
//  7. btid and eta.

// Verdict is the authenticated return tuple (domain, eta, minSegment, asset, recipient, amount).
type Verdict struct {
	Domain     [32]byte
	Eta        [32]byte
	MinSegment uint64
	Asset      [32]byte
	Recipient  [20]byte
	Amount     *big.Int
}

// ABI is the verifier's exact 192-byte return data.
func (v *Verdict) ABI() []byte {
	a, r, m := u256(v.Amount), [32]byte{}, u256u(v.MinSegment)
	copy(r[12:], v.Recipient[:])
	return cat(v.Domain[:], v.Eta[:], m[:], v.Asset[:], r[:], a[:])
}

// BurnTransitionID is btid = H_U(C(b("UNICITY_NB2_BURN"), b(sidBurn), b(txHashBurn))).
func BurnTransitionID(sid, txHash [32]byte) [32]byte {
	return HU(CArr(CBytes([]byte(domainBurn)), CBytes(sid[:]), CBytes(txHash[:])))
}

// RedemptionID is eta = H_U(C(b("UNICITY_NB2_REDEMPTION"), b(D), b(btid))).
func RedemptionID(d, btid [32]byte) [32]byte {
	return HU(CArr(CBytes([]byte(domainRedemption)), CBytes(d[:]), CBytes(btid[:])))
}

// ReturnData is R = tag(39052, [1, b(D), b(asset32), b(recipient20), b(v), a]).
type ReturnData struct {
	D         [32]byte
	Asset     [32]byte
	Recipient [20]byte
	Amount    *big.Int
	MinIndex  uint64
}

// Bytes is the exact encoding of R.
func (r *ReturnData) Bytes() []byte {
	return CTag(TagSegmentReturn, CArr(CUint(V2Version), CBytes(r.D[:]), CBytes(r.Asset[:]), CBytes(r.Recipient[:]), CAmount(r.Amount), CUint(r.MinIndex)))
}

// Evidence is C(1, Token).
func Evidence(token []byte) []byte { return cat(head(majArray, 2), CUint(V2Version), token) }

// VerifyReturn is the verifier: it returns the verdict or the rule that refuses the evidence.
func VerifyReturn(gamma, evidence []byte, t *TrustInput, p Params) (*Verdict, error) {
	c, err := DecodeConfig(gamma, p)
	if err != nil {
		return nil, err
	}
	if err := t.bind(c); err != nil {
		return nil, err
	}
	part, err := decodeEvidence(evidence)
	if err != nil {
		return nil, err
	}
	return verifyPart(c, t, part)
}

func decodeEvidence(b []byte) (*Token, error) {
	it, err := scanNative(b)
	if err != nil {
		return nil, err
	}
	if it.array(2) != nil || it.kids[1].major != majTag {
		return nil, ErrEvidenceShape
	}
	if !it.kids[0].isUint() || it.kids[0].arg != V2Version {
		if err := fail(ErrEvidenceShape); err != nil {
			return nil, err
		}
	}
	return decodeTokenItem(&it.kids[1], b)
}

func verifyPart(c *Config, t *TrustInput, part *Token) (*Verdict, error) {
	// 3. The walk, part first.
	chain := []*Token{part}
	var just []*SplitJustification // just[i] is chain[i]'s reason; chain[i+1] is its parent
	for cur := part; ; {
		tag, ok := reasonTag(cur.Mint.Justification)
		if ok && tag == TagReceiptBacking {
			break
		}
		if !ok || tag != TagSplitJustification {
			return nil, ErrMintReason
		}
		sj, err := DecodeSplitJustification(cur.Mint.Justification)
		if err != nil {
			return nil, err
		}
		just = append(just, sj)
		chain = append(chain, sj.Parent)
		cur = sj.Parent
	}
	// 4. The root's J.
	d := len(chain) - 1
	if _, _, err := verifyRootMint(c, t, &chain[d].Mint); err != nil {
		return nil, err
	}
	// 5. Root first.
	seen := map[[32]byte]bool{}
	var parent *level
	var partLevel *level
	for i := d; i >= 0; i-- {
		lv, err := verifyLevel(c, t, chain[i], seen)
		if err != nil {
			return nil, err
		}
		if i < d {
			if err := checkSplitEdge(parent, lv, chain[i], just[i]); err != nil {
				return nil, err
			}
		}
		if i > 0 {
			if err := checkSplitBurn(chain[i], lv); err != nil {
				return nil, err
			}
		}
		parent, partLevel = lv, lv
	}
	// 6. The terminal return burn.
	r, err := checkReturn(c, part, partLevel)
	if err != nil {
		return nil, err
	}
	// 7. The identifiers.
	btid := BurnTransitionID(partLevel.lastSID, partLevel.lastTx)
	return &Verdict{Domain: c.Domain(), Eta: RedemptionID(c.Domain(), btid), MinSegment: r.MinIndex, Asset: r.Asset,
		Recipient: r.Recipient, Amount: new(big.Int).Set(partLevel.amount)}, nil
}

// level is one verified token of the walk.
type level struct {
	id              [32]byte
	amount          *big.Int
	manifest        SplitManifest
	lastSID, lastTx [32]byte
}

func parseMintData(c *Config, d []byte) (*big.Int, error) {
	root, err := scanOne(d)
	if err != nil {
		return nil, ErrMintData
	}
	v, err := root.tagContent(TagValue)
	if err != nil || v.array(3) != nil || v.kids[0].version(ValueVersion) != nil || !v.kids[2].null {
		return nil, ErrMintData
	}
	assets := &v.kids[1]
	if assets.major != majArray || len(assets.kids) != 1 || assets.kids[0].array(2) != nil {
		return nil, ErrMintData
	}
	var aid [32]byte
	if assets.kids[0].kids[0].fixed(aid[:]) != nil || aid != c.Aid {
		return nil, ErrMintData
	}
	amt, err := assets.kids[0].kids[1].amount()
	if err != nil {
		return nil, ErrMintData
	}
	return amt, nil
}

func verifyLevel(c *Config, t *TrustInput, tok *Token, seen map[[32]byte]bool) (*level, error) {
	m := &tok.Mint
	if m.Network != c.Network || m.Recipient.Type != PredSignature {
		if err := fail(ErrMintShape); err != nil {
			return nil, err
		}
	}
	if m.Type != c.Ty {
		if err := fail(ErrMintType); err != nil {
			return nil, err
		}
	}
	amount, err := parseMintData(c, m.Data)
	if err != nil {
		if e := fail(ErrMintData); e != nil {
			return nil, e
		}
		amount = big.NewInt(1)
	}
	if len(tok.Transfers) == 0 {
		return nil, ErrNoTransfers
	}
	lv := &level{id: TokenID(m.Salt, m.Network), amount: amount}
	mk, err := MinterKey(lv.id)
	if err != nil {
		return nil, err
	}
	h0 := MintSourceHash(lv.id)
	if _, _, err := checkStep(c, t, SignaturePredicate(mk.PubKey().SerializeCompressed()), h0, tok.mintRaw, m.Deadline, &tok.MintProof, seen); err != nil {
		return nil, err
	}
	state := ResultState(h0, lv.id[:])
	owner := m.Recipient
	for i := range tok.Transfers {
		tr := &tok.Transfers[i]
		sid, txh, err := checkStep(c, t, owner, state, tok.transfersRaw[i], tr.Deadline, &tok.Proofs[i], seen)
		if err != nil {
			return nil, err
		}
		lv.lastSID, lv.lastTx = sid, txh
		if i < len(tok.Transfers)-1 {
			if tr.Recipient.Type != PredSignature {
				return nil, ErrBurnNotFinal // the next transfer would have no signing key
			}
			if tr.Data != nil {
				if err := fail(ErrTransferData); err != nil {
					return nil, err
				}
			}
		}
		state = ResultState(state, tr.Mask[:])
		owner = tr.Recipient
	}
	return lv, nil
}

// checkStep verifies one certified transaction: the reconstructed source and hash against the CD, the deadline, the unlock
// under the source key, the reference time against an explicit deadline, the state ID's uniqueness over the lineage, and the
// inclusion proof. It returns (sid, txHash).
func checkStep(c *Config, t *TrustInput, source Predicate, sourceHash [32]byte, txRaw []byte, e Deadline, p *InclusionProof, seen map[[32]byte]bool) ([32]byte, [32]byte, error) {
	var zero [32]byte
	cd := &p.CD
	txHash := HU(txRaw)
	if !bytes.Equal(cd.Source.Bytes(), source.Bytes()) || cd.SourceHash != sourceHash || cd.TxHash != txHash {
		if err := fail(ErrCDMismatch); err != nil {
			return zero, zero, err
		}
	}
	if cd.Deadline != e {
		if err := fail(ErrDeadlineMismatch); err != nil {
			return zero, zero, err
		}
	}
	key, err := ParseKey(source.Params)
	if err != nil || source.Type != PredSignature {
		return zero, zero, ErrBurnNotFinal
	}
	if err := VerifyUnlock(key, sourceHash, txHash, cd.Unlock); err != nil {
		return zero, zero, err
	}
	if e.Set && p.T >= e.At {
		if err := fail(ErrDeadlineExpired); err != nil {
			return zero, zero, err
		}
	}
	sid := StateID(source, sourceHash)
	if seen[sid] {
		if err := fail(ErrRepeatedSID); err != nil {
			return zero, zero, err
		}
	}
	seen[sid] = true
	if err := verifyInclusion(c, t, sid, LeafValue(txHash, p.T), p); err != nil {
		return zero, zero, err
	}
	return sid, txHash, nil
}

// verifyInclusion checks one aggregator inclusion proof: the UC (its encoding, its epoch's entry, partition aggregatorPartition
// and its own shard, the folds and the quorum), the shard owning the state ID, the RSMT membership of (sid, v) under the
// certified state root (InclusionProof), and t <= IR.timestamp of that UC (ReferenceTime).
func verifyInclusion(c *Config, t *TrustInput, sid, value [32]byte, p *InclusionProof) error {
	uc, err := decodeUC(p.UC)
	if err != nil {
		return err
	}
	shard := uc.ShardTreeCertificate.Shard
	if err := t.ucCheck(uc, types.PartitionID(c.AggregatorPartition), shard); err != nil {
		return err
	}
	if !shard.Comparator()(sid[:]) {
		if err := failf(ErrInclusionProof, "state ID outside the certificate's shard"); err != nil {
			return err
		}
	}
	if len(uc.InputRecord.Hash) != 32 || !rsmtMember([32]byte(uc.InputRecord.Hash), sid, value, p.Bitmap, p.Siblings) {
		if err := fail(ErrInclusionProof); err != nil {
			return err
		}
	}
	if p.T > uc.InputRecord.Timestamp {
		return fail(ErrReferenceTime)
	}
	return nil
}

// rsmtMember folds (key, value) along the path (siblings root to leaf, bitmap bit d MSB-first) to root, the generic RSMT
// membership of the 0x0102 primitive.
func rsmtMember(root, key, value [32]byte, bitmap [32]byte, siblings [][32]byte) bool {
	if root == ([32]byte{}) {
		return false
	}
	h := rsmt.HashLeaf(key, value[:])
	idx := len(siblings)
	for d := 255; d >= 0; d-- {
		if bitmap[d/8]&(0x80>>uint(d%8)) == 0 {
			continue
		}
		idx--
		if idx < 0 {
			return false
		}
		sib := siblings[idx]
		region := rsmt.PrefixRegion(key, d)
		if rsmt.KeyBitAt(key, d) == 1 {
			h = rsmt.HashNode(sib, h, uint8(d), region)
		} else {
			h = rsmt.HashNode(h, sib, uint8(d), region)
		}
	}
	return idx == 0 && h == root
}

// checkSplitBurn requires a parent's terminal transfer to burn exactly its manifest. A return burn fails here (its data is R,
// not a manifest), so a token cannot both split and return.
func checkSplitBurn(tok *Token, lv *level) error {
	last := &tok.Transfers[len(tok.Transfers)-1]
	if last.Recipient.Type != PredBurn || last.Data == nil {
		return ErrSplitBurn
	}
	man, err := DecodeSplitManifest(last.Data)
	if err != nil {
		return err
	}
	if h := HU(man.Bytes()); !bytes.Equal(last.Recipient.Params, h[:]) {
		if err := fail(ErrSplitBurn); err != nil {
			return err
		}
	}
	lv.manifest = man
	return nil
}

// checkSplitEdge verifies a child's allocation against its parent's manifest root and the conservation of the parent's amount.
func checkSplitEdge(parent, child *level, tok *Token, sj *SplitJustification) error {
	d := SplitOutputCommitment(parent.id, &tok.Mint)
	sum, ok := sj.Proof.Verify(child.id, d, child.amount, parent.manifest.Root)
	if !ok {
		return fail(ErrSplitProof)
	}
	if sum.Cmp(parent.amount) != 0 {
		return fail(ErrSplitSum)
	}
	return nil
}

func checkReturn(c *Config, part *Token, lv *level) (*ReturnData, error) {
	return checkReturnAt(c, c.Domain(), &part.Transfers[len(part.Transfers)-1], lv.amount)
}

func checkReturnAt(c *Config, d [32]byte, last *TransferTx, amount *big.Int) (*ReturnData, error) {
	if last.Recipient.Type != PredBurn {
		return nil, ErrNotBurn
	}
	r, err := decodeReturnData(last.Data)
	if err != nil {
		return nil, err
	}
	if r.MinIndex > MaxSegment {
		if err := fail(ErrReturnIndex); err != nil {
			return nil, err
		}
	}
	if r.D != d {
		if err := fail(ErrReturnDomain); err != nil {
			return nil, err
		}
	}
	if r.Asset != c.Asset {
		if err := fail(ErrReturnAsset); err != nil {
			return nil, err
		}
	}
	if r.Amount.Cmp(amount) != 0 {
		if err := fail(ErrReturnAmount); err != nil {
			return nil, err
		}
	}
	if r.Recipient == ([20]byte{}) || r.Recipient == c.Vault {
		if err := fail(ErrReturnRecipient); err != nil {
			return nil, err
		}
	}
	if h := HU(last.Data); !bytes.Equal(last.Recipient.Params, h[:]) {
		if err := fail(ErrBurnReason); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// decodeReturnData strictly decodes R; any failure to be exactly a tag(39052, ...) R is ReturnData.
func decodeReturnData(b []byte) (*ReturnData, error) {
	if b == nil {
		return nil, ErrReturnData
	}
	root, err := scanOne(b)
	if err != nil {
		return nil, wrap(ErrReturnData, err)
	}
	c, err := root.tagContent(TagSegmentReturn)
	if err != nil || c.array(6) != nil || c.kids[0].version(V2Version) != nil {
		return nil, ErrReturnData
	}
	k := c.kids
	r := &ReturnData{}
	if k[1].fixed(r.D[:]) != nil || k[2].fixed(r.Asset[:]) != nil || k[3].fixed(r.Recipient[:]) != nil || !k[5].isUint() {
		return nil, ErrReturnData
	}
	if r.Amount, err = k[4].amount(); err != nil {
		return nil, ErrReturnData
	}
	r.MinIndex = k[5].arg
	return r, nil
}
