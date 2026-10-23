package bridgeprofile

import (
	"bytes"
	"math/big"
)

// The lineage relation (protocol 6, docs/design/bridge-split-lineage-spec.md): a redeemed part is a token whose mint justification is
// either the lock reason (the root) or a split reason carrying the burned parent token. Verification starts at the root and descends:
// every token's complete history is checked as in verifyHistory, a parent ends in a split burn that commits a manifest, and every
// child is an allocation of that manifest. Depth 0 is an ordinary full redemption.

// Work charges of the lineage walk, taken before the work they pay for (trial values, to be measured by the ureth implementation).
const (
	// SplitPerByte prices scanning and hashing one nested token: charged on the outer mint transaction and on every justification
	// descended into, so a lineage of depth d pays for the quadratic re-hashing of the nested prefixes honestly.
	SplitPerByte uint64 = 16
	// SplitEdgeBase and SplitPerStep price one allocation proof: SplitEdgeBase for the commitment and the leaf hash, SplitPerStep for
	// each node hash (130 bytes, three SHA-256 blocks).
	SplitEdgeBase uint64 = 20_000
	SplitPerStep  uint64 = 1_500
)

// LevelInfo describes one token of a verified lineage, root first.
type LevelInfo struct {
	TokenID [32]byte
	Amount  *big.Int
	Leaves  int // certified leaves the token contributes: its mint and every transfer
}

// Lineage is a verified redemption: the result (root identity, redeemed part, every leaf in root-to-child order) and the levels.
type Lineage struct {
	*Result
	Levels []LevelInfo
}

// VerifyLineageReturn is the return operation of the lineage composition: history is the redeemed part's projection (the compact
// B2 projection of its own token); its ancestry is read from the exact justification bytes of its mint.
func VerifyLineageReturn(cfg *Cfg, history []byte, lim HistoryBounds) (*Lineage, error) {
	return verifyLineageMetered(cfg, history, lim, nil)
}

func verifyLineageMetered(cfg *Cfg, history []byte, lim HistoryBounds, m *meter) (*Lineage, error) {
	h, err := DecodeHistoryWith(history, lim)
	if err != nil {
		return nil, err
	}
	if len(h.Transfers) == 0 {
		return nil, ErrNoTransfers
	}
	return verifyLineage(cfg, h, m)
}

// charge is a no-op on a nil meter, so the oracle and the metered composition share one walk.
func (m *meter) chargeOpt(n uint64) error {
	if m == nil {
		return nil
	}
	return m.charge(n)
}

// verifyLineage walks the ancestry (part first), then verifies it root first.
func verifyLineage(cfg *Cfg, h *History, m *meter) (*Lineage, error) {
	chain := []*History{h}
	var just []*SplitJustification // just[i] is the justification of chain[i]; chain[i+1] is its burned token
	if err := m.chargeOpt(SplitPerByte * uint64(len(h.mintRaw))); err != nil {
		return nil, err
	}
	for cur := h; ; {
		tag, ok := justificationTag(cur.Mint.Justification)
		if !ok {
			return nil, ErrMintJustif
		}
		if tag == TagMintLock {
			break
		}
		if tag != TagSplitJustification {
			return nil, ErrMintJustif
		}
		if err := m.chargeOpt(SplitPerByte * uint64(len(cur.Mint.Justification))); err != nil {
			return nil, err
		}
		sj, err := DecodeSplitJustification(cur.Mint.Justification)
		if err != nil {
			return nil, err
		}
		if err := m.chargeOpt(ComposePerItem * uint64(sj.Items)); err != nil {
			return nil, err
		}
		tok, err := DecodeToken(sj.Token)
		if err != nil {
			return nil, err
		}
		parent := tok.Project()
		if err := m.chargeOpt(ComposePerLeaf * uint64(1+len(parent.Transfers))); err != nil {
			return nil, err
		}
		just = append(just, sj)
		chain = append(chain, parent)
		cur = parent
	}

	d := len(chain) - 1
	ch := cfg.Hash()
	seen := map[[32]byte]bool{}
	out := &Lineage{Result: &Result{Cfg: ch, Depth: uint64(d)}, Levels: make([]LevelInfo, d+1)}
	var parent *levelState
	for i := d; i >= 0; i-- {
		lv, err := verifyLevel(cfg, chain[i], i == d, seen)
		if err != nil {
			return nil, err
		}
		if i < d {
			if err := checkSplitEdge(parent, lv, chain[i], just[i], m); err != nil {
				return nil, err
			}
		}
		out.Result.Leaves = append(out.Result.Leaves, lv.leaves...)
		out.Levels[d-i] = LevelInfo{TokenID: lv.id, Amount: lv.amount, Leaves: len(lv.leaves)}
		last := lv.leaves[len(lv.leaves)-1]
		lastT := &chain[i].Transfers[len(chain[i].Transfers)-1]
		if i == 0 {
			rr := &Result{Amount: lv.amount}
			if err := checkReturn(cfg, rr, lastT); err != nil {
				return nil, err
			}
			out.Result.ReleaseTo = rr.ReleaseTo
			out.Result.Nullifier = Nullifier(ch, BurnID(last.SID, last.TxHash))
			if out.Result.Nullifier == ([32]byte{}) {
				return nil, ErrZeroDigest
			}
			out.Result.PartTokenID, out.Result.PartAmount = lv.id, new(big.Int).Set(lv.amount)
		} else {
			if err := checkSplitBurn(lastT, lv); err != nil {
				return nil, err
			}
		}
		if i == d {
			r := out.Result
			r.Nonce, r.Salt, r.TokenID, r.Amount = lv.nonce, chain[i].Mint.Salt, lv.id, new(big.Int).Set(lv.amount)
			r.FirstPredicateHash = H(chain[i].Mint.Recipient.Bytes())
			r.LockDigest = LockDigest(ch, lv.nonce, LockRecord(cfg.ZeroAddress, cfg.Ty, cfg.Aid, lv.amount, lv.id, r.FirstPredicateHash))
			if r.LockDigest == ([32]byte{}) {
				return nil, ErrZeroDigest
			}
		}
		parent = lv
	}
	return out, nil
}

// levelState is one verified token: its identity, amount, certified leaves and (after checkSplitBurn) its manifest.
type levelState struct {
	id       [32]byte
	amount   *big.Int
	nonce    uint64
	leaves   []Leaf
	manifest SplitManifest
}

// verifyLevel verifies one token's mint and complete transfer history as verifyHistory does, except the terminal transfer, which the
// caller classifies (a split burn for a parent, the return for the part). A root's mint reason is the lock reason with the derived
// salt; a child's is the split reason, checked against its parent by checkSplitEdge, and its salt is free (the ID derives from it).
func verifyLevel(cfg *Cfg, h *History, root bool, seen map[[32]byte]bool) (*levelState, error) {
	ch := cfg.Hash()
	m := &h.Mint
	if m.Network != cfg.Network || m.Recipient.Type != PredSignature {
		return nil, ErrMintShape
	}
	if m.Type != cfg.Ty {
		return nil, ErrMintType
	}
	lv := &levelState{}
	if root {
		n, _, err := ParseJustification(cfg, m.Justification)
		if err != nil {
			return nil, err
		}
		if m.Salt != DeriveSalt(ch, n) {
			return nil, ErrMintSalt
		}
		lv.nonce = n
	}
	lv.id = DeriveTokenID(m.Salt, cfg.Network)
	amount, err := parseMintData(cfg, m.Data)
	if err != nil {
		return nil, err
	}
	lv.amount = amount
	if len(h.Transfers) == 0 {
		return nil, ErrNoTransfers
	}
	mk, err := MinterKey(lv.id)
	if err != nil {
		return nil, err
	}
	h0 := MintSourceHash(lv.id)
	leaf, err := checkStep(SignaturePredicate(mk.PubKey().SerializeCompressed()), h0, h.mintRaw, m.Deadline, &h.MintCD, h.MintTime, mk.PubKey(), seen)
	if err != nil {
		return nil, err
	}
	lv.leaves = append(lv.leaves, leaf)
	state := ResultState(h0, lv.id[:])
	owner := m.Recipient
	for i := range h.Transfers {
		t := &h.Transfers[i]
		// owner is a signature predicate: the mint recipient or the previous intermediate recipient.
		key, _ := ParseKey(owner.Params)
		leaf, err := checkStep(owner, state, h.transfersRaw[i], t.Deadline, &h.CDs[i], h.Times[i], key, seen)
		if err != nil {
			return nil, err
		}
		lv.leaves = append(lv.leaves, leaf)
		if i < len(h.Transfers)-1 {
			if t.Recipient.Type != PredSignature {
				return nil, ErrBurnNotFinal
			}
			if t.Data != nil {
				return nil, ErrTransferData
			}
		}
		state = ResultState(state, t.Mask[:])
		owner = t.Recipient
	}
	return lv, nil
}

// checkSplitBurn requires the parent's final transfer to burn exactly its manifest: Burn(SHA-256(b_M)) with b_M the transfer's data.
// A return burn fails here (its data is a return reason), so a token cannot be both returned and split.
func checkSplitBurn(t *TransferTx, lv *levelState) error {
	if t.Recipient.Type != PredBurn || t.Data == nil {
		return ErrSplitBurn
	}
	man, err := DecodeSplitManifest(t.Data)
	if err != nil {
		return err
	}
	if h := man.ReasonHash(); !bytes.Equal(t.Recipient.Params, h[:]) || !bytes.Equal(man.Bytes(), t.Data) {
		return ErrSplitBurn
	}
	lv.manifest = man
	return nil
}

// checkSplitEdge is the SDK's split mint-reason verification for one edge: same network and type, the child's allocation proof
// against the parent's manifest root with the child's recomputed commitment, and the reconstructed root sum equal to the parent's
// authenticated amount (value conservation).
func checkSplitEdge(parent, child *levelState, ch *History, sj *SplitJustification, m *meter) error {
	// The parent's mint network and type were checked against cfg, the child's likewise, so equality with cfg is equality with each other;
	// a child of another type or network already failed as ErrMintShape/ErrMintType, and the single asset is cfg.Aid in both payloads.
	if err := m.chargeOpt(SplitEdgeBase + SplitPerStep*uint64(len(sj.Proof))); err != nil {
		return err
	}
	d := SplitOutputCommitment(parent.id, &ch.Mint)
	sum, ok := sj.Proof.Verify(child.id, d, child.amount, parent.manifest.Root)
	if !ok {
		return ErrSplitProof
	}
	if sum.Cmp(parent.amount) != 0 {
		return ErrSplitSum
	}
	return nil
}
