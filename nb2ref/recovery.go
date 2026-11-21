package nb2ref

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
)

// These tags and the progress event are prototype wire, separate from NB2.
var RecoveryProgressTopic = HE([]byte("AxisBProgress(bytes32,bytes32)"))
var RecoveryCompleteTopic = HE([]byte("AxisBComplete(bytes32,bytes32,uint64,bytes32,address,uint256)"))

type RecoveryPhase uint8

const (
	RecoveryDiscover RecoveryPhase = iota + 1
	RecoveryPrepare
	RecoveryHashMint
	RecoveryMint
	RecoveryTransfer
	RecoveryUnwind
	RecoveryComplete
)

const RecoveryHashBytes = 4096

// RecoveryFrame is an opening of a saved traversal frame. End is the upper
// bound of a token, not its parsed end, until all of its transfers are checked.
type RecoveryFrame struct {
	Start, End, Mint, Just, JustEnd uint64
}

func (f RecoveryFrame) packed() []byte {
	return cat(recoveryNum(f.Start), recoveryNum(f.End), recoveryNum(f.Mint), recoveryNum(f.Just), recoveryNum(f.JustEnd))
}

func (f RecoveryFrame) push(tail [32]byte) [32]byte { return HE([]byte{3}, f.packed(), tail[:]) }

// RecoveryState consists only of fixed-size fields. Callers open the stack
// and the sparse tree when the machine needs them.
type RecoveryState struct {
	Phase                                  RecoveryPhase
	Frame                                  RecoveryFrame
	Stack, Seen                            [32]byte
	Pos, MintEnd, Left, SplitProof         uint64
	Hash                                   [32]byte // SHA-256 compression state at a full block boundary, or finalized mint hash
	Owner                                  [33]byte
	State, ID, Amount                      [32]byte
	ParentID, ParentAmount, ParentManifest [32]byte
}

func (s RecoveryState) Digest(session [32]byte) [32]byte {
	return HE([]byte{4}, session[:], []byte{byte(s.Phase)}, s.Frame.packed(), s.Stack[:], s.Seen[:],
		recoveryNum(s.Pos), recoveryNum(s.MintEnd), recoveryNum(s.Left), recoveryNum(s.SplitProof), s.Hash[:],
		s.Owner[:], s.State[:], s.ID[:], s.Amount[:], s.ParentID[:], s.ParentAmount[:], s.ParentManifest[:])
}

type RecoveryInput struct {
	Windows []RecoveryWindow
	Frame   RecoveryFrame
	Tail    [32]byte
	Seen    RecoverySeenWitness
}

type Recovery struct {
	config  *Config
	trust   *TrustInput
	emitter [20]byte
	root    [32]byte
	length  uint64
	session [32]byte
}

func NewRecovery(gamma []byte, trust *TrustInput, params Params, emitter [20]byte, root [32]byte, length uint64) (*Recovery, error) {
	cfg, err := DecodeConfig(gamma, params)
	if err != nil {
		return nil, err
	}
	if err = trust.bind(cfg); err != nil {
		return nil, err
	}
	if emitter == ([20]byte{}) || root == ([32]byte{}) || length < 3 {
		return nil, ErrRecoveryState
	}
	d := cfg.Domain()
	session := HE([]byte("UNICITY_NB2_AXIS_B_PROTOTYPE_V1"), d[:], emitter[:], root[:], recoveryNum(length))
	return &Recovery{cfg, trust, emitter, root, length, session}, nil
}

func (r *Recovery) Session() [32]byte { return r.session }

func (r *Recovery) Start(in RecoveryInput) (RecoveryState, *Verdict, error) {
	start := RecoveryState{Phase: RecoveryDiscover, Frame: RecoveryFrame{Start: 2, End: r.length}, Seen: recoveryEmpty[256]}
	raw := in.at(0, r.length)
	if len(raw) < 2 || raw[0] != 0x82 || raw[1] != V2Version {
		return RecoveryState{}, nil, ErrEvidenceShape
	}
	return r.step(start, in)
}

// Advance verifies the certified immediate predecessor's log from the
// immutable verifier address. The same certified prefix can be resumed
// independently by any caller, without carrying its ancestors' receipts.
func (r *Recovery) Advance(prior RecoveryState, receipt *DepositProof, in RecoveryInput) (RecoveryState, *Verdict, error) {
	if receipt == nil || prior.Phase < RecoveryDiscover || prior.Phase >= RecoveryComplete {
		return RecoveryState{}, nil, ErrRecoveryState
	}
	checked, err := DecodeDepositProof(receipt.Bytes())
	if err != nil {
		return RecoveryState{}, nil, err
	}
	cfg := *r.config
	cfg.Vault = r.emitter
	log, err := VerifyReceiptLog(&cfg, r.trust, checked)
	if err != nil {
		return RecoveryState{}, nil, err
	}
	d := prior.Digest(r.session)
	if len(log.Topics) != 2 || log.Topics[0] != RecoveryProgressTopic || log.Topics[1] != r.session || !bytes.Equal(log.Data, d[:]) {
		return RecoveryState{}, nil, ErrRecoveryState
	}
	return r.step(prior, in)
}

// ProgressLog is sufficient for a host to construct a certified receipt proof.
func (r *Recovery) ProgressLog(s RecoveryState) RawLog {
	h := s.Digest(r.session)
	return RawLog{Address: r.emitter, Topics: [][32]byte{RecoveryProgressTopic, r.session}, Data: h[:]}
}

func (in RecoveryInput) at(pos, limit uint64) []byte {
	if pos >= limit {
		return nil
	}
	for _, w := range in.Windows {
		if pos >= w.Start && pos-w.Start < uint64(len(w.Data)) {
			return w.Data[pos-w.Start : min(limit-w.Start, uint64(len(w.Data)))]
		}
	}
	return nil
}

func (r *Recovery) step(s RecoveryState, in RecoveryInput) (RecoveryState, *Verdict, error) {
	if len(in.Windows) == 0 || len(in.Windows) > 3 {
		return RecoveryState{}, nil, ErrRecoveryWitness
	}
	pages := 0
	for _, w := range in.Windows {
		pages += (len(w.Data) + RecoveryPageBytes - 1) / RecoveryPageBytes
		if pages > RecoveryMaxWindowBytes/RecoveryPageBytes {
			return RecoveryState{}, nil, ErrRecoveryWitness
		}
	}
	for _, w := range in.Windows {
		if err := w.verify(r.root, r.length); err != nil {
			return RecoveryState{}, nil, err
		}
	}
	var verdict *Verdict
	var err error
	switch s.Phase {
	case RecoveryDiscover:
		err = s.discover(in)
	case RecoveryPrepare:
		var end uint64
		_, end, err = recoveryMint(in, s.Frame, false)
		if err == nil {
			s.MintEnd, s.Pos, s.Hash, s.Phase = end, s.Frame.Mint, recoverySHAInit(), RecoveryHashMint
		}
	case RecoveryHashMint:
		err = s.hashMint(in)
	case RecoveryMint:
		err = r.mint(&s, in)
	case RecoveryTransfer:
		verdict, err = r.transfer(&s, in)
	case RecoveryUnwind:
		err = s.unwind(in)
	default:
		err = ErrRecoveryState
	}
	if err != nil {
		return RecoveryState{}, nil, fmt.Errorf("axis B phase %d: %w", s.Phase, err)
	}
	return s, verdict, nil
}

func recoveryExpect(sc *scanner, major byte, arg uint64) error {
	m, a, err := sc.head()
	if err != nil {
		return err
	}
	if m != major || a != arg {
		return ErrShape
	}
	return nil
}

// Recovery scans individual items from their actual depth in the outer evidence
// or the SplitJ unit, where the parent token starts one level deeper.
func (f RecoveryFrame) pairDepth() int {
	if f.Start == 2 {
		return 4
	}
	return 5
}

func recoveryTokenPrefix(sc *scanner) error {
	for _, h := range []struct {
		major byte
		arg   uint64
	}{{majTag, TagToken}, {majArray, 3}, {majUint, TokenVersion}, {majArray, 2}} {
		if err := recoveryExpect(sc, h.major, h.arg); err != nil {
			return err
		}
	}
	return nil
}

func recoveryMintPrefix(sc *scanner, offset, limit uint64) (MintTx, uint64, uint64, error) {
	var mint MintTx
	for _, h := range []struct {
		major byte
		arg   uint64
	}{{majTag, TagMint}, {majArray, 8}, {majUint, TxVersion}} {
		if err := recoveryExpect(sc, h.major, h.arg); err != nil {
			return mint, 0, 0, err
		}
	}
	nw, err := sc.item(0)
	if err != nil {
		return mint, 0, 0, err
	}
	n, err := nw.uintIn(1, 65535)
	if err != nil {
		return mint, 0, 0, err
	}
	mint.Network = uint16(n)
	pred, err := sc.item(0)
	if err != nil {
		return mint, 0, 0, err
	}
	if mint.Recipient, err = decodePredicate(&pred); err != nil {
		return mint, 0, 0, err
	}
	for _, dst := range [][]byte{mint.Salt[:], mint.Type[:]} {
		field, err := sc.item(0)
		if err != nil {
			return mint, 0, 0, err
		}
		if err := field.fixed(dst); err != nil {
			return mint, 0, 0, err
		}
	}
	major, size, err := sc.head()
	just := offset + uint64(sc.pos)
	if err != nil {
		return mint, 0, 0, err
	}
	if major != majBytes || size == 0 || just > limit || size > limit-just {
		return mint, 0, 0, ErrMintReason
	}
	return mint, just, just + size, nil
}

func (s *RecoveryState) discover(in RecoveryInput) error {
	frame := s.Frame
	sc := scanner{b: in.at(frame.Start, frame.End)}
	if err := recoveryTokenPrefix(&sc); err != nil {
		return err
	}
	frame.Mint = frame.Start + uint64(sc.pos)
	_, start, end, err := recoveryMintPrefix(&sc, frame.Start, frame.End)
	if err != nil {
		return err
	}
	frame.Just, frame.JustEnd = start, end
	reason := scanner{b: in.at(start, end)}
	major, tag, err := reason.head()
	if err != nil || major != majTag {
		return ErrMintReason
	}
	switch tag {
	case TagReceiptBacking:
		s.Frame, s.Phase = frame, RecoveryPrepare
	case TagSplitJustification:
		if err := recoveryExpect(&reason, majArray, 2); err != nil {
			return ErrSplitJustif
		}
		s.Stack = frame.push(s.Stack)
		s.Frame = RecoveryFrame{Start: start + uint64(reason.pos), End: end}
	default:
		return ErrMintReason
	}
	return nil
}

func recoveryMint(in RecoveryInput, frame RecoveryFrame, includeReason bool) (MintTx, uint64, error) {
	head := scanner{b: in.at(frame.Mint, frame.End)}
	mint, start, end, err := recoveryMintPrefix(&head, frame.Mint, frame.End)
	if err != nil {
		return mint, 0, err
	}
	if start != frame.Just || end != frame.JustEnd {
		return mint, 0, ErrRecoveryState
	}
	if includeReason {
		mint.Justification = in.at(start, end)
		if uint64(len(mint.Justification)) != end-start {
			return mint, 0, ErrRecoveryWitness
		}
	}
	tail := scanner{b: in.at(end, frame.End)}
	data, err := tail.item(0)
	if err != nil {
		return mint, 0, err
	}
	mint.Data, err = nullableBytes(&data)
	if err != nil {
		return mint, 0, err
	}
	dl, err := tail.item(0)
	if err != nil {
		return mint, 0, err
	}
	mint.Deadline, err = dl.deadline()
	return mint, end + uint64(tail.pos), err
}

func recoverySHAInit() [32]byte {
	return [32]byte{0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a, 0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19}
}

func (s *RecoveryState) hashMint(in RecoveryInput) error {
	if s.Pos < s.Frame.Mint || s.Pos >= s.MintEnd || s.MintEnd-s.Frame.Mint > math.MaxUint64/8 {
		return ErrRecoveryState
	}
	consumed := s.Pos - s.Frame.Mint
	end := s.Pos + min(s.MintEnd-s.Pos, RecoveryHashBytes)
	b := in.at(s.Pos, end)
	if uint64(len(b)) != end-s.Pos || consumed%64 != 0 {
		return ErrRecoveryWitness
	}
	h := sha256.New()
	state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil || len(state) != 108 || !bytes.Equal(state[:4], []byte("sha\x03")) {
		return ErrRecoveryState
	}
	copy(state[4:36], s.Hash[:])
	binary.BigEndian.PutUint64(state[100:], consumed)
	if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
		return err
	}
	_, _ = h.Write(b)
	s.Pos = end
	if end == s.MintEnd {
		copy(s.Hash[:], h.Sum(nil))
		s.Phase = RecoveryMint
		return nil
	}
	state, err = h.(encoding.BinaryMarshaler).MarshalBinary()
	if err == nil {
		copy(s.Hash[:], state[4:36])
	}
	return err
}

func recoveryAllocation(in RecoveryInput, pos, end uint64) (SumProof, error) {
	raw := in.at(pos, end)
	if uint64(len(raw)) != end-pos {
		return nil, ErrRecoveryWitness
	}
	s, err := scanOne(raw)
	if err != nil || s.array(1) != nil {
		return nil, ErrSplitProofCount
	}
	return decodeSumProof(&s.kids[0])
}

func (s *RecoveryState) unwind(in RecoveryInput) error {
	f := in.Frame
	if f.push(in.Tail) != s.Stack || f.JustEnd != s.Frame.End || s.Pos >= f.JustEnd {
		return ErrRecoveryWitness
	}
	if _, err := recoveryAllocation(in, s.Pos, f.JustEnd); err != nil {
		return err
	}
	s.SplitProof, s.Frame, s.Stack, s.Phase = s.Pos, f, in.Tail, RecoveryPrepare
	return nil
}

func (r *Recovery) check(s *RecoveryState, source Predicate, state, txHash [32]byte, deadline Deadline, p *InclusionProof, proof RecoverySeenWitness) ([32]byte, error) {
	var zero [32]byte
	cd := p.CD
	switch {
	case !bytes.Equal(source.Bytes(), cd.Source.Bytes()) || state != cd.SourceHash || txHash != cd.TxHash:
		return zero, ErrCDMismatch
	case cd.Deadline != deadline:
		return zero, ErrDeadlineMismatch
	}
	key, err := ParseKey(source.Params)
	if err != nil || source.Type != PredSignature {
		return zero, ErrBurnNotFinal
	}
	if err := VerifyUnlock(key, state, txHash, cd.Unlock); err != nil {
		return zero, err
	}
	if deadline.Set && p.T >= deadline.At {
		return zero, ErrDeadlineExpired
	}
	sid := StateID(source, state)
	next, err := proof.insert(s.Seen, sid)
	if err != nil {
		return zero, err
	}
	if err := verifyInclusion(r.config, r.trust, sid, LeafValue(txHash, p.T), p); err != nil {
		return zero, err
	}
	s.Seen = next
	return sid, nil
}

func (r *Recovery) mint(s *RecoveryState, in RecoveryInput) error {
	root := s.SplitProof == 0
	m, end, err := recoveryMint(in, s.Frame, root)
	if err != nil {
		return err
	}
	if end != s.MintEnd {
		return ErrRecoveryState
	}
	if root {
		if _, _, err := verifyRootMint(r.config, r.trust, &m); err != nil {
			return err
		}
	}
	if m.Network != r.config.Network || m.Recipient.Type != PredSignature {
		return ErrMintShape
	}
	if m.Type != r.config.Ty {
		return ErrMintType
	}
	amount, err := parseMintData(r.config, m.Data)
	if err != nil {
		return err
	}
	sc := scanner{b: in.at(end, s.Frame.End), native: true}
	value, err := sc.item(s.Frame.pairDepth())
	if err != nil {
		return err
	}
	proof, err := decodeProof(&value, sc.b)
	if err != nil {
		return err
	}
	major, count, err := sc.head()
	if err != nil || major != majArray {
		return ErrShape
	}
	if count == 0 {
		return ErrNoTransfers
	}
	id := TokenID(m.Salt, m.Network)
	key, err := MinterKey(id)
	if err != nil {
		return err
	}
	h0 := MintSourceHash(id)
	if _, err = r.check(s, sigPred(key), h0, s.Hash, m.Deadline, proof, in.Seen); err != nil {
		return err
	}
	if !root {
		alloc, err := recoveryAllocation(in, s.SplitProof, s.Frame.JustEnd)
		if err != nil {
			return err
		}
		d := SplitOutputCommitment(s.ParentID, &m)
		sum, ok := alloc.Verify(id, d, amount, s.ParentManifest)
		if !ok {
			return ErrSplitProof
		}
		if sum.Cmp(new(big.Int).SetBytes(s.ParentAmount[:])) != 0 {
			return ErrSplitSum
		}
	}
	copy(s.Owner[:], m.Recipient.Params)
	s.State, s.ID, s.Amount = ResultState(h0, id[:]), id, u256(amount)
	s.Pos, s.Left, s.Phase = end+uint64(sc.pos), count, RecoveryTransfer
	s.SplitProof, s.ParentID, s.ParentAmount, s.ParentManifest = 0, [32]byte{}, [32]byte{}, [32]byte{}
	return nil
}

func (r *Recovery) transfer(s *RecoveryState, in RecoveryInput) (*Verdict, error) {
	sc := scanner{b: in.at(s.Pos, s.Frame.End), native: true}
	pair, err := sc.item(s.Frame.pairDepth())
	if err != nil {
		return nil, err
	}
	if pair.array(2) != nil || s.Left == 0 {
		return nil, ErrShape
	}
	var tr TransferTx
	if err := decodeTransfer(&pair.kids[0], &tr); err != nil {
		return nil, err
	}
	proof, err := decodeProof(&pair.kids[1], sc.b)
	if err != nil {
		return nil, err
	}
	tx := HU(pair.kids[0].raw(sc.b))
	sid, err := r.check(s, SignaturePredicate(s.Owner[:]), s.State, tx, tr.Deadline, proof, in.Seen)
	if err != nil {
		return nil, err
	}
	s.Pos += uint64(sc.pos)
	s.Left--
	if s.Left > 0 {
		if tr.Recipient.Type != PredSignature {
			return nil, ErrBurnNotFinal
		}
		if tr.Data != nil {
			return nil, ErrTransferData
		}
		copy(s.Owner[:], tr.Recipient.Params)
		s.State = ResultState(s.State, tr.Mask[:])
		return nil, nil
	}
	tok := Token{Transfers: []TransferTx{tr}}
	lv := level{id: s.ID, amount: new(big.Int).SetBytes(s.Amount[:])}
	if s.Stack != ([32]byte{}) {
		if err := checkSplitBurn(&tok, &lv); err != nil {
			return nil, err
		}
		s.ParentID, s.ParentAmount, s.ParentManifest = s.ID, s.Amount, lv.manifest.Root
		s.Phase = RecoveryUnwind
		return nil, nil
	}
	if s.Pos != r.length {
		return nil, ErrTrailing
	}
	rd, err := checkReturn(r.config, &tok, &lv)
	if err != nil {
		return nil, err
	}
	s.Phase = RecoveryComplete
	d := r.config.Domain()
	return &Verdict{d, RedemptionID(d, BurnTransitionID(sid, tx)), rd.MinIndex, rd.Asset, rd.Recipient, lv.amount}, nil
}
