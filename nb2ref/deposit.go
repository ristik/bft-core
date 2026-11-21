package nb2ref

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"math"
	"math/big"

	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Deposit, mint reason and deposit proof (sections 5 and 6).

// Profile bounds of the deposit evidence (profile.json "limits"), checked before any cryptography.
const (
	MaxJustificationBytes   = 65536
	MaxEVMUCBytes           = 16384 // profile evmUcBytes: the EVM UC of a DepositProof
	MaxHeaderBytes          = 2048
	MaxReceiptNodes         = 65
	MaxReceiptBranchNodeLen = 1024
	MaxReceiptLeafNodeLen   = 49152
	FirstOwnerBytes         = 42
)

// Event signatures and their topic0 (section 13.2).
var (
	TopicDeposited     = HE([]byte("Deposited(uint64,bytes32,uint256,bytes32,bytes)"))
	TopicPaid          = HE([]byte("Paid(bytes32,address,uint256)"))
	TopicSegmentSealed = HE([]byte("SegmentSealed(uint64,bytes32,bytes32,bytes)"))
)

// DepositIntentSecret is r = HMAC-SHA256(key = k_w, msg = C(b("UNICITY_NB2_DEPOSIT_INTENT"), b(D), i)).
func DepositIntentSecret(kw [32]byte, d [32]byte, i uint64) [32]byte {
	m := hmac.New(sha256.New, kw[:])
	m.Write(CArr(CBytes([]byte(domainDepositIntent)), CBytes(d[:]), CUint(i)))
	var out [32]byte
	m.Sum(out[:0])
	return out
}

// Rho is rho = H_E(DEPOSIT_SECRET || D || r).
func Rho(d, r [32]byte) [32]byte { return HE(TagDepositSecret[:], d[:], r[:]) }

// DepositSalt is salt_n = H_U(C(b("UNICITY_NB2_DEPOSIT_SALT"), b(D), n, b(r))).
func DepositSalt(d [32]byte, n uint64, r [32]byte) [32]byte {
	return HU(CArr(CBytes([]byte(domainDepositSalt)), CBytes(d[:]), CUint(n), CBytes(r[:])))
}

// FirstOwnerPrefix is the 9-byte head of the 42-byte first-owner predicate tag(39032, [1, b(0x01), b(key33)]).
var FirstOwnerPrefix = []byte{0xd9, 0x98, 0x78, 0x83, 0x01, 0x41, 0x01, 0x58, 0x21}

// DepositProof is [1, b(evmUC), b(headerRLP), txIndex, logIndex, [b(receiptNodeRLP), ...]] (arity 6; the evmPDR field and the
// DepositPDR rule were dropped by the astra ruling of 2026-11-15). It is also the seal receipt container of section 12.2.
type DepositProof struct {
	UC, Header        []byte
	TxIndex, LogIndex uint64
	Nodes             [][]byte
}

// Bytes is the exact encoding.
func (p *DepositProof) Bytes() []byte {
	nodes := make([][]byte, len(p.Nodes))
	for i, n := range p.Nodes {
		nodes[i] = CBytes(n)
	}
	return CArr(CUint(V2Version), CBytes(p.UC), CBytes(p.Header), CUint(p.TxIndex), CUint(p.LogIndex), CArr(nodes...))
}

// ReceiptBacking is the decoded mint reason J = tag(39051, [1, b(D), n, b(r), DepositProof]).
type ReceiptBacking struct {
	D     [32]byte
	N     uint64
	R     [32]byte
	Proof DepositProof
}

// Bytes is the exact encoding of J.
func (j *ReceiptBacking) Bytes() []byte {
	return CTag(TagReceiptBacking, CArr(CUint(V2Version), CBytes(j.D[:]), CUint(j.N), CBytes(j.R[:]), j.Proof.Bytes()))
}

// DecodeReceiptBacking strictly decodes J and bounds every component before any cryptography.
func DecodeReceiptBacking(b []byte) (*ReceiptBacking, error) {
	if len(b) > MaxJustificationBytes {
		return nil, ErrInputTooLarge
	}
	s := scanner{b: b}
	major, tag, err := s.head()
	if err != nil {
		return nil, err
	}
	if major != majTag {
		return nil, ErrShape
	}
	if tag != TagReceiptBacking {
		return nil, ErrTag
	}
	if err := receiptArray(&s, 5); err != nil {
		return nil, err
	}
	var fields [4]item
	for i, major := range [...]byte{majUint, majBytes, majUint, majBytes} {
		fields[i], err = receiptScalar(&s, major, 2)
		if err != nil {
			return nil, err
		}
	}
	j := &ReceiptBacking{}
	if err := fields[0].version(V2Version); err != nil {
		return nil, err
	}
	if err := fields[1].fixed(j.D[:]); err != nil {
		return nil, err
	}
	if j.N, err = fields[2].uintIn(1, MaxDeposit); err != nil {
		return nil, err
	}
	if err := fields[3].fixed(j.R[:]); err != nil {
		return nil, err
	}
	p, err := readDepositProof(&s, 2)
	if err != nil {
		return nil, err
	}
	if s.pos != len(b) {
		return nil, ErrTrailing
	}
	j.Proof = *p
	return j, nil
}

// DecodeDepositProof strictly decodes a standalone DepositProof container (a seal receipt).
func DecodeDepositProof(b []byte) (*DepositProof, error) {
	if len(b) > MaxJustificationBytes {
		return nil, ErrInputTooLarge
	}
	s := scanner{b: b}
	p, err := readDepositProof(&s, 0)
	if err != nil {
		return nil, err
	}
	if s.pos != len(b) {
		return nil, ErrTrailing
	}
	return p, nil
}

func receiptArray(s *scanner, size uint64) error {
	major, count, err := s.head()
	if err != nil {
		return err
	}
	if major != majArray || count != size {
		return ErrShape
	}
	return nil
}

func receiptScalar(s *scanner, major byte, depth int) (item, error) {
	if s.pos == len(s.b) {
		return item{}, ErrTruncated
	}
	if s.b[s.pos]>>5 != major {
		return item{}, ErrShape
	}
	return s.item(depth)
}

// Read the fixed receipt shape without allocating generic CBOR children.
// In particular, the node-count limit applies to its declared head before
// any node body is read or the node slice is allocated.
func readDepositProof(s *scanner, depth int) (*DepositProof, error) {
	if err := receiptArray(s, 6); err != nil {
		return nil, err
	}
	var fields [5]item
	for i, major := range [...]byte{majUint, majBytes, majBytes, majUint, majUint} {
		it, err := receiptScalar(s, major, depth+1)
		if err != nil {
			return nil, err
		}
		fields[i] = it
	}
	if err := fields[0].version(V2Version); err != nil {
		return nil, err
	}
	p := &DepositProof{UC: fields[1].data, Header: fields[2].data}
	if len(p.UC) > MaxEVMUCBytes || len(p.Header) > MaxHeaderBytes {
		return nil, ErrInputTooLarge
	}
	var err error
	if p.TxIndex, err = fields[3].uintIn(0, MaxIndex); err != nil {
		return nil, err
	}
	if p.LogIndex, err = fields[4].uintIn(0, MaxIndex); err != nil {
		return nil, err
	}
	major, count, err := s.head()
	if err != nil {
		return nil, err
	}
	if major != majArray {
		return nil, ErrShape
	}
	if count > MaxReceiptNodes {
		return nil, ErrInputTooLarge
	}
	if count > uint64(len(s.b)-s.pos) {
		return nil, ErrTruncated
	}
	for i := uint64(0); i < count; i++ {
		n, err := receiptScalar(s, majBytes, depth+2)
		if err != nil {
			return nil, err
		}
		max := MaxReceiptBranchNodeLen
		if i+1 == count {
			max = MaxReceiptLeafNodeLen
		}
		if len(n.data) > max {
			return nil, ErrInputTooLarge
		}
		p.Nodes = append(p.Nodes, n.data)
	}
	return p, nil
}

// ReceiptLog is the authenticated log a receipt proof selects.
type ReceiptLog struct {
	Address [20]byte
	Topics  [][32]byte
	Data    []byte
}

// VerifyReceiptLog is section 6.2 steps 2 to 5 up to the emitter: the EVM UC under its epoch's authority for (evmPartition,
// evmShard) with the complete shard and unicity paths over its own ShardConfHash and no expected configuration hash
// (DepositUC), the header bound to the certified input record (DepositHeader), the receipt-trie
// path keyed by RLP(txIndex) (ReceiptPath), the receipt type (ReceiptType) and status (ReceiptStatus), logs[logIndex]
// (LogIndex) and its address (LogEmitter). The caller checks the topics and data of its event.
func VerifyReceiptLog(c *Config, t *TrustInput, p *DepositProof) (*ReceiptLog, error) {
	uc, err := t.VerifyEVMUC(p.UC, c)
	if err != nil {
		return nil, err
	}
	return verifyReceiptLog(c.Vault, p, uc)
}

// verifyReceiptLog authenticates the execution part of a receipt after its UC was checked.
func verifyReceiptLog(emitter [20]byte, p *DepositProof, uc *types.UnicityCertificate) (*ReceiptLog, error) {
	header, err := bindHeader(p.Header, uc)
	if err != nil {
		return nil, err
	}
	value, err := mptVerify([32]byte(header.ReceiptHash), rlpUintKey(p.TxIndex), p.Nodes)
	if err != nil {
		if err := fail(ErrReceiptPath); err != nil {
			return nil, err
		}
		return nil, ErrReceiptPath // a disabled path check cannot supply a receipt
	}
	logs, err := decodeReceipt(value)
	if err != nil {
		return nil, err
	}
	if p.LogIndex >= uint64(len(logs.kids)) {
		return nil, ErrLogIndex
	}
	l := logs.kids[p.LogIndex]
	if !l.list || len(l.kids) != 3 || l.kids[0].list || len(l.kids[0].str) != 20 || !l.kids[1].list || l.kids[2].list {
		return nil, ErrLogIndex
	}
	out := &ReceiptLog{Address: [20]byte(l.kids[0].str), Data: l.kids[2].str}
	if out.Address != emitter { // the emitter before the topics (section 6.2 step 5)
		if err := fail(ErrLogEmitter); err != nil {
			return nil, err
		}
	}
	for _, tp := range l.kids[1].kids {
		if tp.list || len(tp.str) != 32 {
			return nil, ErrLogTopics
		}
		out.Topics = append(out.Topics, [32]byte(tp.str))
	}
	return out, nil
}

// bindHeader requires H_E(headerRLP) == IR.blockHash and header.stateRoot == IR.hash under the pinned header schema (the
// go-ethereum v1.14.11 Cancun header: exactly 20 fields ending at parentBeaconBlockRoot, zero difficulty, empty uncles and
// withdrawals, no blob gas, a nonzero u64 base fee, at most 32 extra bytes, number below 2^63, canonical re-encoding)
// (DepositHeader). It is bridgeprofile's bindHeader plus the field count, which bridgeprofile does not check.
func bindHeader(raw []byte, uc *types.UnicityCertificate) (*gethtypes.Header, error) {
	ir := uc.InputRecord
	var h gethtypes.Header
	if err := rlp.DecodeBytes(raw, &h); err != nil || h.Number == nil || !h.Number.IsUint64() {
		return nil, ErrDepositHeader
	}
	if again, err := rlp.EncodeToBytes(&h); err != nil || !bytes.Equal(again, raw) {
		return nil, ErrDepositHeader
	}
	// Exactly the 20 Cancun fields: go-ethereum also decodes a 21st (Prague requestsHash) into an optional field.
	if it, err := rlpDecode(raw); err != nil || !it.list || len(it.kids) != 20 || h.RequestsHash != nil {
		return nil, ErrDepositHeader
	}
	bh := HE(raw)
	if !bytes.Equal(bh[:], ir.BlockHash) || !bytes.Equal(h.Root[:], ir.Hash) {
		if err := fail(ErrDepositHeader); err != nil {
			return nil, err
		}
	}
	if h.Number.Uint64() > math.MaxInt64 || h.UncleHash != gethtypes.EmptyUncleHash || h.Difficulty == nil || h.Difficulty.Sign() != 0 ||
		h.BaseFee == nil || h.BaseFee.Sign() <= 0 || !h.BaseFee.IsUint64() || h.WithdrawalsHash == nil || *h.WithdrawalsHash != gethtypes.EmptyWithdrawalsHash ||
		h.BlobGasUsed == nil || *h.BlobGasUsed != 0 || h.ExcessBlobGas == nil || *h.ExcessBlobGas != 0 || h.ParentBeaconRoot == nil || len(h.Extra) > 32 {
		return nil, ErrDepositHeader
	}
	return &h, nil
}

// decodeReceipt reads a legacy receipt RLP([status, cumulativeGas, bloom, logs]) or type || RLP(...) with type 1, 2 or 3
// (ReceiptType), requires status 1 (ReceiptStatus) and returns the logs list.
func decodeReceipt(v []byte) (*rlpItem, error) {
	if len(v) == 0 {
		return nil, ErrReceiptType
	}
	body := v
	if v[0] < 0xc0 {
		if v[0] < 1 || v[0] > 3 {
			return nil, ErrReceiptType
		}
		body = v[1:]
	}
	it, err := rlpDecode(body)
	if err != nil || !it.list || len(it.kids) != 4 {
		return nil, ErrReceiptType
	}
	status, gas, bloom, logs := it.kids[0], it.kids[1], it.kids[2], it.kids[3]
	if _, ok := gas.uintBytes(); !ok || status.list || bloom.list || len(bloom.str) != 256 || !logs.list {
		return nil, ErrReceiptType
	}
	if len(status.str) != 1 || status.str[0] != 1 {
		if err := fail(ErrReceiptStatus); err != nil {
			return nil, err
		}
	}
	return &logs, nil
}

// u256 is the 32-byte big-endian word of v.
func u256(v *big.Int) (w [32]byte) { v.FillBytes(w[:]); return }

func u256u(n uint64) (w [32]byte) { return u256(new(big.Int).SetUint64(n)) }

// DepositedData is the 224-byte data of Deposited(n, D, v, rho, firstOwner).
func DepositedData(d [32]byte, v *big.Int, rho [32]byte, firstOwner []byte) []byte {
	vw, off, ln := u256(v), u256u(0x80), u256u(uint64(len(firstOwner)))
	out := cat(d[:], vw[:], rho[:], off[:], ln[:], firstOwner)
	for len(out)%32 != 0 {
		out = append(out, 0)
	}
	return out
}

// verifyRootMint is section 6.2 for a root mint whose reason is J, in order. It returns J and the deposited amount v.
func verifyRootMint(c *Config, t *TrustInput, m *MintTx) (*ReceiptBacking, *big.Int, error) {
	j, err := DecodeReceiptBacking(m.Justification)
	if err != nil {
		return nil, nil, err
	}
	value, err := verifyFundedMint(c, c.Domain(), m, j, func(p *DepositProof) (*ReceiptLog, error) {
		return VerifyReceiptLog(c, t, p)
	})
	if err != nil {
		return nil, nil, err
	}
	return j, value, nil
}

// verifyFundedMint checks the same signed deposit opening in both bridge generations.
func verifyFundedMint(c *Config, d [32]byte, m *MintTx, j *ReceiptBacking, receipt func(*DepositProof) (*ReceiptLog, error)) (*big.Int, error) {
	if j.D != d {
		if err := fail(ErrMintDomain); err != nil {
			return nil, err
		}
	}
	log, err := receipt(&j.Proof)
	if err != nil {
		return nil, err
	}
	if len(log.Topics) != 2 || log.Topics[0] != TopicDeposited || log.Topics[1] != u256u(j.N) {
		if err := fail(ErrLogTopics); err != nil {
			return nil, err
		}
	}
	data := log.Data
	if len(data) != 224 {
		return nil, ErrLogData
	}
	v := new(big.Int).SetBytes(data[32:64])
	owner := data[160 : 160+FirstOwnerBytes]
	if !bytes.Equal(data[96:128], cat(make([]byte, 31), []byte{0x80})) || !bytes.Equal(data[128:160], cat(make([]byte, 31), []byte{FirstOwnerBytes})) ||
		!bytes.Equal(data[160+FirstOwnerBytes:], make([]byte, 224-160-FirstOwnerBytes)) || [32]byte(data[0:32]) != j.D || v.Sign() == 0 {
		if err := fail(ErrLogData); err != nil {
			return nil, err
		}
	}
	if Rho(j.D, j.R) != [32]byte(data[64:96]) {
		if err := fail(ErrSecretOpening); err != nil {
			return nil, err
		}
	}
	if m.Salt != DepositSalt(d, j.N, j.R) {
		if err := fail(ErrMintSalt); err != nil {
			return nil, err
		}
	}
	if m.Type != c.Ty {
		if err := fail(ErrMintType); err != nil {
			return nil, err
		}
	}
	if !bytes.Equal(m.Recipient.Bytes(), owner) {
		if err := fail(ErrMintOwner); err != nil {
			return nil, err
		}
	}
	if v.BitLen() > 256 || !bytes.Equal(m.Data, ValueData(c.Aid, v)) {
		if err := fail(ErrMintData); err != nil {
			return nil, err
		}
	}
	return v, nil
}
