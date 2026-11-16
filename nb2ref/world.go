package nb2ref

import (
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/unicitynetwork/bft-go-base/types"
)

// World is the deterministic DEV deployment behind the tests and the vector file: Γ, a two-entry trust-base history (a root
// committee rotation at RotationRound), the EVM shard with a validator rotation (shard epochs 0 and 1) and the aggregator
// partition. Every value is a fixture input, not a production parameter.
type World struct {
	Cfg        *Config
	Gamma      []byte
	Build      string // "production" or "test": the admitted (K, B) set Γ is judged under
	Params     Params
	Trust      *TrustInput
	Roots      []*Committee // by root epoch - 1
	Entries    []*types.RootTrustBaseV2
	EVM        *EVMShard
	Agg        *Aggregator
	WalletKey  [32]byte
	nextN      uint64
	nextBlock  uint64
	nextIntent uint64
}

// Fixture constants.
const (
	DevNetwork      = 3
	DevChainID      = 31337
	DevEVMPartition = 7
	DevAggPartition = 11
	DevRootRound    = 40   // seal round in root epoch 1
	RotationRound   = 1000 // first round of root epoch 2
	DevTime         = SealTime
)

// SemanticProfileHash is SHA-256 of the exact bytes of native-bridge-plugins protocol/profile.json (protocol 9, artifactVersion 7,
// native-bridge-plugins 0ee070eac2c93b59864a659ee50f4aa7a9dfd54c).
var SemanticProfileHash = [32]byte(mustHex("a9da5f02d629fd81f4e4ce61566e69c234157b106749e18221598909097d144f"))

// NewWorld builds the deployment with the given (K, B) and aggregator shard count (1 or 2).
func NewWorld(k, b uint64, aggShards int) (*World, error) {
	r1, err := NewCommittee("root-1", 3)
	if err != nil {
		return nil, err
	}
	r2, err := NewCommittee("root-2", 3)
	if err != nil {
		return nil, err
	}
	g, err := r1.Genesis(DevNetwork, 1, 1)
	if err != nil {
		return nil, err
	}
	s, err := r1.Successor(g, r2, RotationRound)
	if err != nil {
		return nil, err
	}
	bundle, err := TrustBundle(g, s)
	if err != nil {
		return nil, err
	}
	id, err := g.EntryID()
	if err != nil {
		return nil, err
	}
	trust, err := LoadTrustInput(bundle, id)
	if err != nil {
		return nil, err
	}
	evmShard := types.ShardID{}
	evm := &EVMShard{Network: DevNetwork, Partition: DevEVMPartition, Shard: evmShard, PDRs: []*types.PartitionDescriptionRecord{
		FixturePDR(DevNetwork, DevEVMPartition, evmShard, 0, "evm-a"),
		FixturePDR(DevNetwork, DevEVMPartition, evmShard, 1, "evm-b", "evm-c"),
	}}
	agg := &Aggregator{Network: DevNetwork, Committee: r1, Seal: SealOpts{Network: DevNetwork, Epoch: 1, RootRound: DevRootRound}}
	if aggShards == 1 {
		agg.PDRs = []*types.PartitionDescriptionRecord{FixturePDR(DevNetwork, DevAggPartition, types.ShardID{}, 0, "agg-0")}
	} else {
		l, r := types.ShardID{}.Split()
		agg.PDRs = []*types.PartitionDescriptionRecord{FixturePDR(DevNetwork, DevAggPartition, l, 0, "agg-0"), FixturePDR(DevNetwork, DevAggPartition, r, 0, "agg-1")}
	}
	c := &Config{Network: DevNetwork, RootGenesis: id, ExecutionGenesis: HU([]byte("fixture-execution-genesis")), ChainID: DevChainID,
		EVMPartition: DevEVMPartition, EVMShard: evmShard.Bytes(), AggregatorPartition: DevAggPartition,
		Vault: addr20(HE([]byte("fixture-vault"))), Asset: AssetUCT, SemanticProfileHash: SemanticProfileHash,
		Verifier: addr20(HE([]byte("fixture-verifier"))), VerifierCodeHash: HE([]byte("fixture-verifier-code")),
		K: k, B: b, Qmax: new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil)}
	c.Ty = DeriveType(c.Network, c.RootGenesis, c.ExecutionGenesis, c.ChainID)
	c.Aid = DeriveCoin(c.Network, c.RootGenesis, c.ExecutionGenesis, c.ChainID)
	return &World{Cfg: c, Gamma: c.Bytes(), Build: BuildOf(k), Params: BuildParams(BuildOf(k)), Trust: trust, Roots: []*Committee{r1, r2}, Entries: []*types.RootTrustBaseV2{g, s},
		EVM: evm, Agg: agg, WalletKey: HU([]byte("fixture-wallet-bridge-key")), nextBlock: 9}, nil
}

// Env is the vault's environment matching Γ.
func (w *World) Env() Environment {
	return Environment{Address: w.Cfg.Vault, ChainID: w.Cfg.ChainID, VerifierCodeHash: w.Cfg.VerifierCodeHash}
}

// ReceiptOpts are the knobs of one certified receipt proof.
type ReceiptOpts struct {
	Type       byte // receipt type of the selected transaction (0 legacy)
	TxIndex    uint64
	FillerLogs int  // logs before the selected log in the same receipt
	Rotated    bool // certify after both rotations: shard epoch 1, root epoch 2
	MutReceipt func(*RawReceipt)
	MutLog     func(*RawLog)
	MutIR      func(*types.InputRecord)
	TamperUC   func(*types.UnicityCertificate)
	EVM        *EVMShard  // certify under another partition or shard
	Committee  *Committee // sign with another committee
	Seal       *SealOpts
	MutProof   func(*DepositProof)
	MutHeader  func([]byte) []byte // alter the header bytes before they are certified
}

// ReceiptProof certifies a block whose transaction TxIndex emits log (after FillerLogs other logs) and returns its proof.
func (w *World) ReceiptProof(log RawLog, o ReceiptOpts) (*DepositProof, error) {
	n := w.nextBlock
	w.nextBlock++
	sel := RawReceipt{Type: o.Type, Status: []byte{1}, Gas: 50_000}
	for i := 0; i < o.FillerLogs; i++ {
		sel.Logs = append(sel.Logs, RawLog{Address: addr20(HE([]byte(fmt.Sprint("filler-emitter-", i)))), Topics: [][32]byte{HE([]byte("Filler()"))}, Data: []byte{byte(i)}})
	}
	if o.MutLog != nil {
		o.MutLog(&log)
	}
	sel.Logs = append(sel.Logs, log)
	if o.MutReceipt != nil {
		o.MutReceipt(&sel)
	}
	var receipts [][]byte
	for i := uint64(0); i < o.TxIndex; i++ {
		f := RawReceipt{Type: byte(i % 4), Status: []byte{1}, Gas: 21_000 * (i + 1)}
		receipts = append(receipts, f.Encode())
	}
	receipts = append(receipts, sel.Encode())
	after := RawReceipt{Type: 2, Status: []byte{}, Gas: 21_000 * (o.TxIndex + 2)}
	receipts = append(receipts, after.Encode())
	b, err := NewBlock(n, receipts)
	if err != nil {
		return nil, err
	}
	if o.MutHeader != nil {
		b.Header = o.MutHeader(b.Header)
	}
	nodes, err := b.Path(o.TxIndex)
	if err != nil {
		return nil, err
	}
	shardEpoch, seal, committee := uint64(0), SealOpts{Network: DevNetwork, Epoch: 1, RootRound: DevRootRound}, w.Roots[0]
	if o.Rotated {
		shardEpoch, seal, committee = 1, SealOpts{Network: DevNetwork, Epoch: 2, RootRound: RotationRound + DevRootRound}, w.Roots[1]
	}
	if o.Seal != nil {
		seal = *o.Seal
	}
	if o.Committee != nil {
		committee = o.Committee
	}
	evm := w.EVM
	if o.EVM != nil {
		evm = o.EVM
	}
	uc, err := evm.CertifyBlock(b, n, shardEpoch, committee, seal, o.MutIR, o.TamperUC)
	if err != nil {
		return nil, err
	}
	p := &DepositProof{UC: uc, Header: b.Header, TxIndex: o.TxIndex, LogIndex: uint64(o.FillerLogs), Nodes: nodes}
	if o.MutProof != nil {
		o.MutProof(p)
	}
	return p, nil
}

// Deposit is one deposit into the fixture vault: the wallet secret, the Deposited log and its certified receipt proof.
type Deposit struct {
	N          uint64
	R, Rho     [32]byte
	Value      *big.Int
	Owner      *secp256k1.PrivateKey
	FirstOwner []byte
	J          *ReceiptBacking
}

// FirstOwner is the 42-byte first-owner predicate of a key.
func FirstOwner(k *secp256k1.PrivateKey) []byte {
	return SignaturePredicate(k.PubKey().SerializeCompressed()).Bytes()
}

// MakeDeposit performs the next deposit of value to owner and builds J.
func (w *World) MakeDeposit(value *big.Int, owner *secp256k1.PrivateKey, o ReceiptOpts) (*Deposit, error) {
	w.nextIntent++
	return w.MakeDepositWithSecret(value, owner, DepositIntentSecret(w.WalletKey, w.Cfg.Domain(), w.nextIntent), o)
}

// MakeDepositWithSecret is MakeDeposit with a given secret r (a faulty wallet reusing r).
func (w *World) MakeDepositWithSecret(value *big.Int, owner *secp256k1.PrivateKey, r [32]byte, o ReceiptOpts) (*Deposit, error) {
	w.nextN++
	d := w.Cfg.Domain()
	dep := &Deposit{N: w.nextN, Value: value, Owner: owner, FirstOwner: FirstOwner(owner)}
	dep.R = r
	dep.Rho = Rho(d, dep.R)
	log := RawLog{Address: w.Cfg.Vault, Topics: [][32]byte{TopicDeposited, u256u(dep.N)}, Data: DepositedData(d, value, dep.Rho, dep.FirstOwner)}
	p, err := w.ReceiptProof(log, o)
	if err != nil {
		return nil, err
	}
	dep.J = &ReceiptBacking{D: d, N: dep.N, R: dep.R, Proof: *p}
	return dep, nil
}

// SealReceiptProof certifies a SegmentSealed log and returns the receipt container bytes.
func (w *World) SealReceiptProof(segment uint64, data []byte, o ReceiptOpts) ([]byte, error) {
	log := RawLog{Address: w.Cfg.Vault, Topics: [][32]byte{TopicSegmentSealed, u256u(segment)}, Data: data}
	p, err := w.ReceiptProof(log, o)
	if err != nil {
		return nil, err
	}
	return p.Bytes(), nil
}

// Draft is an unsigned token: its transactions and the key that signs each transfer (Owners[i] signs transfer i; Owners[0]
// is the mint recipient).
type Draft struct {
	Mint      MintTx
	Transfers []TransferTx
	Owners    []*secp256k1.PrivateKey
	Times     []uint64 // reference time per transaction (mint first); zero means the default
	Cert      map[int]CertOpts
	// AfterSign alters the signed token before it is certified (CD-level faults); AfterCert after certification.
	AfterSign, AfterCert func(*Token)
}

func sigPred(k *secp256k1.PrivateKey) Predicate {
	return SignaturePredicate(k.PubKey().SerializeCompressed())
}

// RootDraft is the root token of a deposit, transferred through keys (keys[0] is the deposit's owner).
func (w *World) RootDraft(dep *Deposit, keys []*secp256k1.PrivateKey) *Draft {
	d := w.Cfg.Domain()
	m := MintTx{Network: w.Cfg.Network, Recipient: sigPred(dep.Owner), Salt: DepositSalt(d, dep.N, dep.R), Type: w.Cfg.Ty,
		Justification: dep.J.Bytes(), Data: ValueData(w.Cfg.Aid, dep.Value)}
	dr := &Draft{Mint: m, Owners: []*secp256k1.PrivateKey{dep.Owner}}
	for _, k := range keys[1:] {
		dr.Transfer(sigPred(k), k)
	}
	return dr
}

// Transfer appends an intermediate transfer to next, signed by the current owner; nextKey becomes the owner.
func (d *Draft) Transfer(next Predicate, nextKey *secp256k1.PrivateKey) {
	i := len(d.Transfers)
	d.Transfers = append(d.Transfers, TransferTx{Recipient: next, Mask: HU([]byte("mask"), d.Mint.Salt[:], CUint(uint64(i)))})
	d.Owners = append(d.Owners, nextKey)
}

// Return appends the return burn with R.
func (d *Draft) Return(r *ReturnData) {
	rb := r.Bytes()
	i := len(d.Transfers)
	d.Transfers = append(d.Transfers, TransferTx{Recipient: BurnPredicate(HU(rb)), Mask: HU([]byte("mask"), d.Mint.Salt[:], CUint(uint64(i))), Data: rb})
}

// ReturnTo is the return data of the draft's own amount to recipient at index a.
func (w *World) ReturnTo(amount *big.Int, recipient [20]byte, a uint64) *ReturnData {
	return &ReturnData{D: w.Cfg.Domain(), Asset: AssetUCT, Recipient: recipient, Amount: new(big.Int).Set(amount), MinIndex: a}
}

// Finalize signs and certifies a draft. The signer of transfer i is Owners[i]; the minter signs the mint.
func (w *World) Finalize(d *Draft) (*Token, error) {
	t := &Token{Mint: d.Mint, Transfers: append([]TransferTx(nil), d.Transfers...)}
	t.mintRaw = t.Mint.Bytes()
	id := TokenID(t.Mint.Salt, t.Mint.Network)
	mk, err := MinterKey(id)
	if err != nil {
		return nil, err
	}
	h0 := MintSourceHash(id)
	times := func(i int) uint64 {
		if i < len(d.Times) && d.Times[i] != 0 {
			return d.Times[i]
		}
		return DevTime + 10*uint64(i)
	}
	t.MintProof.CD = Certification{Source: sigPred(mk), SourceHash: h0, TxHash: HU(t.mintRaw), Deadline: t.Mint.Deadline}
	t.MintProof.CD.Unlock = SignUnlock(mk, h0, t.MintProof.CD.TxHash)
	t.MintProof.T = times(0)
	state := ResultState(h0, id[:])
	for i := range t.Transfers {
		raw := t.Transfers[i].Bytes()
		t.transfersRaw = append(t.transfersRaw, raw)
		owner := d.Owners[i]
		cd := Certification{Source: sigPred(owner), SourceHash: state, TxHash: HU(raw), Deadline: t.Transfers[i].Deadline}
		cd.Unlock = SignUnlock(owner, state, cd.TxHash)
		t.Proofs = append(t.Proofs, InclusionProof{CD: cd, T: times(i + 1)})
		state = ResultState(state, t.Transfers[i].Mask[:])
	}
	if d.AfterSign != nil {
		d.AfterSign(t)
	}
	// Certify each transaction: the leaf uses the reconstructed source, never a mutated CD.
	all := append([]*InclusionProof{&t.MintProof}, ptrs(t.Proofs)...)
	src := []Predicate{sigPred(mk)}
	hashes := [][32]byte{h0}
	raws := append([][]byte{t.mintRaw}, t.transfersRaw...)
	st := ResultState(h0, id[:])
	for i := range t.Transfers {
		src = append(src, sigPred(d.Owners[i]))
		hashes = append(hashes, st)
		st = ResultState(st, t.Transfers[i].Mask[:])
	}
	for i, p := range all {
		leaf := Leaf{SID: StateID(src[i], hashes[i]), Value: LeafValue(HU(raws[i]), p.T)}
		o := d.Cert[i]
		if o.IRTime == 0 {
			o.IRTime = DevTime + 5000
		}
		ps, err := w.Agg.Certify([]Leaf{leaf}, o)
		if err != nil {
			return nil, err
		}
		p.Bitmap, p.Siblings, p.UC = ps[0].Bitmap, ps[0].Siblings, ps[0].UC
	}
	if d.AfterCert != nil {
		d.AfterCert(t)
	}
	return t, nil
}

func ptrs(ps []InclusionProof) []*InclusionProof {
	out := make([]*InclusionProof, len(ps))
	for i := range ps {
		out[i] = &ps[i]
	}
	return out
}

// SplitOut is one output of a split.
type SplitOut struct {
	Amount *big.Int
	Owner  *secp256k1.PrivateKey
	Salt   *[32]byte // default derived from the parent ID and the position
}

// SplitOpts are the split negatives' knobs.
type SplitOpts struct {
	MutLeaves  func([]SumLeaf)
	MutProof   func(i int, p SumProof) SumProof
	MutJ       func(i int, j []byte) []byte
	ParentBurn func(*TransferTx)
	// Custom replaces the allocation of child 0 and the manifest root: it receives child 0's leaf and returns its proof and the
	// root the parent's manifest commits to.
	Custom func(leaf SumLeaf) (SumProof, [32]byte)
}

// Split burns the parent draft into its split manifest, finalizes it and returns the children's drafts (their mints carry
// the split reason; their transfers are the caller's).
func (w *World) Split(parent *Draft, outs []SplitOut, o SplitOpts) (*Token, []*Draft, error) {
	c := w.Cfg
	pid := TokenID(parent.Mint.Salt, parent.Mint.Network)
	var mints []MintTx
	var leaves []SumLeaf
	for i, out := range outs {
		salt := HU([]byte("child-salt"), pid[:], CUint(uint64(i)))
		if out.Salt != nil {
			salt = *out.Salt
		}
		m := MintTx{Network: c.Network, Recipient: sigPred(out.Owner), Salt: salt, Type: c.Ty, Data: ValueData(c.Aid, out.Amount)}
		mints = append(mints, m)
		leaves = append(leaves, SumLeaf{Key: TokenID(salt, c.Network), Data: SplitOutputCommitment(pid, &m), Value: out.Amount})
	}
	if o.MutLeaves != nil {
		o.MutLeaves(leaves)
	}
	tree, err := BuildSumTree(leaves)
	if err != nil {
		return nil, nil, err
	}
	man := SplitManifest{Root: tree.Root()}
	var customProof SumProof
	if o.Custom != nil {
		customProof, man.Root = o.Custom(leaves[0])
	}
	burn := TransferTx{Recipient: BurnPredicate(HU(man.Bytes())), Mask: HU([]byte("mask"), parent.Mint.Salt[:], CUint(uint64(len(parent.Transfers)))), Data: man.Bytes()}
	if o.ParentBurn != nil {
		o.ParentBurn(&burn)
	}
	parent.Transfers = append(parent.Transfers, burn)
	ptok, err := w.Finalize(parent)
	if err != nil {
		return nil, nil, err
	}
	pb := ptok.Bytes()
	var kids []*Draft
	for i := range mints {
		key := TokenID(mints[i].Salt, c.Network)
		proof, ok := tree.Proof(key)
		if !ok {
			proof = SumProof{}
		}
		if o.MutProof != nil {
			proof = o.MutProof(i, proof)
		}
		if o.Custom != nil && i == 0 {
			proof = customProof
		}
		j := SplitJustificationBytes(pb, proof)
		if o.MutJ != nil {
			j = o.MutJ(i, j)
		}
		mints[i].Justification = j
		kids = append(kids, &Draft{Mint: mints[i], Owners: []*secp256k1.PrivateKey{outs[i].Owner}})
	}
	return ptok, kids, nil
}

// Key is a fixture key.
func Key(seed string) *secp256k1.PrivateKey { return KeyFromSeed("nb2-key:" + seed) }

// Recipient20 is a fixture EVM recipient.
func Recipient20(seed string) [20]byte { return addr20(HE([]byte("recipient:" + seed))) }
