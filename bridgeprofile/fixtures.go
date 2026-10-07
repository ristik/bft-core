package bridgeprofile

import (
	"bytes"
	gocrypto "crypto"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/holiman/uint256"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier/rsmt"
)

// The fixtures below build real certified evidence for the oracle's tests and
// for the corpus generator: an EVM state with the vault account and its
// permanent lock words, a header, a native unicity certificate signed over the
// input record by a deterministic root authority, and the aggregator side
// (an RSMT, its certificate and leaf paths). Everything is deterministic: keys
// derive from seeds and signatures are RFC 6979.

// SealTime is the fixed round-creation time every fixture seal carries.
const SealTime uint64 = 1_700_000_000

// Authority is a deterministic unit-weight root committee. Signing is by the
// first Signers members (all by default).
type Authority struct {
	Signer abcrypto.Signer // the first member's signer
	NodeID string          // the first member's node identity
	// Signers is the number of members that sign a certificate; 0 means all.
	Signers int
	members []authMember
}

type authMember struct {
	signer abcrypto.Signer
	info   *types.NodeInfo
}

func newMember(seed string) (authMember, error) {
	key := KeyFromSeed("authority:" + seed)
	signer, err := abcrypto.NewInMemorySecp256K1SignerFromKey(key.Serialize())
	if err != nil {
		return authMember{}, err
	}
	v, err := signer.Verifier()
	if err != nil {
		return authMember{}, err
	}
	pub, err := v.MarshalPublicKey()
	if err != nil {
		return authMember{}, err
	}
	lp, err := crypto.UnmarshalSecp256k1PublicKey(pub)
	if err != nil {
		return authMember{}, err
	}
	id, err := peer.IDFromPublicKey(lp)
	if err != nil {
		return authMember{}, err
	}
	return authMember{signer: signer, info: &types.NodeInfo{NodeID: id.String(), SigKey: pub, Stake: 1}}, nil
}

// NewAuthority derives a one-member authority from a seed.
func NewAuthority(seed string) (*Authority, error) { return NewCommittee(seed, 1) }

// NewCommittee derives an n-member unit-weight committee from a seed.
func NewCommittee(seed string, n int) (*Authority, error) {
	a := &Authority{}
	for i := 0; i < n; i++ {
		m, err := newMember(fmt.Sprintf("%s/%d", seed, i))
		if err != nil {
			return nil, err
		}
		a.members = append(a.members, m)
	}
	a.Signer, a.NodeID = a.members[0].signer, a.members[0].info.NodeID
	return a, nil
}

// TrustBase is the signed root trust base of one signer epoch.
func (a *Authority) TrustBase(network types.NetworkID, epoch uint64) (*types.RootTrustBaseV1, error) {
	return a.TrustBaseWith(network, epoch, 0)
}

// TrustBaseWith is TrustBase with an explicit epoch start round.
func (a *Authority) TrustBaseWith(network types.NetworkID, epoch, epochStart uint64, opts ...types.Option) (*types.RootTrustBaseV1, error) {
	var nodes []*types.NodeInfo
	for _, m := range a.members {
		nodes = append(nodes, &types.NodeInfo{NodeID: m.info.NodeID, SigKey: m.info.SigKey, Stake: m.info.Stake})
	}
	tb, err := quorumweight.NewTrustBase(network, nodes, append([]types.Option{types.WithEpoch(epoch), types.WithEpochStart(epochStart)}, opts...)...)
	if err != nil {
		return nil, err
	}
	for _, m := range a.members {
		if err := tb.Sign(m.info.NodeID, m.signer); err != nil {
			return nil, err
		}
	}
	return tb, nil
}

// Certify returns a unicity certificate over ir for the shard configuration
// pdr, sealed at rootRound in root epoch epoch.
func (a *Authority) Certify(network types.NetworkID, epoch, rootRound uint64, ir *types.InputRecord, pdr *types.PartitionDescriptionRecord) (*types.UnicityCertificate, error) {
	confHash, err := pdr.Hash(gocrypto.SHA256)
	if err != nil {
		return nil, err
	}
	trHash := H([]byte("fixture-technical-record"))
	tree, err := types.CreateShardTree(types.ShardingScheme{}, []types.ShardTreeInput{
		{Shard: pdr.ShardID, IR: ir, TRHash: trHash[:], ShardConfHash: confHash},
	}, gocrypto.SHA256)
	if err != nil {
		return nil, err
	}
	stCert, err := tree.Certificate(pdr.ShardID)
	if err != nil {
		return nil, err
	}
	ut, err := types.NewUnicityTree(gocrypto.SHA256, []*types.UnicityTreeData{{Partition: pdr.PartitionID, ShardTreeRoot: tree.RootHash()}})
	if err != nil {
		return nil, err
	}
	cert, err := ut.Certificate(pdr.PartitionID)
	if err != nil {
		return nil, err
	}
	prev := H([]byte("fixture-previous-seal"))
	seal := &types.UnicitySeal{Version: 1, NetworkID: network, Epoch: epoch, RootChainRoundNumber: rootRound,
		Timestamp: SealTime + rootRound, PreviousHash: prev[:], Hash: ut.RootHash()}
	k := a.Signers
	if k <= 0 || k > len(a.members) {
		k = len(a.members)
	}
	for _, m := range a.members[:k] {
		if err := seal.Sign(m.info.NodeID, m.signer); err != nil {
			return nil, err
		}
	}
	return &types.UnicityCertificate{Version: 1, InputRecord: ir, TRHash: trHash[:], ShardConfHash: confHash,
		ShardTreeCertificate: stCert, UnicityTreeCertificate: cert, UnicitySeal: seal}, nil
}

// FixturePDR is a one-validator shard configuration for partition p of network n.
func FixturePDR(network types.NetworkID, partition types.PartitionID, chainID uint64, validatorSeed string) *types.PartitionDescriptionRecord {
	k := KeyFromSeed("validator:" + validatorSeed).PubKey().SerializeCompressed()
	return &types.PartitionDescriptionRecord{
		Version: 1, NetworkID: network, PartitionID: partition, T2Timeout: 5 * time.Second,
		PartitionParams: map[string]string{"chainId": fmt.Sprint(chainID)}, Epoch: 0,
		Validators: []*types.NodeInfo{{NodeID: "validator-1", SigKey: k, Stake: 1}},
	}
}

type nodeList [][]byte

func (l *nodeList) Put(_, v []byte) error { *l = append(*l, bytes.Clone(v)); return nil }
func (l *nodeList) Delete([]byte) error   { return nil }

func newTrie() *trie.Trie { return trie.NewEmpty(triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil)) }

// LockWorld is an EVM state holding the vault with its permanent lock words.
type LockWorld struct {
	Vault         [20]byte
	VaultCodeHash [32]byte
	Locks         map[uint64][32]byte // nonce -> lock digest
	Filler        int                 // extra accounts so the state trie has branches
}

// LockEvidence is everything a proof for one nonce is assembled from.
type LockEvidence struct {
	StateRoot    [32]byte
	Header       []byte
	AccountNodes [][]byte
	StorageNodes [][]byte
	StorageRoot  [32]byte
}

// Evidence builds the state, the header and the proof nodes for nonce n.
func (w *LockWorld) Evidence(n uint64, headerNumber uint64) (*LockEvidence, error) {
	storage := newTrie()
	nonces := make([]uint64, 0, len(w.Locks))
	for k := range w.Locks {
		nonces = append(nonces, k)
	}
	sort.Slice(nonces, func(i, j int) bool { return nonces[i] < nonces[j] })
	for _, k := range nonces {
		key := StorageTrieKey(LockDigestSlot(k))
		if err := storage.Update(key[:], StorageValueRLP(w.Locks[k])); err != nil {
			return nil, err
		}
	}
	acct, err := rlp.EncodeToBytes(&gethtypes.StateAccount{Nonce: 1, Balance: new(uint256.Int), Root: storage.Hash(), CodeHash: w.VaultCodeHash[:]})
	if err != nil {
		return nil, err
	}
	state := newTrie()
	vk := AccountTrieKey(w.Vault)
	if err := state.Update(vk[:], acct); err != nil {
		return nil, err
	}
	for i := 0; i < w.Filler; i++ {
		fa := H([]byte(fmt.Sprint("filler-account-", i)))
		fk := keccak(fa[:20])
		other, _ := rlp.EncodeToBytes(&gethtypes.StateAccount{Nonce: uint64(i), Balance: uint256.NewInt(uint64(i) + 1), Root: gethtypes.EmptyRootHash, CodeHash: gethtypes.EmptyCodeHash[:]})
		if err := state.Update(fk[:], other); err != nil {
			return nil, err
		}
	}
	ev := &LockEvidence{StateRoot: state.Hash(), StorageRoot: storage.Hash()}
	var an, sn nodeList
	if err := state.Prove(vk[:], &an); err != nil {
		return nil, err
	}
	sk := StorageTrieKey(LockDigestSlot(n))
	if err := storage.Prove(sk[:], &sn); err != nil {
		return nil, err
	}
	ev.AccountNodes, ev.StorageNodes = an, sn
	withdrawals, beacon, zero := gethtypes.EmptyWithdrawalsHash, common.Hash{}, uint64(0)
	h := &gethtypes.Header{
		ParentHash: common.Hash(H([]byte("fixture-parent"))), UncleHash: gethtypes.EmptyUncleHash, Root: state.Hash(),
		TxHash: gethtypes.EmptyTxsHash, ReceiptHash: gethtypes.EmptyReceiptsHash, Difficulty: new(big.Int),
		Number: new(big.Int).SetUint64(headerNumber), GasLimit: 30_000_000, Time: SealTime + headerNumber,
		BaseFee: big.NewInt(7), WithdrawalsHash: &withdrawals, BlobGasUsed: &zero, ExcessBlobGas: &zero, ParentBeaconRoot: &beacon,
	}
	if ev.Header, err = rlp.EncodeToBytes(h); err != nil {
		return nil, err
	}
	return ev, nil
}

// Certified assembles the LockProof of nonce n: the evidence plus a unicity
// certificate of the EVM shard (configuration pdr) signed by auth at rootRound
// in the root epoch of tbID's trust base.
func (w *LockWorld) Certified(f *Fixture, auth *Authority, pdr *types.PartitionDescriptionRecord, tr *TrustInput, rootRound, n, headerNumber uint64) (*LockProof, error) {
	return w.CertifiedWith(f, auth, pdr, tr, rootRound, n, headerNumber, nil)
}

// CertifiedWith is Certified with a hook that may alter the certified input
// record before it is signed, so a test or vector can isolate one binding
// (the state hash, the block hash, the shard epoch) with everything else valid.
func (w *LockWorld) CertifiedWith(f *Fixture, auth *Authority, pdr *types.PartitionDescriptionRecord, tr *TrustInput, rootRound, n, headerNumber uint64, mutIR func(ir *types.InputRecord)) (*LockProof, error) {
	ev, err := w.Evidence(n, headerNumber)
	if err != nil {
		return nil, err
	}
	tb, id := tr.Base, tr.ID()
	ir := &types.InputRecord{Version: 1, RoundNumber: headerNumber, Epoch: pdr.Epoch, PreviousHash: sl(H([]byte("fixture-previous-state"))),
		Hash: ev.StateRoot[:], SummaryValue: []byte{}, Timestamp: SealTime + headerNumber, BlockHash: gethcrypto.Keccak256(ev.Header)}
	if mutIR != nil {
		mutIR(ir)
	}
	uc, err := auth.Certify(tb.GetNetworkID(), tb.GetEpoch(), rootRound, ir, pdr)
	if err != nil {
		return nil, err
	}
	ucb, err := types.Cbor.Marshal(uc)
	if err != nil {
		return nil, err
	}
	pdrb, err := types.Cbor.Marshal(pdr)
	if err != nil {
		return nil, err
	}
	return &LockProof{Cfg: f.Cfg.Hash(), TrustBaseID: id, PDR: pdrb, UC: ucb, Header: ev.Header,
		AccountNodes: ev.AccountNodes, StorageNodes: ev.StorageNodes}, nil
}

// ---- aggregator side: an RSMT, its certificate and the leaf paths -----------

type rsmtKV struct {
	key   [32]byte
	value [32]byte
}

type rnode struct {
	hash   [32]byte
	leaf   bool
	depth  int
	lo, hi *rnode
	key    [32]byte
}

func rsmtBuild(ls []rsmtKV) *rnode {
	if len(ls) == 1 {
		return &rnode{hash: rsmt.HashLeaf(ls[0].key, ls[0].value[:]), leaf: true, key: ls[0].key}
	}
	first, last := ls[0].key, ls[len(ls)-1].key
	d := 0
	for rsmt.KeyBitAt(first, d) == rsmt.KeyBitAt(last, d) {
		d++
	}
	split := sort.Search(len(ls), func(i int) bool { return rsmt.KeyBitAt(ls[i].key, d) == 1 })
	lo, hi := rsmtBuild(ls[:split]), rsmtBuild(ls[split:])
	return &rnode{hash: rsmt.HashNode(lo.hash, hi.hash, uint8(d), rsmt.PrefixRegion(first, d)), depth: d, lo: lo, hi: hi, key: first}
}

func (n *rnode) proof(key [32]byte) (bm [32]byte, sibs [][32]byte) {
	for cur := n; !cur.leaf; {
		bm[cur.depth/8] |= 0x80 >> uint(cur.depth%8)
		if rsmt.KeyBitAt(key, cur.depth) == 1 {
			sibs = append(sibs, cur.lo.hash)
			cur = cur.hi
		} else {
			sibs = append(sibs, cur.hi.hash)
			cur = cur.lo
		}
	}
	return
}

// AggregatorWorld certifies sets of leaves under an aggregator root.
type AggregatorWorld struct {
	PDR  *types.PartitionDescriptionRecord
	Auth *Authority
	TB   *types.RootTrustBaseV1
}

// CertifiedLeaves is an anchor and one membership path per requested leaf.
type CertifiedLeaves struct {
	Anchor Anchor
	Proofs []LeafProof
}

// Certify builds the RSMT over leaves (sid -> v), certifies its root with an
// input record carrying irTime as the timestamp, and returns the anchor and the
// ordered paths. Leaves not in the request may be added with extra.
func (w *AggregatorWorld) Certify(leaves []Leaf, extra []Leaf, irTime, rootRound uint64) (*CertifiedLeaves, error) {
	all := append(append([]Leaf{}, leaves...), extra...)
	kv := make([]rsmtKV, len(all))
	for i, l := range all {
		kv[i] = rsmtKV{l.SID, l.Value}
	}
	sort.Slice(kv, func(i, j int) bool { return bytes.Compare(kv[i].key[:], kv[j].key[:]) < 0 })
	root := rsmtBuild(kv)
	ir := &types.InputRecord{Version: 1, RoundNumber: rootRound, Epoch: w.PDR.Epoch, PreviousHash: sl(H([]byte("agg-previous-state"))),
		Hash: root.hash[:], SummaryValue: []byte{}, Timestamp: irTime, BlockHash: sl(H([]byte("agg-block")))}
	uc, err := w.Auth.Certify(w.TB.GetNetworkID(), w.TB.GetEpoch(), rootRound, ir, w.PDR)
	if err != nil {
		return nil, err
	}
	ucb, err := types.Cbor.Marshal(uc)
	if err != nil {
		return nil, err
	}
	irb, err := ir.Bytes()
	if err != nil {
		return nil, err
	}
	conf, err := w.PDR.Hash(gocrypto.SHA256)
	if err != nil {
		return nil, err
	}
	out := &CertifiedLeaves{Anchor: Anchor{Partition: uint32(w.PDR.PartitionID), Shard: EmptyPrefixShard,
		ExpectedStateRoot: root.hash, ExpectedIRHash: H(irb), UC: ucb, InputRecord: irb}}
	copy(out.Anchor.ShardConfHash[:], conf)
	for _, l := range leaves {
		bm, sibs := root.proof(l.SID)
		out.Proofs = append(out.Proofs, LeafProof{Bitmap: bm, Siblings: sibs})
	}
	return out, nil
}

// InclusionProofs returns one SDK inclusion proof per leaf of a history in
// order (mint first), carrying the shared anchor certificate.
func (c *CertifiedLeaves) InclusionProofs() []InclusionProof {
	out := make([]InclusionProof, len(c.Proofs))
	for i, p := range c.Proofs {
		out[i] = InclusionProof{Bitmap: p.Bitmap, Siblings: p.Siblings, UC: c.Anchor.UC}
	}
	return out
}

func sl(h [32]byte) []byte { return h[:] }
