package nb2ref

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
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier/rsmt"
)

// Deterministic fixtures: root committees and their trust-base history, the EVM shard (receipt tries, headers and their
// certificates) and the aggregator partition (RSMTs and their certificates). Keys derive from seeds, signatures are RFC 6979,
// and every time is a constant, so the vector file is a pure function of the code. Parts are copied from bridgeprofile's
// fixtures.go.

// SealTime is the fixed seal time base.
const SealTime uint64 = 1_700_000_000

// Committee is a deterministic root committee; the first Signers members sign (all when 0).
type Committee struct {
	Signers int
	members []member
}

type member struct {
	signer abcrypto.Signer
	info   *types.NodeInfo
}

// NewCommittee derives an n-member committee with the given weights (unit weights when none).
func NewCommittee(seed string, n int, weights ...uint64) (*Committee, error) {
	c := &Committee{}
	for i := 0; i < n; i++ {
		key := KeyFromSeed(fmt.Sprintf("authority:%s/%d", seed, i))
		signer, err := abcrypto.NewInMemorySecp256K1SignerFromKey(key.Serialize())
		if err != nil {
			return nil, err
		}
		v, err := signer.Verifier()
		if err != nil {
			return nil, err
		}
		pub, err := v.MarshalPublicKey()
		if err != nil {
			return nil, err
		}
		lp, err := crypto.UnmarshalSecp256k1PublicKey(pub)
		if err != nil {
			return nil, err
		}
		id, err := peer.IDFromPublicKey(lp)
		if err != nil {
			return nil, err
		}
		w := uint64(1)
		if i < len(weights) {
			w = weights[i]
		}
		c.members = append(c.members, member{signer: signer, info: &types.NodeInfo{NodeID: id.String(), SigKey: pub, Stake: w}})
	}
	return c, nil
}

func (a *Committee) entry(network types.NetworkID, epoch, start uint64, previous []byte) *types.RootTrustBaseV2 {
	e := types.NewRootTrustBaseV2()
	e.NetworkID, e.Epoch, e.EpochStart, e.PreviousEntryID = network, epoch, start, previous
	var total uint64
	for _, m := range a.members {
		e.RootNodes = append(e.RootNodes, &types.NodeInfo{NodeID: m.info.NodeID, SigKey: m.info.SigKey, Stake: m.info.Stake})
		total += m.info.Stake
	}
	sort.Slice(e.RootNodes, func(i, j int) bool { return e.RootNodes[i].NodeID < e.RootNodes[j].NodeID })
	e.QuorumThreshold = total*2/3 + 1
	return e
}

// Genesis is a genesis trust-base entry with this committee.
func (a *Committee) Genesis(network types.NetworkID, epoch, start uint64) (*types.RootTrustBaseV2, error) {
	e := a.entry(network, epoch, start, make([]byte, types.TrustBaseV2IDLen))
	return e, e.Validate()
}

// Successor is the entry after prev with next as its committee, witnessed by every member of this committee.
func (a *Committee) Successor(prev *types.RootTrustBaseV2, next *Committee, start uint64) (*types.RootTrustBaseV2, error) {
	id, err := prev.EntryID()
	if err != nil {
		return nil, err
	}
	e := next.entry(prev.NetworkID, prev.Epoch+1, start, id[:])
	for _, m := range a.members {
		if err := e.Sign(m.info.NodeID, m.signer); err != nil {
			return nil, err
		}
	}
	return e, e.Validate()
}

// ShardInput is one shard's configuration and input record in a root round.
type ShardInput struct {
	PDR *types.PartitionDescriptionRecord
	IR  *types.InputRecord
}

// SealOpts selects the seal of a certificate.
type SealOpts struct {
	Network   types.NetworkID
	Epoch     uint64 // root epoch
	RootRound uint64
}

// CertifyShards seals one root round over the shards of one partition and returns the certificate of inputs[target].
// The tamper hook, when set, alters the certificate after sealing (so the seal no longer covers it).
func (a *Committee) CertifyShards(s SealOpts, inputs []ShardInput, target int, tamper func(*types.UnicityCertificate)) ([]byte, error) {
	if len(inputs) == 1 && inputs[0].PDR.ShardID.Length() == 1 {
		// A lone depth-1 shard: complete the topology with its sibling, carrying the same input record.
		l, r := types.ShardID{}.Split()
		sib := *inputs[0].PDR
		if inputs[0].PDR.ShardID.Equal(l) {
			sib.ShardID = r
			inputs = []ShardInput{inputs[0], {PDR: &sib, IR: inputs[0].IR}}
		} else {
			sib.ShardID = l
			inputs, target = []ShardInput{{PDR: &sib, IR: inputs[0].IR}, inputs[0]}, 1
		}
	}
	trHash := HU([]byte("fixture-technical-record"))
	var scheme types.ShardingScheme
	var ins []types.ShardTreeInput
	confs := make([][]byte, len(inputs))
	for i, in := range inputs {
		h, err := in.PDR.Hash(gocrypto.SHA256)
		if err != nil {
			return nil, err
		}
		confs[i] = h
		if len(inputs) > 1 {
			scheme = append(scheme, in.PDR.ShardID)
		}
		ins = append(ins, types.ShardTreeInput{Shard: in.PDR.ShardID, IR: in.IR, TRHash: trHash[:], ShardConfHash: h})
	}
	pdr := inputs[target].PDR
	tree, err := types.CreateShardTree(scheme, ins, gocrypto.SHA256)
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
	prev := HU([]byte("fixture-previous-seal"))
	seal := &types.UnicitySeal{Version: 1, NetworkID: s.Network, Epoch: s.Epoch, RootChainRoundNumber: s.RootRound,
		Timestamp: SealTime + s.RootRound, PreviousHash: prev[:], Hash: ut.RootHash()}
	k := a.Signers
	if k <= 0 || k > len(a.members) {
		k = len(a.members)
	}
	for _, m := range a.members[:k] {
		if err := seal.Sign(m.info.NodeID, m.signer); err != nil {
			return nil, err
		}
	}
	uc := &types.UnicityCertificate{Version: 1, InputRecord: inputs[target].IR, TRHash: trHash[:], ShardConfHash: confs[target],
		ShardTreeCertificate: stCert, UnicityTreeCertificate: cert, UnicitySeal: seal}
	if tamper != nil {
		tamper(uc)
	}
	return types.Cbor.Marshal(uc)
}

// FixturePDR is a shard configuration with the given validator seeds and epoch.
func FixturePDR(network types.NetworkID, partition types.PartitionID, shard types.ShardID, epoch uint64, validatorSeeds ...string) *types.PartitionDescriptionRecord {
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: network, PartitionID: partition, ShardID: shard, T2Timeout: 5 * time.Second,
		PartitionParams: map[string]string{}, Epoch: epoch}
	for i, s := range validatorSeeds {
		k := KeyFromSeed("validator:" + s).PubKey().SerializeCompressed()
		pdr.Validators = append(pdr.Validators, &types.NodeInfo{NodeID: fmt.Sprintf("validator-%d", i+1), SigKey: k, Stake: 1})
	}
	return pdr
}

// ---- EVM side --------------------------------------------------------------------------------------------------------

// RawLog is one EVM log.
type RawLog struct {
	Address   [20]byte
	Topics    [][32]byte
	RawTopics [][]byte // replaces Topics when set: topics of any width, for malformed-log vectors
	Data      []byte
}

// RawReceipt is one receipt's consensus fields; Type 0 is legacy. Status is the raw status string (0x01 for success).
type RawReceipt struct {
	Type   byte
	Status []byte
	Gas    uint64
	Logs   []RawLog
}

// Encode is the consensus encoding (type || RLP or legacy RLP).
func (r *RawReceipt) Encode() []byte {
	var bloom gethtypes.Bloom
	logs := make([]any, len(r.Logs))
	for i, l := range r.Logs {
		bloom.Add(l.Address[:])
		topics := make([][]byte, len(l.Topics))
		for j, t := range l.Topics {
			topics[j] = bytes.Clone(t[:])
			bloom.Add(t[:])
		}
		if l.RawTopics != nil {
			topics = l.RawTopics
		}
		logs[i] = []any{l.Address[:], topics, l.Data}
	}
	body, err := rlp.EncodeToBytes([]any{r.Status, r.Gas, bloom[:], logs})
	if err != nil {
		panic(err)
	}
	if r.Type == 0 {
		return body
	}
	return append([]byte{r.Type}, body...)
}

type nodeList [][]byte

func (l *nodeList) Put(_, v []byte) error { *l = append(*l, bytes.Clone(v)); return nil }
func (l *nodeList) Delete([]byte) error   { return nil }

// Block is one EVM block's receipt trie and header.
type Block struct {
	Header   []byte
	Root     [32]byte // state root
	receipts *trie.Trie
}

// NewBlock builds the receipt trie of raw receipt values and the pinned Cancun header over it.
func NewBlock(number uint64, receipts [][]byte) (*Block, error) {
	t := trie.NewEmpty(triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil))
	for i, r := range receipts {
		if err := t.Update(rlpUintKey(uint64(i)), r); err != nil {
			return nil, err
		}
	}
	state := HE([]byte(fmt.Sprint("fixture-state-", number)))
	withdrawals, beacon, zero := gethtypes.EmptyWithdrawalsHash, common.Hash{}, uint64(0)
	h := &gethtypes.Header{
		ParentHash: common.Hash(HE([]byte(fmt.Sprint("fixture-parent-", number)))), UncleHash: gethtypes.EmptyUncleHash, Root: state,
		TxHash: common.Hash(HE([]byte(fmt.Sprint("fixture-txs-", number)))), ReceiptHash: t.Hash(), Difficulty: new(big.Int),
		Number: new(big.Int).SetUint64(number), GasLimit: 30_000_000, Time: SealTime + number,
		BaseFee: big.NewInt(7), WithdrawalsHash: &withdrawals, BlobGasUsed: &zero, ExcessBlobGas: &zero, ParentBeaconRoot: &beacon,
	}
	hb, err := rlp.EncodeToBytes(h)
	if err != nil {
		return nil, err
	}
	return &Block{Header: hb, Root: state, receipts: t}, nil
}

// Path is the receipt-trie path of transaction i, root first.
func (b *Block) Path(i uint64) ([][]byte, error) {
	var nl nodeList
	if err := b.receipts.Prove(rlpUintKey(i), &nl); err != nil {
		return nil, err
	}
	return nl, nil
}

// EVMShard is the certified EVM shard: its configuration per shard epoch and the root committee per root epoch.
type EVMShard struct {
	Network   types.NetworkID
	Partition types.PartitionID
	Shard     types.ShardID
	PDRs      []*types.PartitionDescriptionRecord // by shard epoch
}

// CertifyBlock certifies a block's header under the shard epoch's configuration, sealed by committee at the given seal.
// mutIR alters the input record before sealing; tamper alters the certificate after sealing.
func (e *EVMShard) CertifyBlock(b *Block, number, shardEpoch uint64, committee *Committee, s SealOpts, mutIR func(*types.InputRecord), tamper func(*types.UnicityCertificate)) ([]byte, error) {
	bh := HE(b.Header)
	ir := &types.InputRecord{Version: 1, RoundNumber: number, Epoch: shardEpoch, PreviousHash: sl(HU([]byte("fixture-previous-state"))),
		Hash: sl(b.Root), SummaryValue: []byte{}, Timestamp: SealTime + number, BlockHash: bh[:]}
	if mutIR != nil {
		mutIR(ir)
	}
	return committee.CertifyShards(s, []ShardInput{{PDR: e.PDRs[shardEpoch], IR: ir}}, 0, tamper)
}

func sl(h [32]byte) []byte { return h[:] }

// ---- aggregator side -------------------------------------------------------------------------------------------------

type kv struct{ key, value [32]byte }

type rnode struct {
	hash   [32]byte
	leaf   bool
	depth  int
	lo, hi *rnode
}

func rsmtBuild(ls []kv) *rnode {
	if len(ls) == 1 {
		return &rnode{hash: rsmt.HashLeaf(ls[0].key, ls[0].value[:]), leaf: true}
	}
	first, last := ls[0].key, ls[len(ls)-1].key
	d := 0
	for rsmt.KeyBitAt(first, d) == rsmt.KeyBitAt(last, d) {
		d++
	}
	split := sort.Search(len(ls), func(i int) bool { return rsmt.KeyBitAt(ls[i].key, d) == 1 })
	lo, hi := rsmtBuild(ls[:split]), rsmtBuild(ls[split:])
	return &rnode{hash: rsmt.HashNode(lo.hash, hi.hash, uint8(d), rsmt.PrefixRegion(first, d)), depth: d, lo: lo, hi: hi}
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

// Aggregator is the aggregator partition: its shards (one, or two at depth 1) and the committee that seals them.
type Aggregator struct {
	Network   types.NetworkID
	PDRs      []*types.PartitionDescriptionRecord // increasing shard order
	Committee *Committee
	Seal      SealOpts
}

func (a *Aggregator) row(sid [32]byte) int {
	if len(a.PDRs) == 1 {
		return 0
	}
	return int(sid[0] >> 7)
}

// Leaf is one inclusion obligation.
type Leaf struct{ SID, Value [32]byte }

// CertOpts are the per-certification knobs of the negative vectors.
type CertOpts struct {
	IRTime    uint64                          // IR timestamp
	Seal      *SealOpts                       // override the seal
	Committee *Committee                      // override the signing committee
	Partition *types.PartitionID              // certify under another partition ID
	Tamper    func(*types.UnicityCertificate) // alter after sealing
	OtherRow  bool                            // put the leaf into the tree of the shard that does not own it (two shards)
}

// Certify builds one RSMT per shard over the leaves of that shard (plus three filler leaves so paths have siblings),
// certifies each shard root in one root round, and returns (bitmap, siblings, UC) per leaf in order.
func (a *Aggregator) Certify(leaves []Leaf, o CertOpts) ([]InclusionProof, error) {
	groups := make([][]kv, len(a.PDRs))
	rowOf := func(sid [32]byte) int {
		if o.OtherRow {
			return 1 - a.row(sid)
		}
		return a.row(sid)
	}
	for _, l := range leaves {
		r := rowOf(l.SID)
		groups[r] = append(groups[r], kv{l.SID, l.Value})
	}
	for r := range groups {
		for i := 0; i < 3; i++ {
			k := HU([]byte(fmt.Sprintf("agg-filler-%d-%d", r, i)))
			if len(a.PDRs) == 2 {
				k[0] = k[0]&0x7f | byte(r)<<7
			}
			groups[r] = append(groups[r], kv{k, HU(k[:])})
		}
		sort.Slice(groups[r], func(i, j int) bool { return less(groups[r][i].key, groups[r][j].key) })
	}
	roots := make([]*rnode, len(groups))
	irs := make([]*types.InputRecord, len(groups))
	for r := range groups {
		roots[r] = rsmtBuild(groups[r])
		irs[r] = &types.InputRecord{Version: 1, RoundNumber: a.Seal.RootRound, Epoch: a.PDRs[r].Epoch, PreviousHash: sl(HU([]byte("agg-previous-state"))),
			Hash: sl(roots[r].hash), SummaryValue: []byte{}, Timestamp: o.IRTime, BlockHash: sl(HU([]byte("agg-block")))}
	}
	seal, committee := a.Seal, a.Committee
	if o.Seal != nil {
		seal = *o.Seal
	}
	if o.Committee != nil {
		committee = o.Committee
	}
	pdrs := a.PDRs
	if o.Partition != nil {
		pdrs = nil
		for _, p := range a.PDRs {
			q := *p
			q.PartitionID = *o.Partition
			pdrs = append(pdrs, &q)
		}
	}
	ucs := make([][]byte, len(groups))
	inputs := make([]ShardInput, len(groups))
	for r := range groups {
		inputs[r] = ShardInput{PDR: pdrs[r], IR: irs[r]}
	}
	for r := range groups {
		uc, err := committee.CertifyShards(seal, inputs, r, o.Tamper)
		if err != nil {
			return nil, err
		}
		ucs[r] = uc
	}
	out := make([]InclusionProof, len(leaves))
	for i, l := range leaves {
		r := rowOf(l.SID)
		bm, sibs := roots[r].proof(l.SID)
		out[i] = InclusionProof{Bitmap: bm, Siblings: sibs, UC: ucs[r]}
	}
	return out, nil
}
