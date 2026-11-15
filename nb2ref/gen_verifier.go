package nb2ref

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Verifier and configuration vectors.

func (g *gen) configs() error {
	w := g.worlds["main"]
	env := w.Env()
	add := func(id string, gamma []byte, env Environment, ver, cons string) error {
		v := ConfigVector{ID: g.id("config-" + id), Deployment: "main", Gamma: gamma, Address: Hex(env.Address[:]), ChainID: env.ChainID, CodeHash: h32(env.VerifierCodeHash)}
		c, err := DecodeConfig(gamma, w.Params)
		v.Verifier = expectOf(err)
		if err == nil {
			v.Domain = h32(c.Domain())
		}
		_, cerr := Construct(gamma, env, w.Params)
		v.Constructor = expectOf(cerr)
		if v.Verifier.Error != ver || v.Constructor.Error+argStr(v.Constructor.Args) != cons {
			return fmt.Errorf("config %s: verifier %v constructor %v", id, v.Verifier, v.Constructor)
		}
		g.f.Config = append(g.f.Config, v)
		return nil
	}
	mut := func(f func(c *Config)) []byte {
		c := *w.Cfg
		c.Qmax = new(big.Int).Set(w.Cfg.Qmax)
		f(&c)
		return c.Bytes()
	}
	field := func(i int, repl []byte) []byte { // Γ with field i's encoding replaced
		root, _ := scanOne(w.Gamma)
		var items [][]byte
		for j := range root.kids {
			items = append(items, root.kids[j].raw(w.Gamma))
		}
		items[i] = repl
		return CArr(items...)
	}
	steps := []error{
		add("valid", w.Gamma, env, "", ""),
		add("k-not-power-of-two", mut(func(c *Config) { c.K = 3 }), env, "ConfigShape", "BadConfig16"),
		add("k-256", mut(func(c *Config) { c.K = 256 }), env, "ConfigShape", "BadConfig16"),
		add("k-not-admitted", mut(func(c *Config) { c.K = 32 }), env, "ConfigShape", "BadConfig16"),
		add("b-not-admitted", mut(func(c *Config) { c.B = 8 }), env, "ConfigShape", "BadConfig17"),
		add("k-test-value-in-production", mut(func(c *Config) { c.K, c.B = 4, 2 }), env, "ConfigShape", "BadConfig16"),
		add("b-above-k", mut(func(c *Config) { c.B = 128 }), env, "ConfigShape", "BadConfig17"),
		add("qmax-zero", field(18, CBytes(nil)), env, "ConfigShape", "BadConfig18"),
		add("qmax-above-2^144", mut(func(c *Config) { c.Qmax = new(big.Int).Lsh(big.NewInt(1), 144) }), env, "ConfigShape", "BadConfig18"),
		add("same-partitions", mut(func(c *Config) { c.AggregatorPartition = c.EVMPartition }), env, "ConfigShape", "BadConfig8"),
		add("network-zero", mut(func(c *Config) { c.Network = 0 }), env, "ConfigShape", "BadConfig2"),
		add("chain-zero", mut(func(c *Config) { c.ChainID = 0 }), Environment{Address: env.Address, VerifierCodeHash: env.VerifierCodeHash}, "ConfigShape", "BadConfig5"),
		add("shard-empty", mut(func(c *Config) { c.EVMShard = []byte{} }), env, "ConfigShape", "BadConfig7"),
		add("shard-noncanonical", mut(func(c *Config) { c.EVMShard = []byte{0x80, 0x00} }), env, "ConfigShape", "BadConfig7"),
		add("vault-19-bytes", field(9, CBytes(w.Cfg.Vault[:19])), env, "ConfigShape", "BadConfig9"),
		add("domain-literal", field(0, CBytes([]byte("UNICITY_BR_CFG"))), env, "ConfigShape", "BadConfig0"),
		add("version-2", field(1, CUint(2)), env, "ConfigShape", "BadConfig1"),
		add("arity-18", CArr(func() [][]byte {
			r, _ := scanOne(w.Gamma)
			var o [][]byte
			for j := 0; j < 18; j++ {
				o = append(o, r.kids[j].raw(w.Gamma))
			}
			return o
		}()...), env, "ConfigShape", "BadConfig19"),
		add("trailing", append(bytes.Clone(w.Gamma), 0), env, "ConfigShape", "BadConfig19"),
		add("noncanonical-head", field(5, []byte{0x1a, 0x00, 0x00, 0x7a, 0x69}), env, "ConfigShape", "BadConfig19"),
		add("constructor-asset", mut(func(c *Config) { c.Asset = HU([]byte("other-asset")) }), env, "", "BadConfig10"),
		add("constructor-ty", mut(func(c *Config) { c.Ty = HU([]byte("other-type")) }), env, "", "BadConfig11"),
		add("constructor-aid", mut(func(c *Config) { c.Aid = HU([]byte("other-coin")) }), env, "", "BadConfig12"),
		add("constructor-other-address", w.Gamma, Environment{Address: Recipient20("other"), ChainID: env.ChainID, VerifierCodeHash: env.VerifierCodeHash}, "", "BadConfig9"),
		add("constructor-other-chain", w.Gamma, Environment{Address: env.Address, ChainID: 1, VerifierCodeHash: env.VerifierCodeHash}, "", "BadConfig5"),
		add("constructor-verifier-codehash", w.Gamma, Environment{Address: env.Address, ChainID: env.ChainID, VerifierCodeHash: HE([]byte("other"))}, "", "BadConfig15"),
		// Staged constructor precedence (section 4.1), each with two or more faults: the array (19), the fields in index order,
		// then, only for a Γ that decodes completely, asset (10), ty (11), aid (12), vault (9), chainId (5), verifier code hash (15).
		add("constructor-order-chain-env-and-asset", mut(func(c *Config) { c.Asset = HU([]byte("other-asset")) }), Environment{Address: env.Address, ChainID: 1, VerifierCodeHash: env.VerifierCodeHash}, "", "BadConfig10"),
		add("constructor-order-vault-and-ty", mut(func(c *Config) { c.Ty = HU([]byte("other-type")) }), Environment{Address: Recipient20("other"), ChainID: env.ChainID, VerifierCodeHash: env.VerifierCodeHash}, "", "BadConfig11"),
		add("constructor-order-field7-and-asset", mut(func(c *Config) { c.EVMShard = []byte{}; c.Asset = HU([]byte("other-asset")) }), env, "ConfigShape", "BadConfig7"),
		add("constructor-order-chain-env-and-codehash", w.Gamma, Environment{Address: env.Address, ChainID: 1, VerifierCodeHash: HE([]byte("other"))}, "", "BadConfig5"),
		add("constructor-order-array-and-field", append(mut(func(c *Config) { c.Network = 0 }), 0), env, "ConfigShape", "BadConfig19"),
		add("constructor-order-two-fields", mut(func(c *Config) { c.Network = 0; c.EVMShard = []byte{} }), env, "ConfigShape", "BadConfig2"),
		add("constructor-order-aid-and-chain-env", mut(func(c *Config) { c.Aid = HU([]byte("other-coin")) }), Environment{Address: env.Address, ChainID: 1, VerifierCodeHash: env.VerifierCodeHash}, "", "BadConfig12"),
		add("constructor-order-k-before-b", mut(func(c *Config) { c.K, c.B = 4, 0 }), env, "ConfigShape", "BadConfig16"),
		add("constructor-order-over-1024-bytes", append(bytes.Clone(w.Gamma), make([]byte, 1025-len(w.Gamma))...), env, "ConfigShape", "BadConfig19"),
	}
	for _, e := range steps {
		if e != nil {
			return e
		}
	}
	return nil
}

func argStr(a []string) string {
	s := ""
	for _, x := range a {
		s += x
	}
	return s
}

// directOpts builds a depth-0 return: a deposit of Value to key a, transfers through Through, the return burn to "r".
type directOpts struct {
	Value     int64
	Dep       ReceiptOpts
	MutDep    func(*Deposit)
	Through   []string // transfer keys after the owner; default one intermediate owner
	MutDraft  func(*Draft)
	A         uint64
	MutReturn func(*ReturnData)
	MutEv     func(*Token) []byte // the evidence's token bytes
}

func (g *gen) direct(w *World, o directOpts) (*Token, []byte, error) {
	if o.Value == 0 {
		o.Value = 100
	}
	owner := Key("a")
	dep, err := w.MakeDeposit(big.NewInt(o.Value), owner, o.Dep)
	if err != nil {
		return nil, nil, err
	}
	if o.MutDep != nil {
		o.MutDep(dep)
	}
	through := o.Through
	if through == nil {
		through = []string{"b"}
	}
	keys := []*secp256k1.PrivateKey{owner}
	for _, s := range through {
		keys = append(keys, Key(s))
	}
	d := w.RootDraft(dep, keys)
	r := w.ReturnTo(dep.Value, Recipient20("r"), o.A)
	if o.MutReturn != nil {
		o.MutReturn(r)
	}
	d.Return(r)
	if o.MutDraft != nil {
		o.MutDraft(d)
	}
	tok, err := w.Finalize(d)
	if err != nil {
		return nil, nil, err
	}
	tb := tok.Bytes()
	if o.MutEv != nil {
		tb = o.MutEv(tok)
	}
	return tok, Evidence(tb), nil
}

// addVerifier replays one vector and records it.
func (g *gen) addVerifier(id, dep, note string, gamma, evidence []byte, want string) (*Verdict, error) {
	w := g.worlds[dep]
	gm := w.Gamma
	if gamma != nil {
		gm = gamma
	}
	v, err := VerifyReturn(gm, evidence, w.Trust, w.Params)
	if err := checkExpect(id, err, want); err != nil {
		return nil, err
	}
	vec := VerifierVector{ID: g.id(id), Deployment: dep, Note: note, Evidence: evidence, Expect: expectOf(err)}
	if gamma != nil {
		vec.Gamma = gamma
	}
	if v != nil {
		vec.Verdict = verdictJSON(v)
	}
	g.f.Verifier = append(g.f.Verifier, vec)
	return v, nil
}

type vcase struct {
	id, note, want string
	dep            string
	o              directOpts
	gamma          func(w *World) []byte
}

func (g *gen) verifier() error {
	w := g.worlds["main"]
	d := w.Cfg.Domain()
	other := HU([]byte("other"))
	burnAt := func(d *Draft) *TransferTx { return &d.Transfers[len(d.Transfers)-1] }
	setR := func(d *Draft, rb []byte) { t := burnAt(d); t.Data = rb; t.Recipient = BurnPredicate(HU(rb)) }
	rawMint := func(t *Token, f func(m *MintTx) []byte) []byte { t.mintRaw = f(&t.Mint); return t.Bytes() }
	otherRoot, err := NewCommittee("root-other", 3)
	if err != nil {
		return err
	}
	oneSigner, _ := NewCommittee("root-1", 3)
	oneSigner.Signers = 1
	wrongPart := &EVMShard{Network: DevNetwork, Partition: DevEVMPartition + 1, Shard: types.ShardID{}, PDRs: []*types.PartitionDescriptionRecord{
		FixturePDR(DevNetwork, DevEVMPartition+1, types.ShardID{}, 0, "evm-a")}}
	left, _ := types.ShardID{}.Split()
	wrongShard := &EVMShard{Network: DevNetwork, Partition: DevEVMPartition, Shard: left, PDRs: []*types.PartitionDescriptionRecord{
		FixturePDR(DevNetwork, DevEVMPartition, left, 0, "evm-a")}}

	cases := []vcase{
		// Positive.
		{id: "ok-legacy-receipt", note: "legacy receipt at transaction 0", o: directOpts{Dep: ReceiptOpts{Type: 0}}},
		{id: "ok-type1-receipt", o: directOpts{Dep: ReceiptOpts{Type: 1, TxIndex: 1}}},
		{id: "ok-type2-receipt-filler-logs", o: directOpts{Dep: ReceiptOpts{Type: 2, TxIndex: 5, FillerLogs: 3}}},
		{id: "ok-type3-receipt-tx130", note: "two-byte receipt key RLP(130)", o: directOpts{Dep: ReceiptOpts{Type: 3, TxIndex: 130}}},
		{id: "ok-deposit-before-rotation", note: "14.7: shard epoch 0, root epoch 1 (committee root-1)", o: directOpts{Dep: ReceiptOpts{Type: 2, TxIndex: 2}}},
		{id: "ok-deposit-after-rotation", note: "14.7: shard epoch 1 (new validators, new ShardConfHash), root epoch 2 (committee root-2), judged under epoch 2", o: directOpts{Dep: ReceiptOpts{Type: 2, TxIndex: 2, Rotated: true}}},
		{id: "ok-no-intermediate-transfer", o: directOpts{Through: []string{}}},
		{id: "ok-three-owners-min-index-7", o: directOpts{Through: []string{"b", "c", "d"}, A: 7}},
		{id: "ok-max-index", o: directOpts{A: MaxSegment}},
		{id: "ok-deadlines", note: "explicit mint and transfer deadlines with t < e", o: directOpts{MutDraft: func(d *Draft) {
			d.Mint.Deadline = Deadline{Set: true, At: DevTime + 1}
			d.Transfers[0].Deadline = Deadline{Set: true, At: DevTime + 11}
		}}},
		{id: "ok-aggregator-root-epoch-2", note: "every inclusion proof sealed in root epoch 2", o: directOpts{MutDraft: func(d *Draft) {
			d.Cert = map[int]CertOpts{}
			for i := 0; i <= len(d.Transfers); i++ {
				d.Cert[i] = CertOpts{Seal: &SealOpts{Network: DevNetwork, Epoch: 2, RootRound: RotationRound + 5}, Committee: w.Roots[1]}
			}
		}}},
		{id: "ok-sharded-aggregator", dep: "sharded", o: directOpts{Through: []string{"b", "c"}}},
		{id: "ok-extra-malformed-signatures", note: "quorate seals carrying extra signatures of unknown signers (64 bytes; 65 bytes with recovery byte 2): each counts zero and never rejects", o: directOpts{
			Dep: ReceiptOpts{TamperUC: extraSignatures}, MutDraft: func(d *Draft) { d.Cert = map[int]CertOpts{1: {Tamper: extraSignatures}} }}},

		// 14.1 Encoding.
		{id: "Truncated", want: "Truncated", o: directOpts{MutEv: func(t *Token) []byte { b := t.Bytes(); return b[:len(b)-1] }}},
		{id: "Trailing", want: "Trailing", o: directOpts{MutEv: func(t *Token) []byte { return append(t.Bytes(), 0x00) }}},
		{id: "NonCanonical-token-version", note: "token version 2 as a two-byte head", want: "NonCanonical", o: directOpts{MutEv: func(t *Token) []byte {
			b := t.Bytes()
			return replaceOnce(b, []byte{0x83, 0x02, 0x82}, []byte{0x83, 0x18, 0x02, 0x82})
		}}},
		{id: "NonCanonical-float", note: "the token version replaced in place by a half-precision float", want: "NonCanonical", o: directOpts{MutEv: func(t *Token) []byte {
			return replaceOnce(t.Bytes(), []byte{0x83, 0x02, 0x82}, []byte{0x83, 0xf9, 0x40, 0x00, 0x82})
		}}},
		{id: "Shape-token-arity", want: "Shape", o: directOpts{MutEv: func(t *Token) []byte {
			return CTag(TagToken, CArr(CUint(TokenVersion), CArr(t.mintRaw, t.MintProof.Bytes()), CArr(tokenPairs(t)...), CNull))
		}}},
		{id: "Tag-token", want: "Tag", o: directOpts{MutEv: func(t *Token) []byte { b := t.Bytes(); return append(CTag(TagMint, nil)[:3], b[3:]...) }}},
		{id: "Tag-legacy-return-39048", note: "the protocol 7 return tag where the token tag is expected", want: "Tag", o: directOpts{MutEv: func(t *Token) []byte { b := t.Bytes(); return append(CTag(39048, nil)[:3], b[3:]...) }}},
		{id: "Version-token", want: "Version", o: directOpts{MutEv: func(t *Token) []byte {
			return CTag(TagToken, CArr(CUint(3), CArr(t.mintRaw, t.MintProof.Bytes()), CArr(tokenPairs(t)...)))
		}}},
		{id: "Length-mint-salt", want: "Length", o: directOpts{MutEv: func(t *Token) []byte {
			return rawMint(t, func(m *MintTx) []byte {
				return CTag(TagMint, CArr(CUint(TxVersion), CUint(uint64(m.Network)), m.Recipient.Bytes(), CBytes(m.Salt[:31]), CBytes(m.Type[:]), CNullOr(m.Justification), CNullOr(m.Data), CDeadline(m.Deadline)))
			})
		}}},
		{id: "IntRange-deposit-number-zero", want: "IntRange", o: directOpts{MutDep: func(dp *Deposit) { dp.J.N = 0 }}},
		{id: "IntRange-deposit-number-2^56", want: "IntRange", o: directOpts{MutDep: func(dp *Deposit) { dp.J.N = 1 << 56 }}},
		{id: "InputTooLarge-header", note: "a 2049-byte header", want: "InputTooLarge", o: directOpts{MutDep: func(dp *Deposit) { dp.J.Proof.Header = make([]byte, MaxHeaderBytes+1) }}},
		{id: "InputTooLarge-receipt-nodes", note: "66 receipt nodes", want: "InputTooLarge", o: directOpts{MutDep: func(dp *Deposit) {
			for len(dp.J.Proof.Nodes) <= MaxReceiptNodes {
				dp.J.Proof.Nodes = append([][]byte{{0xc0}}, dp.J.Proof.Nodes...)
			}
		}}},
		{id: "cborDepth-16-scans", note: "children at depth 16 in one decoding unit scan; the evidence then fails its shape", want: "EvidenceShape", o: directOpts{MutEv: func(t *Token) []byte { return nested(15) }}},
		{id: "cborDepth-17-InputTooLarge", note: "children at depth 17", want: "InputTooLarge", o: directOpts{MutEv: func(t *Token) []byte { return nested(16) }}},
		{id: "justificationBytes-at-bound", note: "J padded to exactly 65536 bytes: not refused for size (then Trailing)", want: "Trailing", o: directOpts{MutDraft: func(d *Draft) {
			d.Mint.Justification = append(d.Mint.Justification, make([]byte, MaxJustificationBytes-len(d.Mint.Justification))...)
		}}},
		{id: "justificationBytes-over-bound", note: "J padded to 65537 bytes", want: "InputTooLarge", o: directOpts{MutDraft: func(d *Draft) {
			d.Mint.Justification = append(d.Mint.Justification, make([]byte, MaxJustificationBytes+1-len(d.Mint.Justification))...)
		}}},
		{id: "ConfigShape", note: "Γ with K = 3", want: "ConfigShape", gamma: func(w *World) []byte { c := *w.Cfg; c.K = 3; return c.Bytes() }},
		{id: "EvidenceShape-version", want: "EvidenceShape", o: directOpts{MutEv: func(t *Token) []byte { return t.Bytes() }}},

		// 14.2 Deposit evidence.
		{id: "Shape-deposit-proof-arity-7", note: "14.7: the protocol 8 DepositProof with a PDR", want: "Shape", o: directOpts{MutDep: func(dp *Deposit) {
			dp.J.Proof.UC = append([]byte{0xff}, dp.J.Proof.UC...) // marker, rewritten below
		}}},
		{id: "Version-deposit-proof", want: "Version", o: directOpts{MutDep: func(dp *Deposit) {}}},
		{id: "MintDomain", note: "J, the log and rho all name another D; the salt is the verifier's D", want: "MintDomain"},
		{id: "DepositUC-altered-shardconfhash", note: "14.7: ShardConfHash changed after sealing", want: "DepositUC", o: directOpts{Dep: ReceiptOpts{TamperUC: func(uc *types.UnicityCertificate) {
			uc.ShardConfHash = sl(HU([]byte("other-configuration")))
		}}}},
		{id: "DepositUC-wrong-partition", note: "14.7", want: "DepositUC", o: directOpts{Dep: ReceiptOpts{EVM: wrongPart}}},
		{id: "DepositUC-wrong-shard", note: "14.7", want: "DepositUC", o: directOpts{Dep: ReceiptOpts{EVM: wrongShard}}},
		{id: "DepositUC-other-root-deployment", note: "14.7: sealed by a committee of another root deployment on the same network", want: "DepositUC", o: directOpts{Dep: ReceiptOpts{Committee: otherRoot}}},
		{id: "DepositUC-ir-tampered", note: "14.7: InputRecord changed after sealing", want: "DepositUC", o: directOpts{Dep: ReceiptOpts{TamperUC: func(uc *types.UnicityCertificate) {
			uc.InputRecord.Timestamp++
		}}}},
		{id: "DepositUC-quorum", note: "one of three signatures", want: "DepositUC", o: directOpts{Dep: ReceiptOpts{Committee: oneSigner}}},
		{id: "DepositUC-latest-committee", note: "a root epoch 1 seal signed by the epoch 2 committee: never judged by the latest committee", want: "DepositUC", o: directOpts{Dep: ReceiptOpts{Committee: w.Roots[1]}}},
		{id: "DepositUC-seal-network", want: "DepositUC", o: directOpts{Dep: ReceiptOpts{Seal: &SealOpts{Network: DevNetwork + 1, Epoch: 1, RootRound: DevRootRound}}}},
		{id: "NoEntryForEpoch-deposit", note: "retryable", want: "NoEntryForEpoch", o: directOpts{Dep: ReceiptOpts{Seal: &SealOpts{Network: DevNetwork, Epoch: 3, RootRound: 3 * RotationRound}}}},
		{id: "DepositUC-root-before-epoch", note: "multi-fault: the IR changed after sealing and the seal names an epoch the history does not hold; the root fails first (DepositUC, not NoEntryForEpoch)", want: "DepositUC", o: directOpts{Dep: ReceiptOpts{Seal: &SealOpts{Network: DevNetwork, Epoch: 3, RootRound: 3 * RotationRound}, TamperUC: func(uc *types.UnicityCertificate) {
			uc.InputRecord.Timestamp++
		}}}},
		{id: "DepositHeader-tampered", note: "14.7: header bytes changed (extra data), still canonical", want: "DepositHeader", o: directOpts{Dep: ReceiptOpts{MutProof: func(p *DepositProof) {
			p.Header = retaggedHeader(p.Header)
		}}}},
		{id: "DepositHeader-prague-21-fields", note: "a certified header with a 21st field (requestsHash)", want: "DepositHeader", o: directOpts{Dep: ReceiptOpts{MutHeader: pragueHeader}}},
		{id: "DepositHeader-other-block", note: "the parent block's certificate binds another header", want: "DepositHeader", o: directOpts{Dep: ReceiptOpts{MutIR: func(ir *types.InputRecord) {
			h := HE([]byte("parent-header"))
			ir.BlockHash = h[:]
		}}}},
		{id: "ReceiptPath-wrong-index", want: "ReceiptPath", o: directOpts{Dep: ReceiptOpts{TxIndex: 2, MutProof: func(p *DepositProof) { p.TxIndex = 1 }}}},
		{id: "ReceiptPath-extraneous-node", want: "ReceiptPath", o: directOpts{Dep: ReceiptOpts{TxIndex: 2, MutProof: func(p *DepositProof) { p.Nodes = append(p.Nodes, p.Nodes[len(p.Nodes)-1]) }}}},
		{id: "ReceiptType", note: "type byte 4", want: "ReceiptType", o: directOpts{Dep: ReceiptOpts{Type: 4}}},
		{id: "ReceiptStatus", note: "failed transaction", want: "ReceiptStatus", o: directOpts{Dep: ReceiptOpts{Type: 2, MutReceipt: func(r *RawReceipt) { r.Status = []byte{} }}}},
		{id: "LogIndex", want: "LogIndex", o: directOpts{Dep: ReceiptOpts{FillerLogs: 1, MutProof: func(p *DepositProof) { p.LogIndex = 2 }}}},
		{id: "LogEmitter", note: "the same log from another contract", want: "LogEmitter", o: directOpts{Dep: ReceiptOpts{MutLog: func(l *RawLog) { l.Address = Recipient20("impostor") }}}},
		{id: "LogEmitter-before-topics", note: "a wrong emitter and a 31-byte topic: the emitter is checked first", want: "LogEmitter", o: directOpts{Dep: ReceiptOpts{MutLog: func(l *RawLog) {
			l.Address = Recipient20("impostor")
			l.RawTopics = [][]byte{TopicDeposited[:], l.Topics[1][1:]}
		}}}},
		{id: "LogTopics-other-number", note: "a copied commitment under another deposit number: J says n, the log n+1", want: "LogTopics", o: directOpts{Dep: ReceiptOpts{MutLog: func(l *RawLog) {
			l.Topics[1] = u256u(new(big.Int).SetBytes(l.Topics[1][:]).Uint64() + 1)
		}}}},
		{id: "LogData", note: "offset word 0x60", want: "LogData", o: directOpts{Dep: ReceiptOpts{MutLog: func(l *RawLog) { l.Data[127] = 0x60 }}}},
		{id: "SecretOpening", note: "altered secret r", want: "SecretOpening"},
		{id: "MintSalt", want: "MintSalt", o: directOpts{MutDraft: func(d *Draft) { d.Mint.Salt = HU([]byte("other-salt")) }}},
		{id: "MintType", want: "MintType", o: directOpts{MutDraft: func(d *Draft) { d.Mint.Type = other }}},
		{id: "MintOwner", note: "minted to a key other than the deposited first owner", want: "MintOwner", o: directOpts{MutDraft: func(d *Draft) { d.Mint.Recipient = sigPred(Key("thief")); d.Owners[0] = Key("thief") }}},
		{id: "MintData", want: "MintData", o: directOpts{MutDraft: func(d *Draft) { d.Mint.Data = ValueData(w.Cfg.Aid, big.NewInt(99)) }, MutReturn: func(r *ReturnData) { r.Amount = big.NewInt(99) }}},
		{id: "MintReason-legacy-39049", want: "MintReason", o: directOpts{MutDraft: func(d *Draft) {
			d.Mint.Justification = append(CTag(39049, nil)[:3], d.Mint.Justification[3:]...)
		}}},
		{id: "MintReason-null", want: "MintReason", o: directOpts{MutDraft: func(d *Draft) { d.Mint.Justification = nil }}},

		// 14.3 Return.
		{id: "NotBurn", note: "the last transfer goes to a key", want: "NotBurn", o: directOpts{MutDraft: func(d *Draft) {
			t := burnAt(d)
			t.Recipient, t.Data = sigPred(Key("c")), nil
		}}},
		{id: "BurnNotFinal", note: "a return burn followed by a transfer", want: "BurnNotFinal", o: directOpts{MutDraft: func(d *Draft) {
			d.Owners = append(d.Owners, Key("c"))
			d.Transfer(sigPred(Key("c")), Key("c"))
			d.Owners = d.Owners[:len(d.Owners)-1]
		}}},
		{id: "BurnReason", want: "BurnReason", o: directOpts{MutDraft: func(d *Draft) { burnAt(d).Recipient = BurnPredicate(other) }}},
		{id: "ReturnData-arity", want: "ReturnData", o: directOpts{MutDraft: func(d *Draft) {
			setR(d, CTag(TagSegmentReturn, CArr(CUint(1), CBytes(d.Mint.Salt[:]))))
		}}},
		{id: "ReturnData-legacy-39048", want: "ReturnData", o: directOpts{MutDraft: func(d *Draft) {
			rb := burnAt(d).Data
			setR(d, append(CTag(39048, nil)[:3], rb[3:]...))
		}}},
		{id: "ReturnDomain", want: "ReturnDomain", o: directOpts{MutReturn: func(r *ReturnData) { r.D = other }}},
		{id: "ReturnAsset", want: "ReturnAsset", o: directOpts{MutReturn: func(r *ReturnData) { r.Asset = other }}},
		{id: "ReturnAmount", want: "ReturnAmount", o: directOpts{MutReturn: func(r *ReturnData) { r.Amount = big.NewInt(101) }}},
		{id: "ReturnRecipient-zero", want: "ReturnRecipient", o: directOpts{MutReturn: func(r *ReturnData) { r.Recipient = [20]byte{} }}},
		{id: "ReturnRecipient-vault", want: "ReturnRecipient", o: directOpts{MutReturn: func(r *ReturnData) { r.Recipient = w.Cfg.Vault }}},
		{id: "ReturnIndex", note: "a = 2^48", want: "ReturnIndex", o: directOpts{A: MaxSegment + 1}},

		// 14.4 Token.
		{id: "Predicate-type-3", want: "Predicate", o: directOpts{MutEv: func(t *Token) []byte {
			tr := t.Transfers[0]
			tr.Recipient = Predicate{Type: 3, Params: tr.Recipient.Params}
			t.transfersRaw[0] = tr.Bytes()
			return t.Bytes()
		}}},
		{id: "Predicate-burn-params-31", want: "Predicate", o: directOpts{MutEv: func(t *Token) []byte {
			last := len(t.Transfers) - 1
			tr := t.Transfers[last]
			tr.Recipient = Predicate{Type: PredBurn, Params: tr.Recipient.Params[:31]}
			t.transfersRaw[last] = tr.Bytes()
			return t.Bytes()
		}}},
		{id: "MintShape-network", want: "MintShape", o: directOpts{MutDraft: func(d *Draft) { d.Mint.Network = DevNetwork + 1 }}},
		{id: "TransferData", want: "TransferData", o: directOpts{MutDraft: func(d *Draft) { d.Transfers[0].Data = []byte{0x01} }}},
		{id: "CDMismatch", want: "CDMismatch", o: directOpts{MutDraft: func(d *Draft) { d.AfterSign = func(t *Token) { t.Proofs[0].CD.SourceHash = other } }}},
		{id: "UnlockLength", want: "UnlockLength", o: directOpts{MutDraft: func(d *Draft) { d.AfterSign = func(t *Token) { t.Proofs[0].CD.Unlock = t.Proofs[0].CD.Unlock[:64] } }}},
		{id: "UnlockScalars-high-s", want: "UnlockScalars", o: directOpts{MutDraft: func(d *Draft) {
			d.AfterSign = func(t *Token) {
				u := t.Proofs[0].CD.Unlock
				s := new(big.Int).Sub(secpN, new(big.Int).SetBytes(u[32:64]))
				s.FillBytes(u[32:64])
				u[64] ^= 1
			}
		}}},
		{id: "UnlockRecovery", want: "UnlockRecovery", o: directOpts{MutDraft: func(d *Draft) { d.AfterSign = func(t *Token) { t.Proofs[0].CD.Unlock[64] += 4 } }}},
		{id: "UnlockRecovery-id2-lineage", note: "14.4 NB2 unlock restriction: a lineage transfer's unlock with recovery ID 2 is UnlockRecovery (under the SDK relation alone it would be UnlockKey)", want: "UnlockRecovery", o: directOpts{MutDraft: func(d *Draft) { d.AfterSign = func(t *Token) { t.Proofs[0].CD.Unlock[64] = 2 } }}},
		{id: "UnlockRecovery-id3-mint", note: "14.4 NB2 unlock restriction: the mint unlock with recovery ID 3 is UnlockRecovery", want: "UnlockRecovery", o: directOpts{MutDraft: func(d *Draft) { d.AfterSign = func(t *Token) { t.MintProof.CD.Unlock[64] = 3 } }}},
		{id: "UnlockKey", note: "the other recovery ID", want: "UnlockKey", o: directOpts{MutDraft: func(d *Draft) { d.AfterSign = func(t *Token) { t.Proofs[0].CD.Unlock[64] ^= 1 } }}},
		{id: "NoTransfers", note: "a minted token returned with no burn", want: "NoTransfers", o: directOpts{MutDraft: func(d *Draft) { d.Transfers = nil; d.Owners = d.Owners[:1] }}},
		{id: "DeadlineMismatch", want: "DeadlineMismatch", o: directOpts{MutDraft: func(d *Draft) {
			d.AfterSign = func(t *Token) { t.MintProof.CD.Deadline = Deadline{Set: true, At: DevTime + 100} }
		}}},
		{id: "DeadlineExpired", note: "t == e", want: "DeadlineExpired", o: directOpts{MutDraft: func(d *Draft) { d.Mint.Deadline = Deadline{Set: true, At: DevTime} }}},
		{id: "InclusionProof-sibling", want: "InclusionProof", o: directOpts{MutDraft: func(d *Draft) { d.AfterCert = func(t *Token) { t.Proofs[0].Siblings[0][5] ^= 1 } }}},
		{id: "InclusionProof-other-shard", dep: "sharded", note: "the leaf certified in the tree of the shard that does not own its state ID", want: "InclusionProof", o: directOpts{MutDraft: func(d *Draft) {
			d.Cert = map[int]CertOpts{1: {OtherRow: true}}
		}}},
		{id: "ReferenceTime", note: "t one second after the certificate's IR timestamp", want: "ReferenceTime", o: directOpts{MutDraft: func(d *Draft) { d.Cert = map[int]CertOpts{1: {IRTime: DevTime + 9}} }}},
		{id: "SealNetwork", want: "SealNetwork", o: directOpts{MutDraft: func(d *Draft) {
			d.Cert = map[int]CertOpts{1: {Seal: &SealOpts{Network: DevNetwork + 1, Epoch: 1, RootRound: DevRootRound}}}
		}}},
		{id: "SealEpoch", note: "a root epoch 1 seal at a round of epoch 2", want: "SealEpoch", o: directOpts{MutDraft: func(d *Draft) {
			d.Cert = map[int]CertOpts{1: {Seal: &SealOpts{Network: DevNetwork, Epoch: 1, RootRound: RotationRound + 1}}}
		}}},
		{id: "NoEntryForEpoch", note: "retryable", want: "NoEntryForEpoch", o: directOpts{MutDraft: func(d *Draft) {
			d.Cert = map[int]CertOpts{1: {Seal: &SealOpts{Network: DevNetwork, Epoch: 3, RootRound: 3 * RotationRound}}}
		}}},
		{id: "CertStructure-partition", want: "CertStructure", o: directOpts{MutDraft: func(d *Draft) {
			p := types.PartitionID(DevAggPartition + 1)
			d.Cert = map[int]CertOpts{1: {Partition: &p}}
		}}},
		{id: "SealRoot", note: "the IR timestamp changed after sealing", want: "SealRoot", o: directOpts{MutDraft: func(d *Draft) {
			d.Cert = map[int]CertOpts{1: {Tamper: func(uc *types.UnicityCertificate) { uc.InputRecord.Timestamp++ }}}
		}}},
		{id: "SealRoot-before-epoch", note: "multi-fault: the IR changed after sealing and the seal names an epoch the history does not hold; SealRoot is checked first", want: "SealRoot", o: directOpts{MutDraft: func(d *Draft) {
			d.Cert = map[int]CertOpts{1: {Seal: &SealOpts{Network: DevNetwork, Epoch: 3, RootRound: 3 * RotationRound}, Tamper: func(uc *types.UnicityCertificate) { uc.InputRecord.Timestamp++ }}}
		}}},
		{id: "QuorumNotMet", want: "QuorumNotMet", o: directOpts{MutDraft: func(d *Draft) { d.Cert = map[int]CertOpts{1: {Committee: oneSigner}} }}},
		{id: "UnsupportedCertificateEncoding-duplicate-signer", note: "a signature map with one signer key twice", want: "UnsupportedCertificateEncoding", o: directOpts{MutDraft: func(d *Draft) {
			d.AfterCert = func(t *Token) { t.Proofs[0].UC = duplicateSigner(t.Proofs[0].UC) }
		}}},
		{id: "UnsupportedCertificateEncoding", note: "null signature container", want: "UnsupportedCertificateEncoding", o: directOpts{MutDraft: func(d *Draft) {
			d.AfterCert = func(t *Token) { t.Proofs[0].UC = nullSignatures(t.Proofs[0].UC) }
		}}},
	}
	for _, c := range cases {
		dep := c.dep
		if dep == "" {
			dep = "main"
		}
		wd := g.worlds[dep]
		o := c.o
		var gamma []byte
		switch c.id {
		case "ConfigShape":
			gamma = c.gamma(wd)
		case "EvidenceShape-version":
			_, ev, err := g.direct(wd, o)
			if err != nil {
				return err
			}
			ev[1] = 0x02
			if _, err := g.addVerifier(c.id, dep, c.note, nil, ev, c.want); err != nil {
				return err
			}
			continue
		case "Shape-deposit-proof-arity-7", "Version-deposit-proof":
			id := c.id
			o.MutDraft = func(d *Draft) {
				j, _ := DecodeReceiptBacking(d.Mint.Justification)
				p := j.Proof
				var proof []byte
				if id == "Version-deposit-proof" {
					proof = cat(CArr(CUint(2), CBytes(p.UC), CBytes(p.Header), CUint(p.TxIndex), CUint(p.LogIndex), nodesCBOR(p.Nodes)))
				} else {
					pdr, _ := types.Cbor.Marshal(wd.EVM.PDRs[0])
					proof = CArr(CUint(1), CBytes(pdr), CBytes(p.UC), CBytes(p.Header), CUint(p.TxIndex), CUint(p.LogIndex), nodesCBOR(p.Nodes))
				}
				d.Mint.Justification = CTag(TagReceiptBacking, CArr(CUint(1), CBytes(j.D[:]), CUint(j.N), CBytes(j.R[:]), proof))
			}
			o.MutDep = nil
		case "MintDomain":
			o.MutDep = func(dp *Deposit) {}
			o.Dep = ReceiptOpts{}
			// Build the deposit by hand: the log, rho and J carry D'; the mint salt uses the verifier's D.
			if err := g.mintDomainCase(wd, c); err != nil {
				return err
			}
			continue
		case "SecretOpening":
			o.MutDraft = func(d *Draft) {
				j, _ := DecodeReceiptBacking(d.Mint.Justification)
				j.R = HU([]byte("other-secret"))
				d.Mint.Justification = j.Bytes()
				d.Mint.Salt = DepositSalt(wd.Cfg.Domain(), j.N, j.R)
			}
		}
		_, ev, err := g.direct(wd, o)
		if err != nil {
			return fmt.Errorf("%s: %w", c.id, err)
		}
		if _, err := g.addVerifier(c.id, dep, c.note, gamma, ev, c.want); err != nil {
			return err
		}
	}
	_ = d
	return g.splitVectors()
}

func nodesCBOR(nodes [][]byte) []byte {
	items := make([][]byte, len(nodes))
	for i, n := range nodes {
		items[i] = CBytes(n)
	}
	return CArr(items...)
}

func tokenPairs(t *Token) [][]byte {
	pairs := make([][]byte, len(t.Transfers))
	for i := range t.Transfers {
		pairs[i] = CArr(t.transfersRaw[i], t.Proofs[i].Bytes())
	}
	return pairs
}

func replaceOnce(b, old, repl []byte) []byte {
	i := bytes.Index(b, old)
	if i < 0 {
		panic("nb2: pattern not found")
	}
	return append(append(append([]byte{}, b[:i]...), repl...), b[i+len(old):]...)
}

// mintDomainCase: a deposit whose log, rho and J name D' != D while the mint salt is derived from the verifier's D, so only
// MintDomain fails.
func (g *gen) mintDomainCase(w *World, c vcase) error {
	d, dx := w.Cfg.Domain(), HU([]byte("other-domain"))
	owner := Key("a")
	w.nextN++
	n := w.nextN
	r := DepositIntentSecret(w.WalletKey, dx, n)
	value := big.NewInt(100)
	fo := FirstOwner(owner)
	log := RawLog{Address: w.Cfg.Vault, Topics: [][32]byte{TopicDeposited, u256u(n)}, Data: DepositedData(dx, value, Rho(dx, r), fo)}
	p, err := w.ReceiptProof(log, ReceiptOpts{})
	if err != nil {
		return err
	}
	dep := &Deposit{N: n, R: r, Rho: Rho(dx, r), Value: value, Owner: owner, FirstOwner: fo, J: &ReceiptBacking{D: dx, N: n, R: r, Proof: *p}}
	dr := w.RootDraft(dep, []*secp256k1.PrivateKey{owner, Key("b")})
	dr.Mint.Salt = DepositSalt(d, n, r)
	dr.Return(w.ReturnTo(value, Recipient20("r"), 0))
	tok, err := w.Finalize(dr)
	if err != nil {
		return err
	}
	_, err = g.addVerifier(c.id, "main", c.note, nil, Evidence(tok.Bytes()), c.want)
	return err
}

// retaggedHeader re-encodes a header with one byte of extra data: canonical, but not the certified block.
func retaggedHeader(raw []byte) []byte {
	var h gethtypes.Header
	if err := rlp.DecodeBytes(raw, &h); err != nil {
		panic(err)
	}
	h.Extra = []byte{0x01}
	out, err := rlp.EncodeToBytes(&h)
	if err != nil {
		panic(err)
	}
	return out
}

// nullSignatures replaces the seal's signature map with null: a native-admissible container the SDK codec refuses.
func nullSignatures(uc []byte) []byte {
	root, err := scanNative(uc)
	if err != nil {
		panic(err)
	}
	sig := &root.kids[0].kids[6].kids[0].kids[7]
	return cat(uc[:sig.start], CNull, uc[sig.end:])
}

// extraSignatures adds two malformed signatures of unknown signers to a quorate seal (signatures are outside the seal hash).
func extraSignatures(uc *types.UnicityCertificate) {
	bad := make([]byte, 65)
	bad[0], bad[32], bad[64] = 1, 1, 2
	uc.UnicitySeal.Signatures["16Uiu2HAkvzBBDzW9tGGG8QovaWh2K8FFukLA7YLsCrUk8UbKjeTs"] = make([]byte, 64)
	uc.UnicitySeal.Signatures["16Uiu2HAm1uXYgUCnRGbrWnaZqzHBj8SosjmjKWmq52ATaiu3EUzK"] = bad
}

// duplicateSigner repeats the first entry of the seal's signature map.
func duplicateSigner(uc []byte) []byte {
	root, err := scanNative(uc)
	if err != nil {
		panic(err)
	}
	sig := &root.kids[0].kids[6].kids[0].kids[7]
	m := head(majMap, sig.arg+1)
	for i := range sig.kids {
		m = append(m, sig.kids[i].raw(uc)...)
	}
	m = append(m, sig.kids[0].raw(uc)...)
	m = append(m, sig.kids[1].raw(uc)...)
	return cat(uc[:sig.start], m, uc[sig.end:])
}

// nested is an array holding one array ... (depth+1 arrays) around 0: its innermost item sits at depth depth+1. Wrapped as the
// token of an evidence pair it adds one more level.
func nested(depth int) []byte {
	x := CUint(0)
	for i := 0; i < depth; i++ {
		x = CArr(x)
	}
	return x
}

// pragueHeader appends a 32-byte requestsHash to the header list: 21 fields.
func pragueHeader(raw []byte) []byte {
	var fields []rlp.RawValue
	if err := rlp.DecodeBytes(raw, &fields); err != nil {
		panic(err)
	}
	rh := HE([]byte("requests"))
	extra, _ := rlp.EncodeToBytes(rh[:])
	fields = append(fields, extra)
	out, err := rlp.EncodeToBytes(fields)
	if err != nil {
		panic(err)
	}
	return out
}
