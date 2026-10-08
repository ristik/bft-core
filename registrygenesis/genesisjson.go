package registrygenesis

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
	"github.com/unicitynetwork/bft-core/registryproof"
	bfttypes "github.com/unicitynetwork/bft-go-base/types"
)

const (
	maxSourceJSON        = 32 << 20
	maxFinalizedJSON     = 64 << 20
	maxAccounts          = 65_536
	maxStoragePerAccount = 65_536
	maxStorageTotal      = 65_536
	maxCodePerAccount    = 1 << 20
	maxCodeTotal         = 8 << 20
	maxJSONDepth         = 16
	executionProfile     = "unicity/reth-cancun-genesis/v1"
)

var (
	ErrGenesisJSON     = errors.New("registrygenesis: standard genesis JSON invalid")
	ErrGenesisLimit    = errors.New("registrygenesis: genesis JSON resource limit exceeded")
	ErrReservedAccount = errors.New("registrygenesis: reserved genesis account")
	ErrOriginIdentity  = errors.New("registrygenesis: genesis origin identity mismatch")
)

// GenesisJSONLimits bounds parsing before trie construction. The zero value selects DefaultGenesisJSONLimits.
type GenesisJSONLimits struct {
	SourceBytes, FinalizedBytes               int
	Accounts, StoragePerAccount, StorageTotal int
	CodePerAccount, CodeTotal, Depth          int
}

func DefaultGenesisJSONLimits() GenesisJSONLimits {
	return GenesisJSONLimits{maxSourceJSON, maxFinalizedJSON, maxAccounts, maxStoragePerAccount, maxStorageTotal, maxCodePerAccount, maxCodeTotal, maxJSONDepth}
}

func (l GenesisJSONLimits) checked() (GenesisJSONLimits, error) {
	if l == (GenesisJSONLimits{}) {
		return DefaultGenesisJSONLimits(), nil
	}
	vals := []struct {
		name     string
		got, max int
	}{
		{"source bytes", l.SourceBytes, maxSourceJSON}, {"finalized bytes", l.FinalizedBytes, maxFinalizedJSON},
		{"accounts", l.Accounts, maxAccounts}, {"storage per account", l.StoragePerAccount, maxStoragePerAccount},
		{"storage total", l.StorageTotal, maxStorageTotal}, {"code per account", l.CodePerAccount, maxCodePerAccount},
		{"code total", l.CodeTotal, maxCodeTotal}, {"depth", l.Depth, maxJSONDepth},
	}
	for _, v := range vals {
		if v.got <= 0 || v.got > v.max {
			return l, fmt.Errorf("%w: %s is %d, allowed range 1..%d", ErrGenesisLimit, v.name, v.got, v.max)
		}
	}
	return l, nil
}

type importedAccount struct {
	balance *big.Int
	nonce   uint64
	code    []byte
	storage map[common.Hash]common.Hash
}
type importedGenesis struct {
	chainID                             uint64
	nonce, timestamp, gasLimit, baseFee uint64
	difficulty                          *big.Int
	mixHash                             common.Hash
	coinbase                            common.Address
	extra                               []byte
	alloc                               map[common.Address]importedAccount
}

// PreparedGenesis is the immutable result of preparing an operator template.
type PreparedGenesis struct {
	genesis *Genesis
	origin  GenesisOrigin
}

func (p *PreparedGenesis) GenesisJSON() []byte {
	if p == nil {
		return nil
	}
	return p.genesis.GenesisJSON()
}
func (p *PreparedGenesis) FullConfig() (*bfttypes.PartitionDescriptionRecord, error) {
	if p == nil {
		return nil, errors.New("registrygenesis: nil prepared genesis")
	}
	return p.genesis.FullConfig()
}

// B1Words exports every fixed and dynamic registry word of a fresh-B1 genesis (empty for any other layout).
func (p *PreparedGenesis) B1Words() map[common.Hash]common.Hash {
	if p == nil {
		return nil
	}
	return p.genesis.B1Words()
}

// Record is the genesis record G; for a fresh-B1 genesis it carries RootGenesisID and B1ProfileHash.
func (p *PreparedGenesis) Record() Record {
	if p == nil {
		return Record{}
	}
	return p.genesis.Record()
}

func (p *PreparedGenesis) Origin() GenesisOrigin {
	if p == nil {
		return GenesisOrigin{}
	}
	return p.origin.clone()
}

// GenesisOrigin is a checked, immutable execution genesis identity. It is not a certificate or readiness grant.
type GenesisOrigin struct {
	full     common.Hash
	state    common.Hash
	block    common.Hash
	config   common.Hash
	identity common.Hash
	record   Record
	pins     Pins
	evidence registryproof.Evidence
}

func (o GenesisOrigin) Valid() bool                          { return o.identity != (common.Hash{}) }
func (o GenesisOrigin) FullShardConfHash() common.Hash       { return o.full }
func (o GenesisOrigin) StateRoot() common.Hash               { return o.state }
func (o GenesisOrigin) BlockHash() common.Hash               { return o.block }
func (o GenesisOrigin) ExecutionConfigIdentity() common.Hash { return o.config }
func (o GenesisOrigin) Identity() common.Hash                { return o.identity }
func (o GenesisOrigin) Record() Record                       { return o.record.clone() }
func (o GenesisOrigin) ProofContext() registryproof.Context {
	commitment, _ := o.record.Commitment()
	return registryproof.Context{RegistryAddress: o.pins.RegistryAddress, RegistryCodeHash: o.pins.RegistryCodeHash,
		GenesisCommitment: commitment, FullShardConfHash: o.full, ShardEpoch: o.record.ShardEpoch,
		RootEpoch: o.record.RootEpoch, EVMGenesisHash: o.block, Layout: o.record.Layout}
}
func (o GenesisOrigin) Evidence() registryproof.Evidence { return cloneEvidence(o.evidence) }
func (o GenesisOrigin) clone() GenesisOrigin {
	o.record = o.record.clone()
	o.evidence = cloneEvidence(o.evidence)
	return o
}

// PrepareGenesisJSON inserts the generated registry into a reserved-address-free operator template.
func PrepareGenesisJSON(config *bfttypes.PartitionDescriptionRecord, pins Pins, art Artifact, source []byte, limits GenesisJSONLimits) (*PreparedGenesis, error) {
	l, err := limits.checked()
	if err != nil {
		return nil, err
	}
	in, err := parseGenesisJSON(source, l, false)
	if err != nil {
		return nil, err
	}
	if _, ok := in.alloc[pins.SystemAddress]; ok {
		return nil, fmt.Errorf("%w: a_sys %s is allocated", ErrReservedAccount, pins.SystemAddress)
	}
	if _, ok := in.alloc[pins.RegistryAddress]; ok {
		return nil, fmt.Errorf("%w: a_sr %s is allocated", ErrReservedAccount, pins.RegistryAddress)
	}
	g, err := Generate(config, pins, art, EVMParams{GasLimit: in.gasLimit, Coinbase: in.coinbase, ExtraData: in.extra, BaseFee: in.baseFee})
	if err != nil {
		return nil, err
	}
	if in.chainID != g.record.ChainID {
		return nil, fmt.Errorf("%w: JSON chain id %d, shard chain id %d", ErrChainIDMismatch, in.chainID, g.record.ChainID)
	}
	in.alloc[pins.RegistryAddress] = registryAccount(g, art)
	if err := checkAllocLimits(in.alloc, l); err != nil {
		return nil, err
	}
	if err := rebuildImported(g, in, l); err != nil {
		return nil, err
	}
	o, err := originFor(g, in)
	if err != nil {
		return nil, err
	}
	return &PreparedGenesis{genesis: g, origin: o}, nil
}

// ValidateFinalizedGenesisJSON validates without changing the supplied JSON or calling an executor.
// expected may be nil; when present it is an optional distribution/consistency check.
func ValidateFinalizedGenesisJSON(full *bfttypes.PartitionDescriptionRecord, pins Pins, art Artifact, finalized []byte, expected *common.Hash, limits GenesisJSONLimits) (GenesisOrigin, error) {
	if full == nil {
		return GenesisOrigin{}, fmt.Errorf("%w: full shard configuration is nil", ErrGenesisJSON)
	}
	l, err := limits.checked()
	if err != nil {
		return GenesisOrigin{}, err
	}
	in, err := parseGenesisJSON(finalized, l, true)
	if err != nil {
		return GenesisOrigin{}, err
	}
	if _, ok := in.alloc[pins.SystemAddress]; ok {
		return GenesisOrigin{}, fmt.Errorf("%w: a_sys %s is allocated", ErrReservedAccount, pins.SystemAddress)
	}
	base, _, err := baseConfig(full)
	if err != nil {
		return GenesisOrigin{}, err
	}
	delete(base.PartitionParams, GenesisParam)
	g, err := Generate(base, pins, art, EVMParams{GasLimit: in.gasLimit, Coinbase: in.coinbase, ExtraData: in.extra, BaseFee: in.baseFee})
	if err != nil {
		return GenesisOrigin{}, err
	}
	if _, err = VerifyContext(full, pins, g.record); err != nil {
		return GenesisOrigin{}, err
	}
	if in.chainID != g.record.ChainID {
		return GenesisOrigin{}, fmt.Errorf("%w: JSON chain id %d, shard chain id %d", ErrChainIDMismatch, in.chainID, g.record.ChainID)
	}
	want := registryAccount(g, art)
	got, ok := in.alloc[pins.RegistryAddress]
	if !ok || !accountsEqual(got, want) {
		return GenesisOrigin{}, fmt.Errorf("%w: a_sr %s is absent or differs from the generated predeploy", ErrReservedAccount, pins.RegistryAddress)
	}
	if err := checkAllocLimits(in.alloc, l); err != nil {
		return GenesisOrigin{}, err
	}
	if err := rebuildImported(g, in, l); err != nil {
		return GenesisOrigin{}, err
	}
	o, err := originFor(g, in)
	if err != nil {
		return GenesisOrigin{}, err
	}
	if expected != nil && *expected != o.identity {
		return GenesisOrigin{}, fmt.Errorf("%w: expected %s, derived %s", ErrOriginIdentity, *expected, o.identity)
	}
	return o, nil
}

func registryAccount(g *Genesis, art Artifact) importedAccount {
	s := make(map[common.Hash]common.Hash)
	names, _ := registryproof.SlotNamesFor(g.record.layoutVersion())
	for i, n := range names {
		if v := g.storage[n]; v != (common.Hash{}) {
			k, _ := registryproof.SlotKeyFor(g.record.layoutVersion(), i)
			s[k] = v
		}
	}
	for k, v := range g.dynamic {
		if v != (common.Hash{}) {
			s[k] = v
		}
	}
	return importedAccount{balance: new(big.Int), code: bytes.Clone(art.RuntimeCode), storage: s}
}
func accountsEqual(a, b importedAccount) bool {
	return a.nonce == b.nonce && a.balance.Cmp(b.balance) == 0 && bytes.Equal(a.code, b.code) && mapsEqual(a.storage, b.storage)
}
func mapsEqual(a, b map[common.Hash]common.Hash) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func checkAllocLimits(alloc map[common.Address]importedAccount, l GenesisJSONLimits) error {
	if len(alloc) > l.Accounts {
		return fmt.Errorf("%w: %d accounts, limit %d", ErrGenesisLimit, len(alloc), l.Accounts)
	}
	var slots, code int
	for _, a := range alloc {
		if len(a.storage) > l.StoragePerAccount {
			return fmt.Errorf("%w: account storage entries %d, limit %d", ErrGenesisLimit, len(a.storage), l.StoragePerAccount)
		}
		if len(a.code) > l.CodePerAccount {
			return fmt.Errorf("%w: account code is %d bytes, limit %d", ErrGenesisLimit, len(a.code), l.CodePerAccount)
		}
		slots += len(a.storage)
		code += len(a.code)
	}
	if slots > l.StorageTotal {
		return fmt.Errorf("%w: total storage entries %d, limit %d", ErrGenesisLimit, slots, l.StorageTotal)
	}
	if code > l.CodeTotal {
		return fmt.Errorf("%w: total code is %d bytes, limit %d", ErrGenesisLimit, code, l.CodeTotal)
	}
	return nil
}

func rebuildImported(g *Genesis, in *importedGenesis, l GenesisJSONLimits) error {
	state := newTrie()
	var registryStorage *trieProofSource
	for addr, a := range in.alloc {
		storage := newTrie()
		for k, v := range a.storage {
			if v == (common.Hash{}) {
				continue
			}
			enc, err := rlp.EncodeToBytes(common.TrimLeftZeroes(v[:]))
			if err != nil {
				return err
			}
			if err = storage.Update(crypto.Keccak256(k[:]), enc); err != nil {
				return err
			}
		}
		root := storage.Hash()
		codeHash := types.EmptyCodeHash.Bytes()
		if len(a.code) > 0 {
			codeHash = crypto.Keccak256(a.code)
		}
		bal, overflow := uint256.FromBig(a.balance)
		if overflow {
			return fmt.Errorf("%w: balance overflow", ErrGenesisJSON)
		}
		enc, err := rlp.EncodeToBytes(&types.StateAccount{Nonce: a.nonce, Balance: bal, Root: root, CodeHash: codeHash})
		if err != nil {
			return err
		}
		path := crypto.Keccak256(addr[:])
		if err = state.Update(path, enc); err != nil {
			return err
		}
		if addr == g.pins.RegistryAddress {
			if root != g.storageRoot {
				return fmt.Errorf("%w: generated registry storage root %s differs from %s", ErrReservedAccount, root, g.storageRoot)
			}
			registryStorage = &trieProofSource{trie: storage}
		}
	}
	g.stateRoot = state.Hash()
	h := &types.Header{ParentHash: common.Hash{}, UncleHash: types.EmptyUncleHash, Coinbase: in.coinbase, Root: g.stateRoot, TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash, Difficulty: new(big.Int).Set(in.difficulty), Number: new(big.Int), GasLimit: in.gasLimit, GasUsed: 0, Time: in.timestamp, Extra: bytes.Clone(in.extra), MixDigest: in.mixHash, Nonce: types.EncodeNonce(in.nonce), BaseFee: new(big.Int).SetUint64(in.baseFee)}
	withdrawals, beacon := types.EmptyWithdrawalsHash, common.Hash{}
	zero := uint64(0)
	h.WithdrawalsHash = &withdrawals
	h.BlobGasUsed = &zero
	h.ExcessBlobGas = &zero
	h.ParentBeaconRoot = &beacon
	var err error
	g.header, err = rlp.EncodeToBytes(h)
	if err != nil {
		return err
	}
	g.evmGenesisHash = h.Hash()
	path := crypto.Keccak256(g.pins.RegistryAddress[:])
	var ap nodeList
	if err = state.Prove(path, &ap); err != nil {
		return err
	}
	fields, err := registryproof.FieldCountFor(g.record.layoutVersion())
	if err != nil {
		return err
	}
	g.evidence = registryproof.Evidence{Header: bytes.Clone(g.header), AccountProof: ap, StorageProofs: make([][][]byte, fields)}
	if registryStorage == nil {
		return fmt.Errorf("%w: registry absent", ErrReservedAccount)
	}
	for i := 0; i < fields; i++ {
		var p nodeList
		k, err := registryproof.SlotKeyFor(g.record.layoutVersion(), i)
		if err != nil {
			return err
		}
		if err = registryStorage.trie.Prove(crypto.Keccak256(k[:]), &p); err != nil {
			return err
		}
		g.evidence.StorageProofs[i] = p
	}
	g.genesisJSON, err = marshalImported(in)
	if err != nil {
		return err
	}
	if len(g.genesisJSON) > l.FinalizedBytes {
		return fmt.Errorf("%w: finalized JSON is %d bytes, limit %d", ErrGenesisLimit, len(g.genesisJSON), l.FinalizedBytes)
	}
	return nil
}

type trieProofSource struct{ trie *trie.Trie }

func originFor(g *Genesis, in *importedGenesis) (GenesisOrigin, error) {
	cfg, err := executionConfigIdentity(in.chainID)
	if err != nil {
		return GenesisOrigin{}, err
	}
	// OriginIdentity is SHA-256 of deterministic CBOR over this ordered context tuple.
	idBytes, err := bfttypes.Cbor.Marshal([]any{"UNICITY_GENESIS_ORIGIN", executionProfile,
		g.record.NetworkID, g.record.PartitionID, g.record.ShardID, g.fullShardConfHash.Bytes(),
		g.pins.SystemAddress.Bytes(), g.pins.RegistryAddress.Bytes(), g.pins.RegistryCodeHash.Bytes(),
		cfg.Bytes(), g.evmGenesisHash.Bytes(), g.stateRoot.Bytes()})
	if err != nil {
		return GenesisOrigin{}, err
	}
	return GenesisOrigin{full: g.fullShardConfHash, state: g.stateRoot, block: g.evmGenesisHash, config: cfg,
		identity: common.Hash(sha256.Sum256(idBytes)), record: g.record.clone(), pins: g.pins, evidence: cloneEvidence(g.evidence)}, nil
}

func executionConfigIdentity(chainID uint64) (common.Hash, error) {
	// The fixed array is the canonical ExecutionConfigIdentity encoding, in order: profile, chain ID,
	// eleven block-zero forks through MergeNetsplit, Shanghai and Cancun times, terminal total difficulty,
	// and terminal-total-difficulty-passed. All schedule values are zero in this supported profile.
	cfgFields := []any{executionProfile, chainID,
		uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0),
		uint64(0), uint64(0), uint64(0), true}
	cfgBytes, err := bfttypes.Cbor.Marshal(cfgFields)
	if err != nil {
		return common.Hash{}, err
	}
	cfg := common.Hash(sha256.Sum256(cfgBytes))
	return cfg, nil
}

func cloneEvidence(e registryproof.Evidence) registryproof.Evidence {
	out := registryproof.Evidence{Header: bytes.Clone(e.Header), AccountProof: cloneNodes(e.AccountProof), StorageProofs: make([][][]byte, len(e.StorageProofs))}
	for i := range e.StorageProofs {
		out.StorageProofs[i] = cloneNodes(e.StorageProofs[i])
	}
	return out
}

func parseGenesisJSON(data []byte, l GenesisJSONLimits, final bool) (*importedGenesis, error) {
	limit := l.SourceBytes
	if final {
		limit = l.FinalizedBytes
	}
	if len(data) > limit {
		return nil, fmt.Errorf("%w: JSON is %d bytes, limit %d", ErrGenesisLimit, len(data), limit)
	}
	if err := scanJSON(data, l.Depth); err != nil {
		return nil, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGenesisJSON, err)
	}
	if top == nil {
		return nil, fmt.Errorf("%w: top level must be an object", ErrGenesisJSON)
	}
	allowed := []string{"config", "nonce", "timestamp", "extraData", "gasLimit", "difficulty", "mixHash", "coinbase", "alloc", "baseFeePerGas", "number", "parentHash", "gasUsed", "blobGasUsed", "excessBlobGas"}
	if err := keysOnly(top, allowed, "top level"); err != nil {
		return nil, err
	}
	for _, k := range []string{"config", "alloc", "gasLimit", "baseFeePerGas"} {
		if _, ok := top[k]; !ok {
			return nil, fmt.Errorf("%w: missing %s", ErrGenesisJSON, k)
		}
	}
	config, chain, err := parseConfig(top["config"])
	if err != nil {
		return nil, err
	}
	_ = config
	g := &importedGenesis{chainID: chain, difficulty: new(big.Int), alloc: make(map[common.Address]importedAccount)}
	if g.nonce, err = parseOptionalUint(top, "nonce", 64); err != nil {
		return nil, err
	}
	if g.timestamp, err = parseOptionalUint(top, "timestamp", 64); err != nil {
		return nil, err
	}
	if g.gasLimit, err = parseRequiredUint(top, "gasLimit", 64); err != nil || g.gasLimit == 0 {
		if err == nil {
			err = fmt.Errorf("%w: gasLimit is zero", ErrGenesisJSON)
		}
		return nil, err
	}
	if g.baseFee, err = parseRequiredUint(top, "baseFeePerGas", 64); err != nil {
		return nil, err
	}
	if raw, ok := top["difficulty"]; ok {
		g.difficulty, err = parseUint(raw, 256, "difficulty")
		if err != nil {
			return nil, err
		}
	}
	if g.extra, err = parseOptionalBytes(top, "extraData", 32); err != nil {
		return nil, err
	}
	if g.mixHash, err = parseOptionalHash(top, "mixHash"); err != nil {
		return nil, err
	}
	if g.coinbase, err = parseOptionalAddress(top, "coinbase"); err != nil {
		return nil, err
	}
	for _, k := range []string{"number", "gasUsed", "blobGasUsed", "excessBlobGas"} {
		v, e := parseOptionalUint(top, k, 64)
		if e != nil {
			return nil, e
		}
		if v != 0 {
			return nil, fmt.Errorf("%w: %s must be zero", ErrGenesisJSON, k)
		}
	}
	if h, e := parseOptionalHash(top, "parentHash"); e != nil {
		return nil, e
	} else if h != (common.Hash{}) {
		return nil, fmt.Errorf("%w: parentHash must be zero", ErrGenesisJSON)
	}
	if err = parseAlloc(top["alloc"], g, l); err != nil {
		return nil, err
	}
	return g, nil
}

func parseConfig(raw json.RawMessage) (map[string]json.RawMessage, uint64, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, 0, fmt.Errorf("%w: config: %v", ErrGenesisJSON, err)
	}
	if m == nil {
		return nil, 0, fmt.Errorf("%w: config must be an object", ErrGenesisJSON)
	}
	fields := []string{"chainId", "homesteadBlock", "eip150Block", "eip155Block", "eip158Block", "byzantiumBlock", "constantinopleBlock", "petersburgBlock", "istanbulBlock", "berlinBlock", "londonBlock", "mergeNetsplitBlock", "shanghaiTime", "cancunTime", "terminalTotalDifficulty", "terminalTotalDifficultyPassed"}
	if err := keysOnly(m, fields, "config"); err != nil {
		return nil, 0, err
	}
	for _, k := range fields {
		if _, ok := m[k]; !ok {
			return nil, 0, fmt.Errorf("%w: config missing %s", ErrGenesisJSON, k)
		}
	}
	chain, err := parseUint64(m["chainId"], "config.chainId")
	if err != nil {
		return nil, 0, err
	}
	for _, k := range fields[1:14] {
		v, e := parseUint64(m[k], "config."+k)
		if e != nil {
			return nil, 0, e
		}
		if v != 0 {
			return nil, 0, fmt.Errorf("%w: config.%s must be zero", ErrGenesisJSON, k)
		}
	}
	ttd, e := parseUint(m["terminalTotalDifficulty"], 256, "config.terminalTotalDifficulty")
	if e != nil || ttd.Sign() != 0 {
		if e == nil {
			e = fmt.Errorf("%w: terminalTotalDifficulty must be zero", ErrGenesisJSON)
		}
		return nil, 0, e
	}
	var passed bool
	if e = json.Unmarshal(m["terminalTotalDifficultyPassed"], &passed); e != nil || !passed {
		return nil, 0, fmt.Errorf("%w: terminalTotalDifficultyPassed must be true", ErrGenesisJSON)
	}
	return m, chain, nil
}

func parseAlloc(raw json.RawMessage, g *importedGenesis, l GenesisJSONLimits) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("%w: alloc: %v", ErrGenesisJSON, err)
	}
	if m == nil {
		return fmt.Errorf("%w: alloc must be an object", ErrGenesisJSON)
	}
	if len(m) > l.Accounts {
		return fmt.Errorf("%w: %d accounts, limit %d", ErrGenesisLimit, len(m), l.Accounts)
	}
	totalSlots, totalCode := 0, 0
	for text, r := range m {
		addr, err := parseAddressText(text, "alloc address")
		if err != nil {
			return err
		}
		if _, ok := g.alloc[addr]; ok {
			return fmt.Errorf("%w: aliased allocation address %q", ErrGenesisJSON, text)
		}
		var am map[string]json.RawMessage
		if err = json.Unmarshal(r, &am); err != nil {
			return fmt.Errorf("%w: account %s: %v", ErrGenesisJSON, text, err)
		}
		if am == nil {
			return fmt.Errorf("%w: account %s must be an object", ErrGenesisJSON, text)
		}
		if err = keysOnly(am, []string{"balance", "nonce", "code", "storage"}, "account "+text); err != nil {
			return err
		}
		br, ok := am["balance"]
		if !ok {
			return fmt.Errorf("%w: account %s missing balance", ErrGenesisJSON, text)
		}
		bal, err := parseUint(br, 256, "balance")
		if err != nil {
			return err
		}
		a := importedAccount{balance: bal, storage: make(map[common.Hash]common.Hash)}
		if a.nonce, err = parseOptionalUint(am, "nonce", 64); err != nil {
			return err
		}
		if a.code, err = parseOptionalBytes(am, "code", l.CodePerAccount); err != nil {
			return err
		}
		totalCode += len(a.code)
		if totalCode > l.CodeTotal {
			return fmt.Errorf("%w: total code is %d bytes, limit %d", ErrGenesisLimit, totalCode, l.CodeTotal)
		}
		if sr, ok := am["storage"]; ok {
			var sm map[string]json.RawMessage
			if err = json.Unmarshal(sr, &sm); err != nil {
				return fmt.Errorf("%w: storage: %v", ErrGenesisJSON, err)
			}
			if sm == nil {
				return fmt.Errorf("%w: storage must be an object", ErrGenesisJSON)
			}
			if len(sm) > l.StoragePerAccount {
				return fmt.Errorf("%w: account storage entries %d, limit %d", ErrGenesisLimit, len(sm), l.StoragePerAccount)
			}
			totalSlots += len(sm)
			if totalSlots > l.StorageTotal {
				return fmt.Errorf("%w: total storage entries %d, limit %d", ErrGenesisLimit, totalSlots, l.StorageTotal)
			}
			seenStorage := make(map[common.Hash]struct{}, len(sm))
			for kt, vr := range sm {
				k, e := parseWord(kt, "storage key")
				if e != nil {
					return e
				}
				if _, exists := seenStorage[k]; exists {
					return fmt.Errorf("%w: aliased storage key %q", ErrGenesisJSON, kt)
				}
				seenStorage[k] = struct{}{}
				var vs string
				if e = json.Unmarshal(vr, &vs); e != nil {
					return fmt.Errorf("%w: storage value is not a string", ErrGenesisJSON)
				}
				v, e := parseWord(vs, "storage value")
				if e != nil {
					return e
				}
				if v != (common.Hash{}) {
					a.storage[k] = v
				}
			}
		}
		g.alloc[addr] = a
	}
	return nil
}

func scanJSON(data []byte, maxDepth int) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := scanValue(d, 0, maxDepth); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing JSON", ErrGenesisJSON)
	}
	return nil
}
func scanValue(d *json.Decoder, depth, max int) error {
	t, err := d.Token()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrGenesisJSON, err)
	}
	del, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	if depth+1 > max {
		return fmt.Errorf("%w: nesting exceeds %d", ErrGenesisLimit, max)
	}
	switch del {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return err
			}
			s, ok := k.(string)
			if !ok {
				return fmt.Errorf("%w: object key is not string", ErrGenesisJSON)
			}
			if seen[s] {
				return fmt.Errorf("%w: duplicate key %q", ErrGenesisJSON, s)
			}
			seen[s] = true
			if err = scanValue(d, depth+1, max); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	case '[':
		for d.More() {
			if err = scanValue(d, depth+1, max); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	default:
		return fmt.Errorf("%w: unexpected delimiter", ErrGenesisJSON)
	}
}
func keysOnly(m map[string]json.RawMessage, allowed []string, where string) error {
	for k := range m {
		if !slices.Contains(allowed, k) {
			return fmt.Errorf("%w: unsupported %s field %q", ErrGenesisJSON, where, k)
		}
	}
	return nil
}
func parseOptionalUint(m map[string]json.RawMessage, k string, bits int) (uint64, error) {
	r, ok := m[k]
	if !ok {
		return 0, nil
	}
	v, e := parseUint(r, bits, k)
	if e != nil {
		return 0, e
	}
	return v.Uint64(), nil
}
func parseRequiredUint(m map[string]json.RawMessage, k string, bits int) (uint64, error) {
	r, ok := m[k]
	if !ok {
		return 0, fmt.Errorf("%w: missing %s", ErrGenesisJSON, k)
	}
	v, e := parseUint(r, bits, k)
	if e != nil {
		return 0, e
	}
	return v.Uint64(), nil
}
func parseUint64(r json.RawMessage, name string) (uint64, error) {
	v, e := parseUint(r, 64, name)
	if e != nil {
		return 0, e
	}
	return v.Uint64(), nil
}
func parseUint(r json.RawMessage, bits int, name string) (*big.Int, error) {
	s := string(bytes.TrimSpace(r))
	if len(s) > 0 && s[0] == '"' {
		if err := json.Unmarshal(r, &s); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrGenesisJSON, name)
		}
	}
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		s = s[2:]
	}
	if s == "" {
		return nil, fmt.Errorf("%w: empty %s", ErrGenesisJSON, name)
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9') && !(base == 16 && ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
			return nil, fmt.Errorf("%w: %s is not an unsigned integer", ErrGenesisJSON, name)
		}
	}
	significant := strings.TrimLeft(s, "0")
	if significant == "" {
		significant = "0"
	}
	maxDigits := (bits + 3) / 4
	if base == 10 {
		maxDigits = len(new(big.Int).Lsh(big.NewInt(1), uint(bits)).String())
	}
	if len(significant) > maxDigits {
		return nil, fmt.Errorf("%w: %s exceeds uint%d", ErrGenesisJSON, name, bits)
	}
	s = significant
	v, ok := new(big.Int).SetString(s, base)
	if !ok || v.BitLen() > bits {
		return nil, fmt.Errorf("%w: %s exceeds uint%d", ErrGenesisJSON, name, bits)
	}
	return v, nil
}
func parseOptionalBytes(m map[string]json.RawMessage, k string, max int) ([]byte, error) {
	r, ok := m[k]
	if !ok {
		return nil, nil
	}
	var s string
	if err := json.Unmarshal(r, &s); err != nil {
		return nil, fmt.Errorf("%w: %s is not hex bytes", ErrGenesisJSON, k)
	}
	if !strings.HasPrefix(s, "0x") || len(s)%2 != 0 {
		return nil, fmt.Errorf("%w: %s is not even-length 0x bytes", ErrGenesisJSON, k)
	}
	if (len(s)-2)/2 > max {
		return nil, fmt.Errorf("%w: %s is more than %d bytes", ErrGenesisLimit, k, max)
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrGenesisJSON, k, err)
	}
	if len(b) > max {
		return nil, fmt.Errorf("%w: %s is %d bytes, limit %d", ErrGenesisLimit, k, len(b), max)
	}
	return b, nil
}
func parseOptionalHash(m map[string]json.RawMessage, k string) (common.Hash, error) {
	r, ok := m[k]
	if !ok {
		return common.Hash{}, nil
	}
	var s string
	if err := json.Unmarshal(r, &s); err != nil {
		return common.Hash{}, fmt.Errorf("%w: %s", ErrGenesisJSON, k)
	}
	b, err := decodeFixed(s, 32, k)
	if err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(b), nil
}
func parseOptionalAddress(m map[string]json.RawMessage, k string) (common.Address, error) {
	r, ok := m[k]
	if !ok {
		return common.Address{}, nil
	}
	var s string
	if err := json.Unmarshal(r, &s); err != nil {
		return common.Address{}, fmt.Errorf("%w: %s", ErrGenesisJSON, k)
	}
	return parseAddressText(s, k)
}
func parseAddressText(s, name string) (common.Address, error) {
	raw := s
	if strings.HasPrefix(raw, "0x") {
		raw = raw[2:]
	}
	if len(raw) != 40 {
		return common.Address{}, fmt.Errorf("%w: %s must be exactly 20 hexadecimal bytes", ErrGenesisJSON, name)
	}
	b, err := hex.DecodeString(raw)
	if err != nil {
		return common.Address{}, fmt.Errorf("%w: %s: %v", ErrGenesisJSON, name, err)
	}
	return common.BytesToAddress(b), nil
}
func decodeFixed(s string, n int, name string) ([]byte, error) {
	if !strings.HasPrefix(s, "0x") || len(s) != 2+n*2 {
		return nil, fmt.Errorf("%w: %s must be exactly %d 0x-prefixed bytes", ErrGenesisJSON, name, n)
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrGenesisJSON, name, err)
	}
	return b, nil
}
func parseWord(s, name string) (common.Hash, error) {
	if !strings.HasPrefix(s, "0x") || len(s) <= 2 || len(s) > 66 {
		return common.Hash{}, fmt.Errorf("%w: %s must be 1..32 hexadecimal bytes", ErrGenesisJSON, name)
	}
	h := s[2:]
	if len(h)%2 != 0 {
		h = "0" + h
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return common.Hash{}, fmt.Errorf("%w: %s: %v", ErrGenesisJSON, name, err)
	}
	return common.BytesToHash(b), nil
}

func marshalImported(g *importedGenesis) ([]byte, error) {
	type acct struct {
		Balance string            `json:"balance"`
		Nonce   string            `json:"nonce,omitempty"`
		Code    string            `json:"code,omitempty"`
		Storage map[string]string `json:"storage,omitempty"`
	}
	alloc := make(map[string]acct, len(g.alloc))
	for addr, a := range g.alloc {
		s := map[string]string{}
		for k, v := range a.storage {
			s[strings.ToLower(k.Hex())] = strings.ToLower(v.Hex())
		}
		x := acct{Balance: fmt.Sprintf("0x%x", a.balance), Code: hexutil.Encode(a.code), Storage: s}
		if a.nonce != 0 {
			x.Nonce = fmt.Sprintf("0x%x", a.nonce)
		}
		if len(a.code) == 0 {
			x.Code = ""
		}
		if len(s) == 0 {
			x.Storage = nil
		}
		alloc[strings.ToLower(addr.Hex())] = x
	}
	config := gethChainConfig{ChainID: g.chainID, TerminalTotalDifficultyPassed: true}
	out := struct {
		Config        gethChainConfig `json:"config"`
		Nonce         string          `json:"nonce"`
		Timestamp     string          `json:"timestamp"`
		ExtraData     string          `json:"extraData"`
		GasLimit      string          `json:"gasLimit"`
		Difficulty    string          `json:"difficulty"`
		MixHash       string          `json:"mixHash"`
		Coinbase      string          `json:"coinbase"`
		Alloc         map[string]acct `json:"alloc"`
		BaseFee       string          `json:"baseFeePerGas"`
		Number        string          `json:"number"`
		ParentHash    string          `json:"parentHash"`
		GasUsed       string          `json:"gasUsed"`
		BlobGasUsed   string          `json:"blobGasUsed"`
		ExcessBlobGas string          `json:"excessBlobGas"`
	}{Config: config, Nonce: fmt.Sprintf("0x%x", g.nonce), Timestamp: fmt.Sprintf("0x%x", g.timestamp), ExtraData: hexutil.Encode(g.extra), GasLimit: fmt.Sprintf("0x%x", g.gasLimit), Difficulty: fmt.Sprintf("0x%x", g.difficulty), MixHash: g.mixHash.Hex(), Coinbase: g.coinbase.Hex(), Alloc: alloc, BaseFee: fmt.Sprintf("0x%x", g.baseFee), Number: "0x0", ParentHash: common.Hash{}.Hex(), GasUsed: "0x0", BlobGasUsed: "0x0", ExcessBlobGas: "0x0"}
	return json.MarshalIndent(out, "", "  ")
}

// ErrGenesisRootEpoch is a finalized genesis whose root epoch cannot be a root epoch this node can run under: absent, zero, or not
// representable.
var ErrGenesisRootEpoch = errors.New("registrygenesis: the finalized genesis carries no usable root epoch")

// RootEpochOf reads the root epoch a finalized genesis was generated at: the a_sr storage word assignment.rootEpoch. It is only a
// reading: ValidateFinalizedGenesisJSON re-derives the genesis with this value and refuses unless the commitment and the predeployed
// account reproduce exactly, so a number that was not the one G commits to fails there. The genesis is authenticated by block 0 and the
// root-certified registry snapshots, never by the number alone.
func RootEpochOf(finalized []byte, layout uint64, limits GenesisJSONLimits) (uint64, error) {
	l, err := limits.checked()
	if err != nil {
		return 0, err
	}
	in, err := parseGenesisJSON(finalized, l, true)
	if err != nil {
		return 0, err
	}
	names, err := registryproof.SlotNamesFor(layout)
	if err != nil {
		return 0, err
	}
	acct, ok := in.alloc[registryproof.RegistryAddress]
	if !ok {
		return 0, fmt.Errorf("%w: a_sr %s is not allocated", ErrGenesisRootEpoch, registryproof.RegistryAddress)
	}
	for i, n := range names {
		if n != "assignment.rootEpoch" {
			continue
		}
		k, err := registryproof.SlotKeyFor(layout, i)
		if err != nil {
			return 0, err
		}
		v := acct.storage[k]
		if new(big.Int).SetBytes(v[:]).BitLen() > 64 {
			return 0, fmt.Errorf("%w: the word does not fit 64 bits", ErrGenesisRootEpoch)
		}
		return binary.BigEndian.Uint64(v[24:]), nil
	}
	return 0, fmt.Errorf("%w: layout %d has no assignment.rootEpoch slot", ErrGenesisRootEpoch, layout)
}
