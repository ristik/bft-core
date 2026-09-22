/*
Package registrygenesis builds the authenticated genesis of the SealRegistry (profile sealRegistry/v1)
exactly as docs/design/f4a-seal-registry-contract.md §5.3 orders it:

 1. the base configuration, the record with seal_registry_genesis absent, and baseConfigHash;
 2. the genesis record G over baseConfigHash, the pinned registry code hash and the root epoch, and
    genesisCommitment = SHA-256(CBOR(G));
 3. the full configuration with seal_registry_genesis set, and fullShardConfHash;
 4. the six §5.4 storage words;
 5. the EVM genesis allocation (the pinned runtime code and those words at a_sr), its state root, the
    Cancun genesis header and evmGenesisHash.

Each step reads only earlier steps. The package also provides the §5.3 startup context check
(VerifyContext) and the genesis proof material a node would retain as witness(evmGenesisHash) (§8.2).

The CLI genesis command generates the finalized artifact and prints the derived GenesisOrigin (its only
production importer), but no node consumes one yet: nothing derives readiness or authority from it
(inert_test.go).
*/
package registrygenesis

import (
	"bytes"
	gocrypto "crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"regexp"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/holiman/uint256"
	"github.com/unicitynetwork/bft-core/registryproof"
	bfttypes "github.com/unicitynetwork/bft-go-base/types"
)

const (
	// GenesisParam is the partition parameter that carries genesisCommitment (§5.2).
	GenesisParam = "seal_registry_genesis"
	// ChainIDParam is the partition parameter that carries the EVM chain id.
	ChainIDParam = "chain_id"

	genesisDomain = "UNICITY_SEAL_REGISTRY_GENESIS"
)

// SystemAddress is a_sys of the v1 profile (§2.1).
var SystemAddress = common.HexToAddress("0xff00000000000000000000000000000000000001")

var (
	ErrArtifact        = errors.New("registrygenesis: registry artifact invalid")
	ErrPins            = errors.New("registrygenesis: independent pins invalid")
	ErrAlreadyBound    = errors.New("registrygenesis: configuration already carries seal_registry_genesis")
	ErrNoChainID       = errors.New("registrygenesis: configuration has no valid chain_id partition parameter")
	ErrGenesisEncoding = errors.New("registrygenesis: seal_registry_genesis is not 64 lowercase hex characters")
	ErrGenesisMismatch = errors.New("registrygenesis: seal_registry_genesis does not equal the commitment of G")
	ErrBaseConfig      = errors.New("registrygenesis: G base configuration hash is not the configuration's")
	ErrChainIDMismatch = errors.New("registrygenesis: G chain id does not equal the configured chain_id")
	ErrContextMismatch = errors.New("registrygenesis: G does not match the configured context")
	ErrEVMParams       = errors.New("registrygenesis: EVM genesis parameters invalid")
)

var lowerHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Pins are the expected values that do not come from the shard configuration record (§5.3): the root
// epoch of the node's configured trust base, the deployment's registry code hash, and the two addresses.
type Pins struct {
	RootEpoch        uint64
	RegistryCodeHash common.Hash
	SystemAddress    common.Address
	RegistryAddress  common.Address
}

func (p Pins) check() error {
	if p.SystemAddress != SystemAddress || p.RegistryAddress != registryproof.RegistryAddress {
		return fmt.Errorf("%w: addresses %s and %s are not the v1 a_sys %s and a_sr %s", ErrPins, p.SystemAddress, p.RegistryAddress, SystemAddress, registryproof.RegistryAddress)
	}
	if p.RegistryCodeHash == (common.Hash{}) {
		return fmt.Errorf("%w: registry code hash is zero", ErrPins)
	}
	return nil
}

// Record is the genesis record G of §5.1. No field is derived from the EVM genesis block.
type Record struct {
	NetworkID        uint64
	PartitionID      uint64
	ShardID          []byte
	ChainID          uint64
	SystemAddress    common.Address
	RegistryAddress  common.Address
	RegistryCodeHash common.Hash
	BaseConfigHash   common.Hash
	ShardEpoch       uint64
	RootEpoch        uint64
}

func (g Record) clone() Record {
	g.ShardID = bytes.Clone(g.ShardID)
	return g
}

// Encode is CBOR(G): deterministic CBOR of the twelve-element array of §5.1.
func (g Record) Encode() ([]byte, error) {
	return bfttypes.Cbor.Marshal([]any{
		genesisDomain, uint64(registryproof.LayoutVersion),
		g.NetworkID, g.PartitionID, g.ShardID, g.ChainID,
		g.SystemAddress.Bytes(), g.RegistryAddress.Bytes(),
		g.RegistryCodeHash.Bytes(), g.BaseConfigHash.Bytes(),
		g.ShardEpoch, g.RootEpoch,
	})
}

// Commitment is genesisCommitment = SHA-256(CBOR(G)).
func (g Record) Commitment() (common.Hash, error) {
	enc, err := g.Encode()
	if err != nil {
		return common.Hash{}, err
	}
	return sha256.Sum256(enc), nil
}

// EVMParams are the EVM genesis header inputs other than the state root. Timestamp and number are 0, and
// Shanghai and Cancun are active at genesis with nothing later scheduled, as `ubft engine-api genesis`
// schedules them.
type EVMParams struct {
	GasLimit  uint64
	Coinbase  common.Address
	ExtraData []byte
	BaseFee   uint64
}

// DefaultEVMParams are the values `ubft engine-api genesis` writes by default.
var DefaultEVMParams = EVMParams{GasLimit: 30_000_000, BaseFee: 1_000_000_000}

func (e EVMParams) check() error {
	if e.GasLimit == 0 {
		return fmt.Errorf("%w: gas limit is zero", ErrEVMParams)
	}
	if len(e.ExtraData) > 32 {
		return fmt.Errorf("%w: genesis extraData is %d bytes, at most 32", ErrEVMParams, len(e.ExtraData))
	}
	return nil
}

/*
Genesis is the output of Generate. It has no exported field: every value is fixed when Generate returns,
and every accessor returns a copy, so no caller can change a value another accessor derives from (the
same boundary #156's review required of registryproof.Snapshot).
*/
type Genesis struct {
	baseConfigHash    common.Hash
	record            Record
	recordCBOR        []byte
	genesisCommitment common.Hash
	fullConfigCBOR    []byte
	fullShardConfHash common.Hash
	storage           map[string]common.Hash
	storageRoot       common.Hash
	stateRoot         common.Hash
	header            []byte
	evmGenesisHash    common.Hash
	genesisJSON       []byte
	pins              Pins
	evidence          registryproof.Evidence
}

/*
Generate runs §5.3 steps 1 to 5 from a configuration that does not yet carry seal_registry_genesis.

The configuration supplies network, partition, shard, chain id and shard epoch; pins supply the root epoch,
code hash and addresses; the artifact supplies the runtime code, which must hash to pins.RegistryCodeHash.
Nothing is read from an execution client, and the same inputs always produce the same bytes. The caller's
configuration and artifact are not modified or retained.
*/
func Generate(config *bfttypes.PartitionDescriptionRecord, pins Pins, art Artifact, evm EVMParams) (*Genesis, error) {
	if config == nil {
		return nil, fmt.Errorf("%w: configuration is nil", ErrNoChainID)
	}
	if err := pins.check(); err != nil {
		return nil, err
	}
	art = Artifact{RuntimeCode: bytes.Clone(art.RuntimeCode), CodeHash: art.CodeHash}
	if err := art.check(); err != nil {
		return nil, err
	}
	if art.CodeHash != pins.RegistryCodeHash {
		return nil, fmt.Errorf("%w: artifact code hash %s is not the pinned %s", ErrPins, art.CodeHash, pins.RegistryCodeHash)
	}
	evm.ExtraData = bytes.Clone(evm.ExtraData)
	if err := evm.check(); err != nil {
		return nil, err
	}
	if _, ok := config.PartitionParams[GenesisParam]; ok {
		return nil, ErrAlreadyBound
	}

	// Step 1.
	base, chainID, err := baseConfig(config)
	if err != nil {
		return nil, err
	}
	baseHash, err := configHash(base)
	if err != nil {
		return nil, err
	}

	// Step 2.
	g := Record{
		NetworkID: uint64(base.NetworkID), PartitionID: uint64(base.PartitionID), ShardID: base.ShardID.Bytes(),
		ChainID: chainID, SystemAddress: pins.SystemAddress, RegistryAddress: pins.RegistryAddress,
		RegistryCodeHash: pins.RegistryCodeHash, BaseConfigHash: baseHash,
		ShardEpoch: base.Epoch, RootEpoch: pins.RootEpoch,
	}
	enc, err := g.Encode()
	if err != nil {
		return nil, err
	}
	commitment := common.Hash(sha256.Sum256(enc))

	// Step 3.
	full := *base
	full.PartitionParams = maps.Clone(base.PartitionParams)
	full.PartitionParams[GenesisParam] = hex.EncodeToString(commitment[:])
	fullHash, err := configHash(&full)
	if err != nil {
		return nil, err
	}
	fullCBOR, err := bfttypes.Cbor.Marshal(&full)
	if err != nil {
		return nil, err
	}

	// Step 4.
	words := map[string]common.Hash{
		"layoutVersion":        wordUint(registryproof.LayoutVersion),
		"genesisCommitment":    commitment,
		"config.shardConfHash": fullHash,
		"assignment.epoch":     wordUint(g.ShardEpoch),
		"assignment.rootEpoch": wordUint(g.RootEpoch),
		"phase":                wordUint(2),
	}

	out := &Genesis{
		baseConfigHash: baseHash, record: g, recordCBOR: enc, genesisCommitment: commitment,
		fullConfigCBOR: fullCBOR, fullShardConfHash: fullHash, storage: words, pins: pins,
	}
	// Step 5.
	if err := out.buildEVMGenesis(chainID, art, evm); err != nil {
		return nil, err
	}
	return out, nil
}

// baseConfig copies the record with only seal_registry_genesis removed and parses chain_id, which must
// be present so the reduced parameter map is never empty (§5.2). chain_id must be the canonical base-10
// form, so one configuration cannot name a chain id two ways.
func baseConfig(pdr *bfttypes.PartitionDescriptionRecord) (*bfttypes.PartitionDescriptionRecord, uint64, error) {
	raw, ok := pdr.PartitionParams[ChainIDParam]
	if !ok {
		return nil, 0, ErrNoChainID
	}
	chainID, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || strconv.FormatUint(chainID, 10) != raw {
		return nil, 0, fmt.Errorf("%w: %q is not a canonical base-10 uint64", ErrNoChainID, raw)
	}
	base := *pdr
	base.PartitionParams = maps.Clone(pdr.PartitionParams)
	delete(base.PartitionParams, GenesisParam)
	return &base, chainID, nil
}

func configHash(pdr *bfttypes.PartitionDescriptionRecord) (common.Hash, error) {
	h, err := pdr.Hash(gocrypto.SHA256)
	if err != nil {
		return common.Hash{}, err
	}
	if len(h) != common.HashLength {
		return common.Hash{}, fmt.Errorf("configuration hash is %d bytes", len(h))
	}
	return common.Hash(h), nil
}

func wordUint(v uint64) common.Hash { return common.BigToHash(new(big.Int).SetUint64(v)) }

type nodeList [][]byte

func (l *nodeList) Put(_, v []byte) error { *l = append(*l, bytes.Clone(v)); return nil }
func (l *nodeList) Delete([]byte) error   { return nil }

func newTrie() *trie.Trie { return trie.NewEmpty(triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil)) }

// buildEVMGenesis commits the allocation to a state trie, builds the header the way the pinned reth builds
// a genesis header for a Cancun-at-genesis chain (crates/chainspec/src/spec.rs make_genesis_header at
// 189c0df3), and takes the genesis proof for the §4.1 key list.
func (g *Genesis) buildEVMGenesis(chainID uint64, art Artifact, evm EVMParams) error {
	storage := newTrie()
	slotPaths := make([][]byte, registryproof.FieldCount)
	for i, name := range registryproof.SlotNames {
		key := registryproof.SlotKey(i)
		slotPaths[i] = crypto.Keccak256(key[:])
		if w := g.storage[name]; w != (common.Hash{}) {
			v, err := rlp.EncodeToBytes(common.TrimLeftZeroes(w[:]))
			if err != nil {
				return err
			}
			if err := storage.Update(slotPaths[i], v); err != nil {
				return err
			}
		}
	}
	g.storageRoot = storage.Hash()

	account, err := rlp.EncodeToBytes(&types.StateAccount{
		Nonce: 0, Balance: new(uint256.Int), Root: g.storageRoot, CodeHash: art.CodeHash.Bytes(),
	})
	if err != nil {
		return err
	}
	state := newTrie()
	accountPath := crypto.Keccak256(g.pins.RegistryAddress[:])
	if err := state.Update(accountPath, account); err != nil {
		return err
	}
	g.stateRoot = state.Hash()

	header := genesisHeader(evm, g.stateRoot)
	if g.header, err = rlp.EncodeToBytes(header); err != nil {
		return err
	}
	g.evmGenesisHash = header.Hash()

	var accountProof nodeList
	if err := state.Prove(accountPath, &accountProof); err != nil {
		return err
	}
	g.evidence = registryproof.Evidence{Header: bytes.Clone(g.header), AccountProof: accountProof, StorageProofs: make([][][]byte, registryproof.FieldCount)}
	for i := range slotPaths {
		var p nodeList
		if err := storage.Prove(slotPaths[i], &p); err != nil {
			return err
		}
		g.evidence.StorageProofs[i] = p
	}

	g.genesisJSON, err = genesisJSON(chainID, evm, &allocation{address: g.pins.RegistryAddress, code: art.RuntimeCode, words: g.storage})
	return err
}

func genesisHeader(evm EVMParams, stateRoot common.Hash) *types.Header {
	withdrawals, beaconRoot := types.EmptyWithdrawalsHash, common.Hash{}
	blobGasUsed, excessBlobGas := uint64(0), uint64(0)
	return &types.Header{
		ParentHash: common.Hash{}, UncleHash: types.EmptyUncleHash, Coinbase: evm.Coinbase, Root: stateRoot,
		TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash, Difficulty: new(big.Int),
		Number: new(big.Int), GasLimit: evm.GasLimit, GasUsed: 0, Time: 0, Extra: bytes.Clone(evm.ExtraData),
		MixDigest: common.Hash{}, Nonce: types.BlockNonce{}, BaseFee: new(big.Int).SetUint64(evm.BaseFee),
		WithdrawalsHash: &withdrawals, BlobGasUsed: &blobGasUsed, ExcessBlobGas: &excessBlobGas,
		ParentBeaconRoot: &beaconRoot,
	}
}

// BaseConfigHash is §5.3 step 1.
func (g *Genesis) BaseConfigHash() common.Hash { return g.baseConfigHash }

// Record is a copy of G.
func (g *Genesis) Record() Record { return g.record.clone() }

// RecordCBOR is a copy of CBOR(G).
func (g *Genesis) RecordCBOR() []byte { return bytes.Clone(g.recordCBOR) }

// GenesisCommitment is SHA-256(CBOR(G)), and the value of the seal_registry_genesis parameter.
func (g *Genesis) GenesisCommitment() common.Hash { return g.genesisCommitment }

// FullConfig returns a newly decoded copy of the full configuration, the record with the parameter set.
func (g *Genesis) FullConfig() (*bfttypes.PartitionDescriptionRecord, error) {
	var pdr bfttypes.PartitionDescriptionRecord
	if err := bfttypes.Cbor.Unmarshal(g.fullConfigCBOR, &pdr); err != nil {
		return nil, err
	}
	return &pdr, nil
}

// FullShardConfHash is the hash of the full configuration, the value every certificate carries.
func (g *Genesis) FullShardConfHash() common.Hash { return g.fullShardConfHash }

// Storage is a copy of the six §5.4 words, by §4.2 field name.
func (g *Genesis) Storage() map[string]common.Hash { return maps.Clone(g.storage) }

// StorageRoot is the registry account's storage root at genesis.
func (g *Genesis) StorageRoot() common.Hash { return g.storageRoot }

// StateRoot is the EVM genesis state root.
func (g *Genesis) StateRoot() common.Hash { return g.stateRoot }

// Header is a copy of RLP(EVM genesis header).
func (g *Genesis) Header() []byte { return bytes.Clone(g.header) }

// EVMGenesisHash is Keccak-256 of the genesis header.
func (g *Genesis) EVMGenesisHash() common.Hash { return g.evmGenesisHash }

// GenesisJSON is a copy of the execution-client genesis file: the `ubft engine-api genesis` template with
// this allocation.
func (g *Genesis) GenesisJSON() []byte { return bytes.Clone(g.genesisJSON) }

// ProofContext is the registryproof verifier context these values pin.
func (g *Genesis) ProofContext() registryproof.Context {
	return registryproof.Context{
		RegistryAddress: g.pins.RegistryAddress, RegistryCodeHash: g.pins.RegistryCodeHash,
		GenesisCommitment: g.genesisCommitment, FullShardConfHash: g.fullShardConfHash,
		ShardEpoch: g.record.ShardEpoch, RootEpoch: g.record.RootEpoch, EVMGenesisHash: g.evmGenesisHash,
	}
}

// Evidence returns a copy of the genesis header and the proofs for the §4.1 keys, taken from the generated
// state. It is unverified material: registryproof.Verify decides it, and once verified it is what a node
// retains as witness(evmGenesisHash).
func (g *Genesis) Evidence() registryproof.Evidence {
	out := registryproof.Evidence{Header: bytes.Clone(g.evidence.Header), AccountProof: cloneNodes(g.evidence.AccountProof), StorageProofs: make([][][]byte, len(g.evidence.StorageProofs))}
	for i, p := range g.evidence.StorageProofs {
		out.StorageProofs[i] = cloneNodes(p)
	}
	return out
}

func cloneNodes(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i, n := range in {
		out[i] = bytes.Clone(n)
	}
	return out
}

/*
VerifyContext is the §5.3 startup check over a full configuration, the independent pins and a configured
G. It returns fullShardConfHash, the value registry storage must hold.

Every G field is compared with a value that does not come from G before any digest is trusted: the
configuration record for network, partition, shard, chain id and shard epoch, and the pins for root
epoch, code hash and addresses. A G for another context, with the parameter updated to its commitment,
is as self-consistent as the right one (review 5195786713, P2).
*/
func VerifyContext(full *bfttypes.PartitionDescriptionRecord, pins Pins, g Record) (common.Hash, error) {
	if full == nil {
		return common.Hash{}, ErrGenesisEncoding
	}
	if err := pins.check(); err != nil {
		return common.Hash{}, err
	}
	raw, ok := full.PartitionParams[GenesisParam]
	if !ok || !lowerHex64.MatchString(raw) {
		return common.Hash{}, ErrGenesisEncoding
	}
	base, chainID, err := baseConfig(full)
	if err != nil {
		return common.Hash{}, err
	}
	if chainID != g.ChainID {
		return common.Hash{}, ErrChainIDMismatch
	}
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"network", g.NetworkID == uint64(full.NetworkID)},
		{"partition", g.PartitionID == uint64(full.PartitionID)},
		{"shard", bytes.Equal(g.ShardID, full.ShardID.Bytes())},
		{"shard epoch", g.ShardEpoch == full.Epoch},
		{"root epoch", g.RootEpoch == pins.RootEpoch},
		{"registry code hash", g.RegistryCodeHash == pins.RegistryCodeHash},
		{"a_sys", g.SystemAddress == pins.SystemAddress},
		{"a_sr", g.RegistryAddress == pins.RegistryAddress},
	} {
		if !c.ok {
			return common.Hash{}, fmt.Errorf("%w: %s", ErrContextMismatch, c.name)
		}
	}
	baseHash, err := configHash(base)
	if err != nil {
		return common.Hash{}, err
	}
	if baseHash != g.BaseConfigHash {
		return common.Hash{}, fmt.Errorf("%w: G names %s, the configuration hashes to %s", ErrBaseConfig, g.BaseConfigHash, baseHash)
	}
	c, err := g.Commitment()
	if err != nil {
		return common.Hash{}, err
	}
	if raw != hex.EncodeToString(c[:]) {
		return common.Hash{}, ErrGenesisMismatch
	}
	return configHash(full)
}

// gethGenesis mirrors cli/ubft/cmd/engine_api_genesis.go field for field, with account objects in the
// allocation.
type gethGenesis struct {
	Config     gethChainConfig         `json:"config"`
	Nonce      string                  `json:"nonce"`
	Timestamp  string                  `json:"timestamp"`
	ExtraData  string                  `json:"extraData"`
	GasLimit   string                  `json:"gasLimit"`
	Difficulty string                  `json:"difficulty"`
	MixHash    string                  `json:"mixHash"`
	Coinbase   string                  `json:"coinbase"`
	Alloc      map[string]allocAccount `json:"alloc"`
	BaseFee    string                  `json:"baseFeePerGas"`
}

type allocAccount struct {
	Balance string            `json:"balance"`
	Code    string            `json:"code"`
	Storage map[string]string `json:"storage"`
}

// gethChainConfig lists every activation explicitly, as the CLI template does: Shanghai and Cancun at
// timestamp 0 and nothing after Cancun.
type gethChainConfig struct {
	ChainID                       uint64 `json:"chainId"`
	HomesteadBlock                uint64 `json:"homesteadBlock"`
	EIP150Block                   uint64 `json:"eip150Block"`
	EIP155Block                   uint64 `json:"eip155Block"`
	EIP158Block                   uint64 `json:"eip158Block"`
	ByzantiumBlock                uint64 `json:"byzantiumBlock"`
	ConstantinopleBlock           uint64 `json:"constantinopleBlock"`
	PetersburgBlock               uint64 `json:"petersburgBlock"`
	IstanbulBlock                 uint64 `json:"istanbulBlock"`
	BerlinBlock                   uint64 `json:"berlinBlock"`
	LondonBlock                   uint64 `json:"londonBlock"`
	MergeNetsplitBlock            uint64 `json:"mergeNetsplitBlock"`
	ShanghaiTime                  uint64 `json:"shanghaiTime"`
	CancunTime                    uint64 `json:"cancunTime"`
	TerminalTotalDifficulty       uint64 `json:"terminalTotalDifficulty"`
	TerminalTotalDifficultyPassed bool   `json:"terminalTotalDifficultyPassed"`
}

// allocation is the registry account; nil writes the empty allocation of the CLI template.
type allocation struct {
	address common.Address
	code    []byte
	words   map[string]common.Hash
}

func genesisJSON(chainID uint64, evm EVMParams, a *allocation) ([]byte, error) {
	alloc := map[string]allocAccount{}
	if a != nil {
		storage := map[string]string{}
		for i, name := range registryproof.SlotNames {
			if w := a.words[name]; w != (common.Hash{}) {
				storage[registryproof.SlotKey(i).Hex()] = w.Hex()
			}
		}
		alloc[a.address.Hex()] = allocAccount{Balance: "0x0", Code: hexutil.Encode(a.code), Storage: storage}
	}
	g := gethGenesis{
		Config: gethChainConfig{ChainID: chainID, TerminalTotalDifficultyPassed: true},
		Nonce:  "0x0", Timestamp: "0x0", ExtraData: hexutil.Encode(evm.ExtraData),
		GasLimit: fmt.Sprintf("0x%x", evm.GasLimit), Difficulty: "0x0",
		MixHash: common.Hash{}.Hex(), Coinbase: evm.Coinbase.Hex(), Alloc: alloc,
		BaseFee: fmt.Sprintf("0x%x", evm.BaseFee),
	}
	return json.MarshalIndent(g, "", "  ")
}
