/*
Package registryproof reads the SealRegistry (profile sealRegistry/v1) as of an authenticated EVM parent
block, from that block's RLP header and eth_getProof-style Merkle-Patricia proofs. It implements the
parent-state proof contract of docs/design/f4a-seal-registry-contract.md §7.

The package verifies evidence; it does not acquire it. Nothing here calls an RPC, stores a witness,
chooses a parent or selects a retention policy (§8, F6, F7). A caller that could not obtain evidence
reports ErrUnavailable itself, or passes an empty Evidence, and the two cases are indistinguishable to
the rest of the node.

Trie paths are checked by go-ethereum's trie.VerifyProof (review decision 4 of #153). This package owns
every piece of context the library does not: the block (the caller's authenticated parent hash and the
recomputed header hash), the account (RegistryAddress, a constant), the storage keys (the fixed §4.1
list, never an input), the proof database (each supplied node keyed by its locally computed Keccak-256
hash), the size bounds (checked while copying the input, before any decoding or hashing), canonical
decoding of the account and every storage word, and the §7.3 initialization and parent rules.
docs/design/f4c-registry-proof-reader.md records the bounds and the dependency review.

The reviewed production callers are the allowlist in inert_test.go: the Engine API adapter, rootinput,
configuredprogress, parentwitness, and the genesis and shard-node CLI. The adapter's local witness
source is part of this path; other packages with controlled imports use their own guards.
*/
package registryproof

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	bfttypes "github.com/unicitynetwork/bft-go-base/types"
)

// The §7.5 refusals. Each wrapped error keeps its class for errors.Is. None falls back to another block,
// to the current head or to zero.
var (
	// ErrUnavailable is the absence of evidence, not bad evidence: no header and no proofs were supplied.
	ErrUnavailable = errors.New("registryproof: proof unavailable")
	// ErrBounds is evidence larger than §7.4 allows, or with the wrong number of storage proofs. It is
	// decided from lengths alone, before any node is hashed or decoded.
	ErrBounds = errors.New("registryproof: proof exceeds bounds")
	// ErrContext is a verifier context or parent hash that cannot be used, independent of the evidence.
	ErrContext = errors.New("registryproof: invalid verifier context")

	ErrHeaderHash     = errors.New("registryproof: header hash mismatch")
	ErrHeaderShape    = errors.New("registryproof: unsupported header shape")
	ErrAccountProof   = errors.New("registryproof: account proof invalid")
	ErrCodeHash       = errors.New("registryproof: code hash mismatch")
	ErrStorageProof   = errors.New("registryproof: storage proof invalid")
	ErrValue          = errors.New("registryproof: value not canonical or out of range")
	ErrNotInitialized = errors.New("registryproof: registry not initialized")
	ErrConfiguration  = errors.New("registryproof: configuration mismatch")
	ErrNotFinalized   = errors.New("registryproof: parent not finalized")
)

// RegistryAddress is a_sr of the v1 profile (§2.1).
var RegistryAddress = common.HexToAddress("0xff00000000000000000000000000000000000002")

// LayoutVersion is the only layout this reader accepts (§11).
const LayoutVersion = 1

const (
	phaseOpen      = 1
	phaseFinalized = 2
)

const slotDomain = "unicity.seal-registry.v1/"

// SlotNames is the fixed §4.2 field list, in the order Evidence.StorageProofs follows.
var SlotNames = [FieldCount]string{
	"layoutVersion", "genesisCommitment", "config.shardConfHash", "assignment.epoch", "assignment.rootEpoch",
	"clock.rootRound", "origin.rootEpoch", "origin.timestamp", "origin.treeRoot", "origin.identity",
	"origin.trHash", "round.authorized", "input.commitment", "certified.round", "certified.stateHash",
	"certified.hasBlockHash", "certified.blockHash", "phase", "outcomes.round", "outcomes.commitment",
	"transition.cursor", "inbox.consumed",
	"transition.bodyID", "transition.genesisID", "transition.frozenID", "transition.commitID",
	"transition.frozenParent", "transition.successorTR",
}

// FieldCount is the number of §4.2 fields, and the exact number of storage proofs Evidence carries.
const FieldCount = 28

const (
	fLayoutVersion = iota
	fGenesisCommitment
	fShardConfHash
	fAssignmentEpoch
	fAssignmentRootEpoch
	fClockRootRound
	fOriginRootEpoch
	fOriginTimestamp
	fOriginTreeRoot
	fOriginIdentity
	fOriginTRHash
	fRoundAuthorized
	fInputCommitment
	fCertifiedRound
	fCertifiedStateHash
	fCertifiedHasBlockHash
	fCertifiedBlockHash
	fPhase
	fOutcomesRound
	fOutcomesCommitment
	fTransitionCursor
	fInboxConsumed
	fTransitionBodyID
	fTransitionGenesisID
	fTransitionFrozenID
	fTransitionCommitID
	fTransitionFrozenParent
	fTransitionSuccessorTR
)

// genesisFields are the words §5.4 writes at genesis; every other field is zero there.
var genesisFields = [...]int{fLayoutVersion, fGenesisCommitment, fShardConfHash, fAssignmentEpoch, fAssignmentRootEpoch, fPhase}

var (
	slotKeys       [FieldCount]common.Hash // Keccak-256(slotDomain || name), the EVM storage slot
	trieSlotKeys   [FieldCount][]byte      // Keccak-256(slot), the storage-trie path
	accountTrieKey = crypto.Keccak256(RegistryAddress[:])
)

func init() {
	for i, name := range SlotNames {
		slotKeys[i] = crypto.Keccak256Hash([]byte(slotDomain + name))
		trieSlotKeys[i] = crypto.Keccak256(slotKeys[i][:])
	}
}

// SlotKey returns the storage slot of field i of SlotNames.
func SlotKey(i int) common.Hash { return slotKeys[i] }

// LayoutVersion2 is the assignment-aware layout (sealRegistry/v2): the immutable genesis configuration
// hash stays in config.shardConfHash, and two words are added for the active assignment hash and the
// folded supersession commitment. The v1 layout stays readable for its own historical deployments.
const LayoutVersion2 = 2

// SlotNamesV2 is the v2 field list in the order the v2 artifact pins it, and the order Evidence.StorageProofs
// follows for a v2 context.
var SlotNamesV2 = [FieldCountV2]string{
	"layoutVersion", "genesisCommitment", "config.shardConfHash", "assignment.epoch", "assignment.rootEpoch",
	"assignment.activeConfHash", "assignment.spanCommitment",
	"clock.rootRound", "origin.rootEpoch", "origin.timestamp", "origin.treeRoot", "origin.identity",
	"origin.trHash", "round.authorized", "input.commitment", "certified.round", "certified.stateHash",
	"certified.hasBlockHash", "certified.blockHash", "phase", "outcomes.round", "outcomes.commitment",
	"transition.cursor", "inbox.consumed",
	"transition.bodyID", "transition.genesisID", "transition.frozenID", "transition.commitID",
	"transition.frozenParent", "transition.successorTR",
}

// FieldCountV2 is the number of v2 fields, and the exact number of storage proofs a v2 Evidence carries.
const FieldCountV2 = 30

// layout is the field list of one layout version with its derived keys.
type layout struct {
	version  uint64
	names    []string
	slotKeys []common.Hash
	trieKeys [][]byte
	idx      map[string]int
	genesis  []string
}

func newLayout(version uint64, names []string, genesis []string) *layout {
	l := &layout{version: version, names: names, idx: make(map[string]int, len(names)), genesis: genesis}
	for i, name := range names {
		domain := slotDomain
		if version == FreshB1 {
			domain = "unicity.seal-registry/"
		}
		k := crypto.Keccak256Hash([]byte(domain + name))
		l.slotKeys = append(l.slotKeys, k)
		l.trieKeys = append(l.trieKeys, crypto.Keccak256(k[:]))
		l.idx[name] = i
	}
	return l
}

var (
	layoutV1 = newLayout(1, SlotNames[:], []string{"layoutVersion", "genesisCommitment", "config.shardConfHash", "assignment.epoch", "assignment.rootEpoch", "phase"})
	layoutV2 = newLayout(2, SlotNamesV2[:], []string{"layoutVersion", "genesisCommitment", "config.shardConfHash", "assignment.epoch", "assignment.rootEpoch", "assignment.activeConfHash", "phase"})
)

// layoutFor selects the layout a context declares. Zero means the v1 layout, so every existing v1
// context keeps its meaning.
func layoutFor(version uint64) (*layout, error) {
	switch version {
	case 0, 1:
		return layoutV1, nil
	case LayoutVersion2:
		return layoutV2, nil
	case FreshB1:
		return layoutB1, nil
	}
	return nil, fmt.Errorf("%w: unsupported registry layout %d", ErrContext, version)
}

// FieldCountFor is the number of storage proofs an Evidence for the given layout carries.
func FieldCountFor(version uint64) (int, error) {
	l, err := layoutFor(version)
	if err != nil {
		return 0, err
	}
	return len(l.names), nil
}

// SlotNamesFor is the field list for the given layout.
func SlotNamesFor(version uint64) ([]string, error) {
	l, err := layoutFor(version)
	if err != nil {
		return nil, err
	}
	return append([]string(nil), l.names...), nil
}

// SlotKeyFor is the storage slot of field i of the given layout.
func SlotKeyFor(version uint64, i int) (common.Hash, error) {
	l, err := layoutFor(version)
	if err != nil || i < 0 || i >= len(l.slotKeys) {
		return common.Hash{}, fmt.Errorf("%w: layout %d field %d", ErrContext, version, i)
	}
	return l.slotKeys[i], nil
}

// Assignment is an independently authenticated active assignment a v2 snapshot is checked against: the
// root epoch, shard epoch and configuration hash that committed handoff history, or a verified
// acknowledgement span, establishes for the parent being read. Without it the snapshot must be at the
// genesis assignment.
type Assignment struct {
	Set            bool
	ShardEpoch     uint64
	RootEpoch      uint64
	ActiveConfHash common.Hash
}

// Context is what the verifier trusts, all of it configured independently of the execution client and
// verified by the §5.3 startup check before it is used here.
type Context struct {
	RegistryAddress   common.Address // must be RegistryAddress
	RegistryCodeHash  common.Hash    // G.registryCodeHash
	GenesisCommitment common.Hash    // SHA-256(CBOR(G))
	FullShardConfHash common.Hash    // fullShardConfHash: the immutable genesis configuration hash
	ShardEpoch        uint64         // G.shardEpoch
	RootEpoch         uint64         // G.rootEpoch
	EVMGenesisHash    common.Hash    // evmGenesisHash
	// Layout selects a historical reader (zero/1 or 2), or the inactive FreshB1 allocation.
	Layout uint64
	// Active is the authenticated active assignment of a v2 parent; see Assignment.
	Active Assignment
}

func (c Context) check() error {
	if c.RegistryAddress != RegistryAddress {
		return fmt.Errorf("%w: registry address %s is not the v1 a_sr %s", ErrContext, c.RegistryAddress, RegistryAddress)
	}
	for name, h := range map[string]common.Hash{
		"registry code hash": c.RegistryCodeHash, "genesis commitment": c.GenesisCommitment,
		"full shard configuration hash": c.FullShardConfHash, "EVM genesis hash": c.EVMGenesisHash,
	} {
		if h == (common.Hash{}) {
			return fmt.Errorf("%w: %s is zero", ErrContext, name)
		}
	}
	return nil
}

// Evidence is a header and the proofs for one block. It carries proof nodes only: an RPC response's
// summary fields (balance, nonce, codeHash, storageHash, per-slot value) have no place here, so they
// cannot be trusted by mistake. EvidenceFromGetProof builds one from an eth_getProof result.
type Evidence struct {
	Header        []byte     // RLP(header)
	AccountProof  [][]byte   // trie nodes for Keccak-256(RegistryAddress)
	StorageProofs [][][]byte // exactly FieldCountFor(Layout) entries, in that layout's fixed-slot order
}

// limits are the §7.4 bounds; docs/design/f4c-registry-proof-reader.md gives the derivation.
type limits struct {
	headerBytes   int
	nodesPerProof int
	nodeBytes     int
	totalBytes    int
}

var defaultLimits = limits{headerBytes: 1024, nodesPerProof: 65, nodeBytes: 1024, totalBytes: 256 << 10}

// clone copies ev into memory the caller cannot reach, enforcing every bound on the way. Lengths are read
// from the local copies being cloned, so a caller changing its slices concurrently cannot make a checked
// length differ from a copied one.
func (l limits) clone(lay *layout, ev Evidence) (Evidence, error) {
	header, account, storage := ev.Header, ev.AccountProof, ev.StorageProofs
	if len(header) == 0 && len(account) == 0 && len(storage) == 0 {
		return Evidence{}, ErrUnavailable
	}
	if len(header) > l.headerBytes {
		return Evidence{}, fmt.Errorf("%w: header is %d bytes, limit %d", ErrBounds, len(header), l.headerBytes)
	}
	if len(storage) != len(lay.names) {
		return Evidence{}, fmt.Errorf("%w: %d storage proofs, want exactly %d", ErrBounds, len(storage), len(lay.names))
	}
	total := len(header)
	proof := func(what string, nodes [][]byte) ([][]byte, error) {
		if len(nodes) > l.nodesPerProof {
			return nil, fmt.Errorf("%w: %s has %d nodes, limit %d", ErrBounds, what, len(nodes), l.nodesPerProof)
		}
		out := make([][]byte, len(nodes))
		for i, n := range nodes {
			if len(n) > l.nodeBytes {
				return nil, fmt.Errorf("%w: %s node %d is %d bytes, limit %d", ErrBounds, what, i, len(n), l.nodeBytes)
			}
			if total += len(n); total > l.totalBytes {
				return nil, fmt.Errorf("%w: evidence exceeds %d bytes", ErrBounds, l.totalBytes)
			}
			out[i] = bytes.Clone(n)
		}
		return out, nil
	}
	out := Evidence{Header: bytes.Clone(header), StorageProofs: make([][][]byte, len(lay.names))}
	var err error
	if out.AccountProof, err = proof("account proof", account); err != nil {
		return Evidence{}, err
	}
	for i, nodes := range storage {
		if out.StorageProofs[i], err = proof("storage proof "+lay.names[i], nodes); err != nil {
			return Evidence{}, err
		}
	}
	return out, nil
}

// proofNodes is the proof database handed to trie.VerifyProof: a bounded, owned, in-memory map from the
// locally computed Keccak-256 of each supplied node to that node. No mapping supplied by a peer is used.
type proofNodes map[common.Hash][]byte

func newProofNodes(nodes [][]byte) proofNodes {
	m := make(proofNodes, len(nodes))
	for _, n := range nodes {
		m[crypto.Keccak256Hash(n)] = n
	}
	return m
}

var errNoNode = errors.New("proof node not supplied")

func (p proofNodes) Has(key []byte) (bool, error) {
	_, err := p.Get(key)
	return err == nil, nil
}

func (p proofNodes) Get(key []byte) ([]byte, error) {
	if len(key) != common.HashLength {
		return nil, errNoNode
	}
	n, ok := p[common.Hash(key)]
	if !ok {
		return nil, errNoNode
	}
	return n, nil
}

// provenValue returns the value at path under root, or present == false when the proof shows the path
// absent. An empty trie proves every path absent by its root alone.
func provenValue(root common.Hash, path []byte, nodes [][]byte) (value []byte, present bool, err error) {
	if root == types.EmptyRootHash {
		return nil, false, nil
	}
	v, err := trie.VerifyProof(root, path, newProofNodes(nodes))
	if err != nil {
		return nil, false, err
	}
	if v == nil {
		return nil, false, nil
	}
	return bytes.Clone(v), true, nil
}

// decodeHeader accepts only the canonical RLP of a header with exactly the Cancun field set: the
// Shanghai and Cancun fields present, nothing from a later fork (§7.3 step 1).
func decodeHeader(enc []byte) (*types.Header, error) {
	var h types.Header
	if err := rlp.DecodeBytes(enc, &h); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHeaderShape, err)
	}
	if re, err := rlp.EncodeToBytes(&h); err != nil || !bytes.Equal(re, enc) {
		return nil, fmt.Errorf("%w: header RLP is not canonical", ErrHeaderShape)
	}
	if h.BaseFee == nil || h.WithdrawalsHash == nil || h.BlobGasUsed == nil || h.ExcessBlobGas == nil || h.ParentBeaconRoot == nil {
		return nil, fmt.Errorf("%w: a Cancun header field is missing", ErrHeaderShape)
	}
	if h.RequestsHash != nil {
		return nil, fmt.Errorf("%w: header carries a field from a later fork", ErrHeaderShape)
	}
	if !h.Number.IsUint64() {
		return nil, fmt.Errorf("%w: block number exceeds uint64", ErrHeaderShape)
	}
	return &h, nil
}

// decodeAccount accepts only the canonical RLP of [nonce, balance, storageRoot, codeHash].
func decodeAccount(enc []byte) (types.StateAccount, error) {
	var a types.StateAccount
	if err := rlp.DecodeBytes(enc, &a); err != nil {
		return a, err
	}
	if len(a.CodeHash) != common.HashLength {
		return a, fmt.Errorf("code hash is %d bytes", len(a.CodeHash))
	}
	if re, err := rlp.EncodeToBytes(&a); err != nil || !bytes.Equal(re, enc) {
		return a, errors.New("account RLP is not canonical")
	}
	return a, nil
}

// decodeWord accepts a present storage value only as a canonical RLP byte string of 1 to 32 bytes with
// no leading zero byte (§7.3 step 4). A zero word is never present in the trie.
func decodeWord(enc []byte) (common.Hash, error) {
	var b []byte
	if err := rlp.DecodeBytes(enc, &b); err != nil {
		return common.Hash{}, err
	}
	if len(b) == 0 || len(b) > common.HashLength || b[0] == 0 {
		return common.Hash{}, fmt.Errorf("stored value %x is not a minimal non-zero word", b)
	}
	return common.BytesToHash(b), nil
}

/*
Snapshot is the registry as of one verified parent block. It has no exported or mutable state: the values
Verify checked live in an unexported record that nothing changes after Verify returns, and every accessor
returns a copy. Only Verify produces a non-zero Snapshot, and GenesisParentEligible reads the record, so
editing a copy of the values cannot change a decision (review of #156).
*/
type Snapshot struct {
	r *record
}

type record struct {
	storageRoot      common.Hash
	f                Fields
	context          Context     // the complete immutable local context Verify used
	evmGenesisHash   common.Hash // the configured evmGenesisHash Verify compared the parent with
	headerParentHash common.Hash // decoded header.parentHash; distinct from f.ParentHash, the proof subject
}

// Fields returns a copy of the verified values. Fields holds only arrays, integers and booleans, so the
// copy shares no memory with the snapshot. The zero Snapshot returns zero Fields.
func (s Snapshot) Fields() Fields {
	if s.r == nil {
		return Fields{}
	}
	return s.r.f
}

// Valid reports whether s was produced by Verify.
func (s Snapshot) Valid() bool { return s.r != nil }

// ParentHash is the verified parent block hash.
func (s Snapshot) ParentHash() common.Hash { return s.Fields().ParentHash }

// HeaderParentHash is the verified subject header's decoded predecessor. ParentHash is the subject itself.
func (s Snapshot) HeaderParentHash() common.Hash {
	if s.r == nil {
		return common.Hash{}
	}
	return s.r.headerParentHash
}

// VerifiedContext returns the complete local proof context under which Verify accepted the snapshot.
// Matching proven storage values alone does not establish that two snapshots used the same code and
// genesis pins.
func (s Snapshot) VerifiedContext() Context {
	if s.r == nil {
		return Context{}
	}
	return s.r.context
}

// Number is the verified parent block number.
func (s Snapshot) Number() uint64 { return s.Fields().Number }

// StateRoot is the verified parent state root.
func (s Snapshot) StateRoot() common.Hash { return s.Fields().StateRoot }

// Genesis reports that the parent is the configured evmGenesisHash, whose storage was checked against §5.4.
func (s Snapshot) Genesis() bool { return s.Fields().Genesis }

// LastAppliedRootRound is the committed cursor for the next derivation: clock.rootRound of this parent,
// and nothing else (§7.3 step 7, D1 §5).
func (s Snapshot) LastAppliedRootRound() uint64 { return s.Fields().ClockRootRound }

// Fields is a copy of a verified snapshot's values, for diagnostics and for callers that read the
// registry. It carries no authority: no function in this package accepts it.
type Fields struct {
	// Provenance.
	ParentHash common.Hash
	Number     uint64
	StateRoot  common.Hash
	// Genesis reports that ParentHash is the configured evmGenesisHash, whose storage was checked
	// against §5.4 instead of the parent-consistency rule.
	Genesis bool

	B1Initialized, B1Network, B1WCert, B1Head, B1Count uint64
	B1ProfileHash                                      common.Hash
	// The authenticated root-record log words (FreshB1 only): imported count and tip, the progress and UC time of the last import, the
	// length and tip of the source log as of it, and the last round that imported.
	RecordsCount, RecordsProgress, RecordsUCTime, RecordsTargetCount, RecordsImportedRound uint64
	RecordsTip, RecordsTargetTip                                                           common.Hash
	LayoutVersion                                                                          uint64
	GenesisCommitment                                                                      common.Hash
	ShardConfHash                                                                          common.Hash
	ShardEpoch                                                                             uint64
	RootEpoch                                                                              uint64
	// Layout is the local registry reader selector, including FreshB1.
	Layout uint64
	// ActiveConfHash and SpanCommitment exist in layout 2 and FreshB1. ShardConfHash stays the immutable genesis hash.
	ActiveConfHash                                                    common.Hash
	SpanCommitment                                                    common.Hash
	ClockRootRound                                                    uint64
	OriginRootEpoch                                                   uint64
	OriginTimestamp                                                   uint64
	OriginTreeRoot                                                    common.Hash
	OriginIdentity                                                    common.Hash
	OriginTRHash                                                      common.Hash
	RoundAuthorized                                                   uint64
	InputCommitment                                                   common.Hash
	CertifiedRound                                                    uint64
	CertifiedStateHash                                                common.Hash
	HasBlockHash                                                      bool
	CertifiedBlockHash                                                common.Hash
	Phase                                                             uint64
	OutcomesRound                                                     uint64
	OutcomesCommitment                                                common.Hash
	TransitionCursor                                                  uint64
	InboxConsumed                                                     uint64
	TransitionBodyID, TransitionGenesisID, TransitionFrozenID         common.Hash
	TransitionCommitID, TransitionFrozenParent, TransitionSuccessorTR common.Hash
}

func decodeFields(lay *layout, w []common.Hash) (Fields, error) {
	var s Fields
	at := func(name string) common.Hash { return w[lay.idx[name]] }
	scalars := []struct {
		name string
		dst  *uint64
	}{
		{"assignment.epoch", &s.ShardEpoch}, {"assignment.rootEpoch", &s.RootEpoch},
		{"clock.rootRound", &s.ClockRootRound}, {"origin.rootEpoch", &s.OriginRootEpoch}, {"origin.timestamp", &s.OriginTimestamp},
		{"round.authorized", &s.RoundAuthorized}, {"certified.round", &s.CertifiedRound}, {"phase", &s.Phase},
		{"outcomes.round", &s.OutcomesRound}, {"transition.cursor", &s.TransitionCursor}, {"inbox.consumed", &s.InboxConsumed},
	}
	if lay.version == FreshB1 {
		scalars = append(scalars, struct {
			name string
			dst  *uint64
		}{"b1.initialized", &s.B1Initialized}, struct {
			name string
			dst  *uint64
		}{"b1.network", &s.B1Network}, struct {
			name string
			dst  *uint64
		}{"b1.wCert", &s.B1WCert}, struct {
			name string
			dst  *uint64
		}{"b1.head", &s.B1Head}, struct {
			name string
			dst  *uint64
		}{"b1.count", &s.B1Count})
		s.B1ProfileHash = at("b1.profileHash")
		s.RecordsTip, s.RecordsTargetTip = at("records.tip"), at("records.targetTip")
		for _, r := range []struct {
			name string
			dst  *uint64
		}{{"records.count", &s.RecordsCount}, {"records.progress", &s.RecordsProgress}, {"records.ucTime", &s.RecordsUCTime},
			{"records.targetCount", &s.RecordsTargetCount}, {"records.importedRound", &s.RecordsImportedRound}} {
			scalars = append(scalars, struct {
				name string
				dst  *uint64
			}{r.name, r.dst})
		}
	} else {
		scalars = append(scalars, struct {
			name string
			dst  *uint64
		}{"layoutVersion", &s.LayoutVersion})
	}
	for _, sc := range scalars {
		word := at(sc.name)
		if !bytes.Equal(word[:24], make([]byte, 24)) {
			return Fields{}, fmt.Errorf("%w: %s does not fit uint64", ErrValue, sc.name)
		}
		*sc.dst = binary.BigEndian.Uint64(word[24:])
	}
	s.Layout = lay.version
	s.GenesisCommitment, s.ShardConfHash = at("genesisCommitment"), at("config.shardConfHash")
	s.OriginTreeRoot, s.OriginIdentity, s.OriginTRHash = at("origin.treeRoot"), at("origin.identity"), at("origin.trHash")
	s.InputCommitment, s.CertifiedStateHash = at("input.commitment"), at("certified.stateHash")
	s.CertifiedBlockHash, s.OutcomesCommitment = at("certified.blockHash"), at("outcomes.commitment")
	s.TransitionBodyID, s.TransitionGenesisID = at("transition.bodyID"), at("transition.genesisID")
	s.TransitionFrozenID, s.TransitionCommitID = at("transition.frozenID"), at("transition.commitID")
	s.TransitionFrozenParent, s.TransitionSuccessorTR = at("transition.frozenParent"), at("transition.successorTR")
	if lay.version == LayoutVersion2 || lay.version == FreshB1 {
		s.ActiveConfHash, s.SpanCommitment = at("assignment.activeConfHash"), at("assignment.spanCommitment")
	}

	switch flag := at("certified.hasBlockHash"); flag {
	case common.Hash{}:
		if s.CertifiedBlockHash != (common.Hash{}) {
			return Fields{}, fmt.Errorf("%w: null certified block hash is not the zero word", ErrValue)
		}
	case common.BigToHash(common.Big1):
		s.HasBlockHash = true
	default:
		return Fields{}, fmt.Errorf("%w: certified.hasBlockHash is %x", ErrValue, flag)
	}
	return s, nil
}

/*
Verify authenticates the registry as of parentHash (§7.3) and returns its snapshot.

parentHash must already be authenticated by the caller as the certified parent of the round being built,
validated or replayed (§7.2); a block number, tag or executor head is not representable here. Order:
context, bounded copy of the evidence, header hash, header shape, account proof, code hash, storage
proofs, word decoding, initialization (step 5), then parent consistency or the genesis storage check
(step 6). The first failing step decides the refusal.
*/
func Verify(c Context, parentHash common.Hash, ev Evidence) (Snapshot, error) {
	return defaultLimits.verify(c, parentHash, ev)
}

func (l limits) verify(c Context, parentHash common.Hash, ev Evidence) (Snapshot, error) {
	if err := c.check(); err != nil {
		return Snapshot{}, err
	}
	lay, err := layoutFor(c.Layout)
	if err != nil {
		return Snapshot{}, err
	}
	if parentHash == (common.Hash{}) {
		return Snapshot{}, fmt.Errorf("%w: parent hash is zero", ErrContext)
	}
	ev, err = l.clone(lay, ev)
	if err != nil {
		return Snapshot{}, err
	}

	// Step 1. The hash of the supplied bytes is compared before they are decoded.
	if got := crypto.Keccak256Hash(ev.Header); got != parentHash {
		return Snapshot{}, fmt.Errorf("%w: header hashes to %s, parent is %s", ErrHeaderHash, got, parentHash)
	}
	h, err := decodeHeader(ev.Header)
	if err != nil {
		return Snapshot{}, err
	}

	// Step 2. Only the proven leaf is read.
	enc, present, err := provenValue(h.Root, accountTrieKey, ev.AccountProof)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrAccountProof, err)
	}
	if !present {
		return Snapshot{}, fmt.Errorf("%w: the proof shows no account at %s", ErrCodeHash, RegistryAddress)
	}
	account, err := decodeAccount(enc)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrAccountProof, err)
	}
	if got := common.BytesToHash(account.CodeHash); got != c.RegistryCodeHash {
		return Snapshot{}, fmt.Errorf("%w: account code hash %s, pinned %s", ErrCodeHash, got, c.RegistryCodeHash)
	}

	// Steps 3 and 4.
	words := make([]common.Hash, len(lay.names))
	for i := range lay.names {
		v, present, err := provenValue(account.Root, lay.trieKeys[i], ev.StorageProofs[i])
		if err != nil {
			return Snapshot{}, fmt.Errorf("%w: %s: %v", ErrStorageProof, lay.names[i], err)
		}
		if !present {
			continue
		}
		if words[i], err = decodeWord(v); err != nil {
			return Snapshot{}, fmt.Errorf("%w: %s: %v", ErrValue, lay.names[i], err)
		}
	}
	s, err := decodeFields(lay, words)
	if err != nil {
		return Snapshot{}, err
	}
	s.ParentHash, s.Number, s.StateRoot = parentHash, h.Number.Uint64(), h.Root

	// Step 5. Zero-valued fields mean their genesis values only after these hold.
	if (lay.version != FreshB1 && s.LayoutVersion == 0) || (lay.version == FreshB1 && s.B1Initialized != 1) || s.GenesisCommitment == (common.Hash{}) {
		return Snapshot{}, fmt.Errorf("%w: at block %d", ErrNotInitialized, s.Number)
	}
	switch {
	case lay.version == FreshB1 && (s.B1Network == 0 || s.B1Network > 65535 || s.B1WCert >= 16 || s.B1Head > s.B1WCert || s.B1Count == 0 || s.B1Count > s.B1WCert+1 || s.B1ProfileHash == (common.Hash{})):
		return Snapshot{}, ErrConfiguration
	case lay.version != FreshB1 && s.LayoutVersion != lay.version:
		return Snapshot{}, fmt.Errorf("%w: layout version %d, expected %d", ErrConfiguration, s.LayoutVersion, lay.version)
	case s.GenesisCommitment != c.GenesisCommitment:
		return Snapshot{}, fmt.Errorf("%w: genesis commitment %s, configured %s", ErrConfiguration, s.GenesisCommitment, c.GenesisCommitment)
	case s.ShardConfHash != c.FullShardConfHash:
		return Snapshot{}, fmt.Errorf("%w: shard configuration hash %s, configured %s", ErrConfiguration, s.ShardConfHash, c.FullShardConfHash)
	case lay.version == LayoutVersion2 || lay.version == FreshB1:
		if err := verifyAssignmentV2(s, c); err != nil {
			return Snapshot{}, err
		}
	case s.ShardEpoch != c.ShardEpoch:
		return Snapshot{}, fmt.Errorf("%w: epochs %d/%d, configured %d/%d", ErrConfiguration, s.ShardEpoch, s.RootEpoch, c.ShardEpoch, c.RootEpoch)
	}
	switch {
	case s.InboxConsumed != 0:
		return Snapshot{}, fmt.Errorf("%w: unsupported inbox cursor", ErrConfiguration)
	case s.TransitionCursor == 0 && (lay.version == LayoutVersion2 || lay.version == FreshB1):
		if s.RootEpoch != c.RootEpoch || s.SpanCommitment != (common.Hash{}) || s.TransitionBodyID != (common.Hash{}) || s.TransitionGenesisID != (common.Hash{}) || s.TransitionFrozenID != (common.Hash{}) || s.TransitionCommitID != (common.Hash{}) || s.TransitionFrozenParent != (common.Hash{}) || s.TransitionSuccessorTR != (common.Hash{}) {
			return Snapshot{}, fmt.Errorf("%w: missing epoch transition", ErrConfiguration)
		}
	case s.TransitionCursor > 0 && (lay.version == LayoutVersion2 || lay.version == FreshB1):
		// Each acknowledgement advances the root epoch by at least one: exactly one for an ordinary or
		// root-only step, by the folded span for a supersession.
		if s.TransitionCursor > ^uint64(0)-c.RootEpoch || s.RootEpoch < c.RootEpoch+s.TransitionCursor || s.TransitionBodyID == (common.Hash{}) || s.TransitionGenesisID == (common.Hash{}) || s.TransitionFrozenID == (common.Hash{}) || s.TransitionCommitID == (common.Hash{}) || s.TransitionFrozenParent == (common.Hash{}) || s.TransitionSuccessorTR == (common.Hash{}) {
			return Snapshot{}, fmt.Errorf("%w: invalid installed transition", ErrConfiguration)
		}
	case s.TransitionCursor == 0:
		if s.RootEpoch != c.RootEpoch || s.TransitionBodyID != (common.Hash{}) || s.TransitionGenesisID != (common.Hash{}) || s.TransitionFrozenID != (common.Hash{}) || s.TransitionCommitID != (common.Hash{}) || s.TransitionFrozenParent != (common.Hash{}) || s.TransitionSuccessorTR != (common.Hash{}) {
			return Snapshot{}, fmt.Errorf("%w: missing epoch transition", ErrConfiguration)
		}
	case s.TransitionCursor > 0:
		if s.TransitionCursor > ^uint64(0)-c.RootEpoch || s.RootEpoch != c.RootEpoch+s.TransitionCursor || s.TransitionBodyID == (common.Hash{}) || s.TransitionGenesisID == (common.Hash{}) || s.TransitionFrozenID == (common.Hash{}) || s.TransitionCommitID == (common.Hash{}) || s.TransitionFrozenParent == (common.Hash{}) || s.TransitionSuccessorTR == (common.Hash{}) {
			return Snapshot{}, fmt.Errorf("%w: invalid installed transition", ErrConfiguration)
		}
	}
	switch s.Phase {
	case phaseFinalized:
	case phaseOpen:
		return Snapshot{}, fmt.Errorf("%w: phase is open at block %d", ErrNotFinalized, s.Number)
	default:
		return Snapshot{}, fmt.Errorf("%w: phase %d", ErrValue, s.Phase)
	}

	// Step 6.
	if parentHash == c.EVMGenesisHash {
		if s.Number != 0 {
			return Snapshot{}, fmt.Errorf("%w: the configured EVM genesis header has number %d", ErrConfiguration, s.Number)
		}
		for i := range words {
			if !lay.isGenesisField(i) && words[i] != (common.Hash{}) {
				return Snapshot{}, fmt.Errorf("%w: %s is set at the EVM genesis block", ErrConfiguration, lay.names[i])
			}
		}
		s.Genesis = true
	} else {
		if s.Number == 0 {
			return Snapshot{}, fmt.Errorf("%w: block 0 is not the configured EVM genesis", ErrConfiguration)
		}
		if s.OutcomesRound != s.RoundAuthorized || s.OutcomesCommitment == (common.Hash{}) {
			return Snapshot{}, fmt.Errorf("%w: outcomes round %d for authorized round %d", ErrNotFinalized, s.OutcomesRound, s.RoundAuthorized)
		}
	}
	return Snapshot{r: &record{storageRoot: account.Root, f: s, context: c, evmGenesisHash: c.EVMGenesisHash, headerParentHash: h.ParentHash}}, nil
}

func (l *layout) isGenesisField(i int) bool {
	for _, g := range l.genesis {
		if l.idx[g] == i {
			return true
		}
	}
	return false
}

// verifyAssignmentV2 checks the v2 assignment words. The genesis hash word is immutable; the active hash
// starts equal to it and changes only with the shard epoch. The caller's authenticated Active assignment,
// when set, must be exactly what the registry holds; otherwise the registry must still be at the genesis
// assignment of the context.
func verifyAssignmentV2(s Fields, c Context) error {
	if s.ActiveConfHash == (common.Hash{}) {
		return fmt.Errorf("%w: active configuration hash is zero", ErrConfiguration)
	}
	if s.RootEpoch < c.RootEpoch || s.ShardEpoch < c.ShardEpoch || s.ShardEpoch-c.ShardEpoch > s.RootEpoch-c.RootEpoch {
		return fmt.Errorf("%w: shard epoch %d is not reachable from genesis epoch %d at root epoch %d", ErrConfiguration, s.ShardEpoch, c.ShardEpoch, s.RootEpoch)
	}
	if (s.ShardEpoch == c.ShardEpoch) != (s.ActiveConfHash == c.FullShardConfHash) {
		return fmt.Errorf("%w: active configuration hash %s at shard epoch %d, genesis configuration %s", ErrConfiguration, s.ActiveConfHash, s.ShardEpoch, c.FullShardConfHash)
	}
	if c.Active.Set {
		if s.ShardEpoch != c.Active.ShardEpoch || s.RootEpoch != c.Active.RootEpoch || s.ActiveConfHash != c.Active.ActiveConfHash {
			return fmt.Errorf("%w: registry assignment %d/%d %s, authenticated %d/%d %s", ErrConfiguration,
				s.ShardEpoch, s.RootEpoch, s.ActiveConfHash, c.Active.ShardEpoch, c.Active.RootEpoch, c.Active.ActiveConfHash)
		}
	}
	return nil
}

// Genesis-parent eligibility (§7.3 E1 to E4). It is a separate decision from proof verification: a
// genesis proof verifies at startup with no authorization at all.
var (
	ErrGenesisInstallation  = errors.New("registryproof: authorized round 0 is genesis installation, not a payload")
	ErrNotGenesisHistory    = errors.New("registryproof: the bound certificate does not show genesis history")
	ErrParentNotGenesis     = errors.New("registryproof: the parent is not the verified EVM genesis block")
	ErrRegistryNotAtGenesis = errors.New("registryproof: the registry at the parent has executed a round")
)

/*
GenesisParentEligible decides whether the EVM genesis block may be the parent of a payload for
authorizedRound. bound is the input record of the authenticated, block-bound certificate; genesisState
is the pinned genesis state commitment; parent is the snapshot Verify returned for the proposed parent.

The rule depends on authenticated history, never on the round number being 1: after initial root
timeouts the first payload can be authorized for round 2 or later with genesis still its parent (§9.2a).
*/
func GenesisParentEligible(authorizedRound uint64, bound *bfttypes.InputRecord, genesisState []byte, parent Snapshot) error {
	if authorizedRound == 0 { // E1
		return ErrGenesisInstallation
	}
	if len(genesisState) == 0 {
		return fmt.Errorf("%w: genesis state commitment is empty", ErrContext)
	}
	if bound == nil || bound.BlockHash != nil || bound.RoundNumber >= authorizedRound ||
		!bytes.Equal(bound.Hash, genesisState) || !bytes.Equal(bound.PreviousHash, genesisState) { // E2
		return ErrNotGenesisHistory
	}
	// The decision reads the record Verify produced, never a copy the caller could have edited.
	if parent.r == nil {
		return fmt.Errorf("%w: the snapshot was not produced by Verify", ErrParentNotGenesis)
	}
	p := parent.r.f
	if !p.Genesis || p.Number != 0 || p.ParentHash != parent.r.evmGenesisHash { // E3
		return ErrParentNotGenesis
	}
	if p.RoundAuthorized != 0 || p.CertifiedRound != 0 { // E4
		return ErrRegistryNotAtGenesis
	}
	return nil
}
