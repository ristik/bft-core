package nb2ref

import (
	"encoding/hex"
	"math/big"
	"math/bits"
	"strconv"
)

// NativeBridgeProtoVersion is NATIVE_BRIDGE_PROTO_VERSION of the v2 byte contract.
const NativeBridgeProtoVersion = 9

// CBOR tags (section 3).
const (
	TagPredicate          = 39032
	TagMint               = 39041
	TagTransfer           = 39045
	TagCertification      = 39031
	TagToken              = 39040
	TagInclusion          = 39033
	TagValue              = 39050
	TagSplitJustification = 39044
	TagSplitManifest      = 39046
	TagReceiptBacking     = 39051 // mint reason J
	TagSegmentReturn      = 39052 // return data R
)

// SDK literal versions (unchanged) and the v2 structure version.
const (
	TxVersion        = 2
	CertVersion      = 2
	TokenVersion     = 2
	InclusionVersion = 1
	ValueVersion     = 1
	EngineBuiltIn    = 1
	PredSignature    = 1
	PredBurn         = 2
	V2Version        = 1
)

// Domain literals.
const (
	domainConfig        = "UNICITY_NB2_CFG"
	domainDepositIntent = "UNICITY_NB2_DEPOSIT_INTENT"
	domainDepositSalt   = "UNICITY_NB2_DEPOSIT_SALT"
	domainBurn          = "UNICITY_NB2_BURN"
	domainRedemption    = "UNICITY_NB2_REDEMPTION"
	domainSplitOutput   = "UNICITY_SPLIT_OUTPUT"
)

// EVM domain tags TAG(name) = H_E(ASCII(name)).
var (
	TagDepositSecret  = HE([]byte("UNICITY_NB2_DEPOSIT_SECRET"))
	TagArchiveGenesis = HE([]byte("UNICITY_NB2_ARCHIVE_GENESIS"))
	TagArchiveStep    = HE([]byte("UNICITY_NB2_ARCHIVE_STEP"))
)

// AssetUCT is a_UCT = H_U(UTF8("unicity-nb2-asset:native-uct")).
var AssetUCT = HU([]byte("unicity-nb2-asset:native-uct"))

// Range bounds of the packed accounting word and the indices.
const (
	MaxDeposit = 1<<56 - 1 // n
	MaxSegment = 1<<48 - 1 // c and a
	MaxIndex   = 1<<32 - 1 // txIndex, logIndex
)

// QmaxLimit is 2^144 - 1.
var QmaxLimit = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 144), big.NewInt(1))

// Params is the admitted (K, B) set of a build. A production build admits only (64, 16), fixed by the #1098 gas bake-off; a
// test build admits the separate test set {4, 8} x {2, 4} instead, never both (section 4.1).
type Params struct{ K, B map[uint64]bool }

// MaxK is the largest K any Γ admits (the admitted sets; production fixes K = 64 since #1098), so the 8-bit population m
// always holds K - 1.
const MaxK = 64

// Admits reports whether (K, B) is an admitted pair: both powers of two, 2 <= B <= K <= MaxK, both in the set.
func (p Params) Admits(k, b uint64) bool {
	return k >= 2 && k <= MaxK && bits.OnesCount64(k) == 1 && b >= 2 && b <= k && bits.OnesCount64(b) == 1 && p.K[k] && p.B[b]
}

// CandidateParams is the production set: (K, B) = (64, 16).
var CandidateParams = Params{K: map[uint64]bool{64: true}, B: map[uint64]bool{16: true}}

// TestParams is the test build's set.
var TestParams = Params{K: map[uint64]bool{4: true, 8: true}, B: map[uint64]bool{2: true, 4: true}}

// BuildParams is the admitted set of a build name ("production" or "test").
func BuildParams(build string) Params {
	if build == "test" {
		return TestParams
	}
	return CandidateParams
}

// BuildOf is the build that admits K.
func BuildOf(k uint64) string {
	if TestParams.K[k] {
		return "test"
	}
	return "production"
}

// Config is Γ (section 4.1).
type Config struct {
	Network             uint16
	RootGenesis         [32]byte // g_root: the genesis EntryID of the Unicity Trust Base history
	ExecutionGenesis    [32]byte // g_evm
	ChainID             uint64
	EVMPartition        uint32
	EVMShard            []byte // canonical native shard ID, 1..33 bytes
	AggregatorPartition uint32
	Vault               [20]byte
	Asset               [32]byte
	Ty, Aid             [32]byte
	SemanticProfileHash [32]byte
	Verifier            [20]byte
	VerifierCodeHash    [32]byte
	K, B                uint64
	Qmax                *big.Int
	wireVersion         uint64 // zero means legacy encoding for constructed configurations
}

// ConfigArity is the arity of Γ.
const ConfigArity = 19

// Bytes is the exact encoding of Γ.
func (c *Config) Bytes() []byte {
	version := c.wireVersion
	if version == 0 {
		version = V2Version
	}
	return c.bytesWithVersion(version)
}

func (c *Config) bytesWithVersion(version uint64) []byte {
	return CArr(
		CBytes([]byte(domainConfig)), CUint(version), CUint(uint64(c.Network)),
		CBytes(c.RootGenesis[:]), CBytes(c.ExecutionGenesis[:]), CUint(c.ChainID), CUint(uint64(c.EVMPartition)),
		CBytes(c.EVMShard), CUint(uint64(c.AggregatorPartition)), CBytes(c.Vault[:]), CBytes(c.Asset[:]),
		CBytes(c.Ty[:]), CBytes(c.Aid[:]), CBytes(c.SemanticProfileHash[:]), CBytes(c.Verifier[:]),
		CBytes(c.VerifierCodeHash[:]), CUint(c.K), CUint(c.B), CAmount(c.Qmax))
}

// Domain is D = H_U(Γ).
func (c *Config) Domain() [32]byte { return HU(c.Bytes()) }

// H is log2 K, the gap-proof depth.
func (c *Config) H() int { return bits.TrailingZeros64(c.K) }

// ConfigError is a Γ failure with the index of the first field that fails (19 for the array itself: not an array of 19 items,
// a bad head or trailing bytes). It is ConfigShape to the verifier and BadConfig(field) to the vault constructor.
type ConfigError struct {
	Field int
	Cause error
}

func (e *ConfigError) Error() string {
	return "nb2: ConfigShape: field " + strconv.Itoa(e.Field) + ": " + e.Cause.Error()
}
func (e *ConfigError) Unwrap() []error { return []error{ErrConfigShape, e.Cause} }

func cfgErr(field int, cause error) error { return &ConfigError{Field: field, Cause: cause} }

// DecodeConfig strictly decodes Γ and checks every section 4.1 constraint that does not need the deployment environment:
// exact widths, ranges, aggregatorPartition != evmPartition, (K, B) admitted by p and 1 <= Qmax <= 2^144 - 1. It does not
// check that asset, ty and aid are the section 4.2 derivations: the vault constructor does (Construct), and the stateless
// verifier receives only the Γ the vault was constructed with. Every failure is ConfigShape (a *ConfigError naming the field).
func DecodeConfig(b []byte, p Params) (*Config, error) {
	return decodeConfig(b, p, V2Version)
}

func decodeConfig(b []byte, p Params, version uint64) (*Config, error) {
	if len(b) > maxConfigBytes {
		return nil, cfgErr(ConfigArity, ErrInputTooLarge)
	}
	root, err := scanOne(b)
	if err != nil {
		return nil, cfgErr(ConfigArity, err)
	}
	if err := root.array(ConfigArity); err != nil {
		return nil, cfgErr(ConfigArity, err)
	}
	k := root.kids
	c := &Config{}
	if err := k[0].literal(domainConfig); err != nil {
		return nil, cfgErr(0, err)
	}
	if err := k[1].version(version); err != nil {
		return nil, cfgErr(1, err)
	}
	nw, err := k[2].uintIn(1, 65535)
	if err != nil {
		return nil, cfgErr(2, err)
	}
	c.Network = uint16(nw)
	if err := k[3].fixed(c.RootGenesis[:]); err != nil {
		return nil, cfgErr(3, err)
	}
	if err := k[4].fixed(c.ExecutionGenesis[:]); err != nil {
		return nil, cfgErr(4, err)
	}
	if c.ChainID, err = k[5].uintIn(1, ^uint64(0)); err != nil {
		return nil, cfgErr(5, err)
	}
	ep, err := k[6].uintIn(1, 1<<32-1)
	if err != nil {
		return nil, cfgErr(6, err)
	}
	c.EVMPartition = uint32(ep)
	shard, err := k[7].bstr()
	if err != nil {
		return nil, cfgErr(7, err)
	}
	if !canonicalShardID(shard) {
		return nil, cfgErr(7, ErrLength)
	}
	c.EVMShard = append([]byte{}, shard...)
	ap, err := k[8].uintIn(1, 1<<32-1)
	if err != nil {
		return nil, cfgErr(8, err)
	}
	if ap == ep {
		return nil, cfgErr(8, ErrIntRange)
	}
	c.AggregatorPartition = uint32(ap)
	if err := k[9].fixed(c.Vault[:]); err != nil {
		return nil, cfgErr(9, err)
	}
	if err := k[10].fixed(c.Asset[:]); err != nil {
		return nil, cfgErr(10, err)
	}
	if err := k[11].fixed(c.Ty[:]); err != nil {
		return nil, cfgErr(11, err)
	}
	if err := k[12].fixed(c.Aid[:]); err != nil {
		return nil, cfgErr(12, err)
	}
	if err := k[13].fixed(c.SemanticProfileHash[:]); err != nil {
		return nil, cfgErr(13, err)
	}
	if err := k[14].fixed(c.Verifier[:]); err != nil {
		return nil, cfgErr(14, err)
	}
	if err := k[15].fixed(c.VerifierCodeHash[:]); err != nil {
		return nil, cfgErr(15, err)
	}
	// Field 16 is complete, K in the build's admitted K set, before field 17 is read (section 4.1 stage order): a production
	// Γ with K = 4 and B = 0 is BadConfig(16).
	if c.K, err = k[16].uintIn(2, MaxK); err != nil {
		return nil, cfgErr(16, err)
	}
	if !(p.K[c.K] && bits.OnesCount64(c.K) == 1) {
		return nil, cfgErr(16, ErrIntRange)
	}
	if c.B, err = k[17].uintIn(2, MaxK); err != nil {
		return nil, cfgErr(17, err)
	}
	if !p.Admits(c.K, c.B) {
		return nil, cfgErr(17, ErrIntRange)
	}
	if c.Qmax, err = k[18].amount(); err != nil {
		return nil, cfgErr(18, err)
	}
	if c.Qmax.Cmp(QmaxLimit) > 0 {
		return nil, cfgErr(18, ErrIntRange)
	}
	return c, nil
}

// maxConfigBytes bounds Γ before scanning: 19 fields of at most 33+9 bytes each is far below it.
const maxConfigBytes = 1024

// canonicalShardID reports whether b is a canonical native shard ID: 1..33 bytes, the prefix bits, one set terminator bit and
// zero padding, so the last byte is nonzero; at most 256 prefix bits.
func canonicalShardID(b []byte) bool {
	if len(b) == 0 || len(b) > 33 || b[len(b)-1] == 0 {
		return false
	}
	d := 8*len(b) - bits.TrailingZeros8(b[len(b)-1]) - 1
	return d <= 256
}

// identityString is Dstr = networkDecimal ":" rootGenesisHex ":" executionGenesisHex ":" chainIdDecimal.
func identityString(network uint16, rootGenesis, executionGenesis [32]byte, chainID uint64) string {
	return strconv.FormatUint(uint64(network), 10) + ":" + hex.EncodeToString(rootGenesis[:]) + ":" +
		hex.EncodeToString(executionGenesis[:]) + ":" + strconv.FormatUint(chainID, 10)
}

// DeriveType is ty = H_U(UTF8("unicity-bridge:unicity-native-nb2:" + Dstr)).
func DeriveType(network uint16, rootGenesis, executionGenesis [32]byte, chainID uint64) [32]byte {
	return HU([]byte("unicity-bridge:unicity-native-nb2:" + identityString(network, rootGenesis, executionGenesis, chainID)))
}

// DeriveCoin is aid = H_U(UTF8("unicity-bridge-coin:unicity-native-nb2:" + Dstr)).
func DeriveCoin(network uint16, rootGenesis, executionGenesis [32]byte, chainID uint64) [32]byte {
	return HU([]byte("unicity-bridge-coin:unicity-native-nb2:" + identityString(network, rootGenesis, executionGenesis, chainID)))
}

// Environment is what the vault constructor checks Γ against: its own address, block.chainid and the verifier's EXTCODEHASH.
type Environment struct {
	Address          [20]byte
	ChainID          uint64
	VerifierCodeHash [32]byte // EXTCODEHASH(verifier20)
}

// Construct is the vault constructor's acceptance of Γ: DecodeConfig under p, then asset == a_UCT and ty, aid equal to their
// section 4.2 derivations (coordinator ruling 2026-11-15), vault20 == address(this), chainId == block.chainid and the
// verifier's code hash, in that order. Every failure is BadConfig(field).
func Construct(gamma []byte, env Environment, p Params) (*Config, error) {
	c, err := DecodeConfig(gamma, p)
	if err != nil {
		var ce *ConfigError
		field := ConfigArity
		if asConfigError(err, &ce) {
			field = ce.Field
		}
		return nil, &BadConfigError{Field: field}
	}
	switch {
	case c.Asset != AssetUCT:
		return nil, &BadConfigError{Field: 10}
	case c.Ty != DeriveType(c.Network, c.RootGenesis, c.ExecutionGenesis, c.ChainID):
		return nil, &BadConfigError{Field: 11}
	case c.Aid != DeriveCoin(c.Network, c.RootGenesis, c.ExecutionGenesis, c.ChainID):
		return nil, &BadConfigError{Field: 12}
	case c.Vault != env.Address:
		return nil, &BadConfigError{Field: 9}
	case c.ChainID != env.ChainID:
		return nil, &BadConfigError{Field: 5}
	case c.VerifierCodeHash != env.VerifierCodeHash:
		return nil, &BadConfigError{Field: 15}
	}
	return c, nil
}

func asConfigError(err error, out **ConfigError) bool {
	ce, ok := err.(*ConfigError)
	if ok {
		*out = ce
	}
	return ok
}

// BadConfigError is BadConfig(uint256 field).
type BadConfigError struct{ Field int }

func (e *BadConfigError) Error() string { return "nb2: BadConfig(" + strconv.Itoa(e.Field) + ")" }
func (e *BadConfigError) Unwrap() error { return ErrBadConfig }
