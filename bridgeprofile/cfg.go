package bridgeprofile

import (
	"encoding/hex"
	"math/big"
	"strconv"
	"strings"
)

// Cfg is the immutable configuration
// C("UNICITY_BR_CFG",network,rootGenesis,chainId,executionGenesis,evmPartition,
// evmShard,vault,zeroAddress,ty,aid,semanticProfileHash,tokenVerifierAddress,
// tokenVerifierCodeHash,b1ProfileHash,aggregatorPolicyHash). The domain is an
// ASCII bstr; network/chainId/evmPartition are shortest uints (uint16/u64/u32)
// and every other field is a bstr. Its field widths are fixed below.
type Cfg struct {
	Network               uint16
	RootGenesis           [32]byte
	ChainID               uint64
	ExecutionGenesis      [32]byte
	EVMPartition          uint32
	EVMShard              []byte // native canonical shard bytes
	Vault                 [20]byte
	ZeroAddress           [20]byte
	Ty                    [32]byte
	Aid                   [32]byte
	SemanticProfileHash   [32]byte
	TokenVerifierAddress  [20]byte
	TokenVerifierCodeHash [32]byte
	B1ProfileHash         [32]byte
	AggregatorPolicyHash  [32]byte
}

const cfgDomain = "UNICITY_BR_CFG"

// Bytes is the exact canonical Cfg encoding.
func (c *Cfg) Bytes() []byte {
	return CArr(
		CBytes([]byte(cfgDomain)),
		CUint(uint64(c.Network)),
		CBytes(c.RootGenesis[:]),
		CUint(c.ChainID),
		CBytes(c.ExecutionGenesis[:]),
		CUint(uint64(c.EVMPartition)),
		CBytes(c.EVMShard),
		CBytes(c.Vault[:]),
		CBytes(c.ZeroAddress[:]),
		CBytes(c.Ty[:]),
		CBytes(c.Aid[:]),
		CBytes(c.SemanticProfileHash[:]),
		CBytes(c.TokenVerifierAddress[:]),
		CBytes(c.TokenVerifierCodeHash[:]),
		CBytes(c.B1ProfileHash[:]),
		CBytes(c.AggregatorPolicyHash[:]),
	)
}

// Hash is cfg = H(Cfg).
func (c *Cfg) Hash() [32]byte { return H(c.Bytes()) }

// DecodeCfg strictly decodes Cfg bytes; decode then re-encode must equal the
// input.
func DecodeCfg(b []byte) (*Cfg, error) {
	if len(b) > MaxSemanticBytes {
		return nil, ErrInputTooLarge
	}
	root, err := scanOne(b)
	if err != nil {
		return nil, err
	}
	if !root.isArray(16) {
		return nil, ErrShape
	}
	k := root.kids
	if !k[0].isBytes() || string(k[0].data) != cfgDomain {
		return nil, ErrShape
	}
	var c Cfg
	nw, err := k[1].uintMax(0xffff)
	if err != nil {
		return nil, err
	}
	if nw == 0 {
		return nil, ErrIntRange
	}
	c.Network = uint16(nw)
	if err := fixed(&k[2], c.RootGenesis[:]); err != nil {
		return nil, err
	}
	if c.ChainID, err = k[3].uintMax(^uint64(0)); err != nil {
		return nil, err
	}
	if err := fixed(&k[4], c.ExecutionGenesis[:]); err != nil {
		return nil, err
	}
	ep, err := k[5].uintMax(0xffffffff)
	if err != nil {
		return nil, err
	}
	c.EVMPartition = uint32(ep)
	if !k[6].isBytes() {
		return nil, ErrShape
	}
	c.EVMShard = append([]byte{}, k[6].data...)
	for i, dst := range [][]byte{c.Vault[:], c.ZeroAddress[:], c.Ty[:], c.Aid[:], c.SemanticProfileHash[:],
		c.TokenVerifierAddress[:], c.TokenVerifierCodeHash[:], c.B1ProfileHash[:], c.AggregatorPolicyHash[:]} {
		if err := fixed(&k[7+i], dst); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

func fixed(it *item, dst []byte) error {
	d, err := it.bytesN(len(dst))
	if err != nil {
		return err
	}
	copy(dst, d)
	return nil
}

// IdentityFamily is the bridge identity family of this profile. It is not a
// CAIP-2 namespace.
const IdentityFamily = "unicity-native"

// identityD is D = networkDecimal:rootGenesisHex:executionGenesisHex:chainIdDecimal:zeroAddressHex.
// Decimals have no leading zeros, genesis hex is 64 lowercase characters and
// the zero address is 40 zero characters, none with a 0x prefix. The vault is
// excluded: approved replacement vaults represent the same asset.
func identityD(network uint16, rootGenesis, executionGenesis [32]byte, chainID uint64) string {
	return strconv.FormatUint(uint64(network), 10) + ":" + hex.EncodeToString(rootGenesis[:]) + ":" +
		hex.EncodeToString(executionGenesis[:]) + ":" + strconv.FormatUint(chainID, 10) + ":" + strings.Repeat("0", 40)
}

// DeriveType is ty = SHA256(UTF8("unicity-bridge:unicity-native:" + D)).
func DeriveType(network uint16, rootGenesis, executionGenesis [32]byte, chainID uint64) [32]byte {
	return H([]byte("unicity-bridge:" + IdentityFamily + ":" + identityD(network, rootGenesis, executionGenesis, chainID)))
}

// DeriveAsset is aid = SHA256(UTF8("unicity-bridge-coin:unicity-native:" + D)).
func DeriveAsset(network uint16, rootGenesis, executionGenesis [32]byte, chainID uint64) [32]byte {
	return H([]byte("unicity-bridge-coin:" + IdentityFamily + ":" + identityD(network, rootGenesis, executionGenesis, chainID)))
}

// ValueData is the genesis data: the common wallet value envelope
// tag(39050,[1,[[b(aid32),b(amount)]],null]) with exactly one inline asset.
func ValueData(aid [32]byte, amount *big.Int) []byte {
	return CTag(TagValue, CArr(CUint(ValueVersion), CArr(CArr(CBytes(aid[:]), CAmount(amount))), CNull))
}
