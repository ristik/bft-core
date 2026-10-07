package bridgeprofile

import "math/big"

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

// DeriveType is ty = H(C("UNICITY_NATIVE_WHOLE",network,executionGenesis,vault)):
// network is a uint, executionGenesis and vault are bstr.
func DeriveType(network uint16, executionGenesis [32]byte, vault [20]byte) [32]byte {
	return H(CArr(CBytes([]byte("UNICITY_NATIVE_WHOLE")), CUint(uint64(network)),
		CBytes(executionGenesis[:]), CBytes(vault[:])))
}

// DeriveAsset is aid = H(C("UNICITY_NATIVE_UCT",network,executionGenesis)).
func DeriveAsset(network uint16, executionGenesis [32]byte) [32]byte {
	return H(CArr(CBytes([]byte("UNICITY_NATIVE_UCT")), CUint(uint64(network)),
		CBytes(executionGenesis[:])))
}

// MintData is the exact mint payload C(b(aid),b(amount)).
func MintData(aid [32]byte, amount *big.Int) []byte {
	return CArr(CBytes(aid[:]), CAmount(amount))
}
