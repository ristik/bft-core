// Package f4aregistry is an executable design for docs/design/f4a-seal-registry-contract.md. It is not
// a registry implementation, a genesis generator or a proof reader. It pins the non-circular genesis
// construction (§5), the slot-key derivation (§4.1) and the worked vector (§5.4), so the document's
// bytes are reproducible with:
//
//	go test ./docs/design/models/f4aregistry/ -v
package f4aregistry

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"golang.org/x/crypto/sha3"
)

const (
	genesisParam  = "seal_registry_genesis"
	chainIDParam  = "chain_id"
	slotDomain    = "unicity.seal-registry.v1/"
	genesisDomain = "UNICITY_SEAL_REGISTRY_GENESIS"
	layoutVersion = 1
)

var (
	errNoChainID       = errors.New("configuration has no chain_id partition parameter")
	errGenesisEncoding = errors.New("seal_registry_genesis is not 64 lowercase hex characters")
	errGenesisMismatch = errors.New("seal_registry_genesis does not equal the commitment recomputed from G")
	errChainIDMismatch = errors.New("G chain id does not equal the configured chain_id")

	lowerHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

	aSys = [20]byte{0: 0xff, 19: 0x01}
	aSr  = [20]byte{0: 0xff, 19: 0x02}

	// placeholderCode stands in for the registry runtime code, which does not exist yet. The vector
	// pins the construction, not a real code hash.
	placeholderCode = []byte{0x00}
)

func keccak(b []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	return h.Sum(nil)
}

func slotKey(name string) []byte { return keccak([]byte(slotDomain + name)) }

// genesis is the record G of §5.1. It has no field derived from the EVM genesis block.
type genesis struct {
	NetworkID        uint64
	PartitionID      uint64
	ShardID          []byte
	ChainID          uint64
	ASys, ASr        [20]byte
	RegistryCodeHash []byte
	BaseConfigHash   []byte
	ShardEpoch       uint64
	RootEpoch        uint64
}

func (g genesis) encode() ([]byte, error) {
	return types.Cbor.Marshal([]any{
		genesisDomain, uint64(layoutVersion),
		g.NetworkID, g.PartitionID, g.ShardID, g.ChainID,
		g.ASys[:], g.ASr[:],
		g.RegistryCodeHash, g.BaseConfigHash,
		g.ShardEpoch, g.RootEpoch,
	})
}

func (g genesis) commitment() ([]byte, error) {
	enc, err := g.encode()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(enc)
	return sum[:], nil
}

// baseConfig is step 1 of §5.3: the record with only seal_registry_genesis removed. chain_id must
// remain, so the reduced map is never empty and nil-versus-empty map encoding never arises.
func baseConfig(pdr *types.PartitionDescriptionRecord) (*types.PartitionDescriptionRecord, error) {
	if _, ok := pdr.PartitionParams[chainIDParam]; !ok {
		return nil, errNoChainID
	}
	base := *pdr
	base.PartitionParams = maps.Clone(pdr.PartitionParams)
	delete(base.PartitionParams, genesisParam)
	return &base, nil
}

func configHash(pdr *types.PartitionDescriptionRecord) ([]byte, error) {
	return pdr.Hash(crypto.SHA256)
}

// verifyConfiguredGenesis is the startup check of §5.3 over a full configuration and a configured G.
// It returns the full shard configuration hash, which is what registry storage must hold.
func verifyConfiguredGenesis(full *types.PartitionDescriptionRecord, g genesis) ([]byte, error) {
	raw, ok := full.PartitionParams[genesisParam]
	if !ok || !lowerHex64.MatchString(raw) {
		return nil, errGenesisEncoding
	}
	base, err := baseConfig(full)
	if err != nil {
		return nil, err
	}
	chainID, err := strconv.ParseUint(base.PartitionParams[chainIDParam], 10, 64)
	if err != nil || chainID != g.ChainID {
		return nil, errChainIDMismatch
	}
	baseHash, err := configHash(base)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(baseHash) != hex.EncodeToString(g.BaseConfigHash) {
		return nil, fmt.Errorf("G base configuration hash %x is not the configuration's %x", g.BaseConfigHash, baseHash)
	}
	c, err := g.commitment()
	if err != nil {
		return nil, err
	}
	if raw != hex.EncodeToString(c) {
		return nil, errGenesisMismatch
	}
	return configHash(full)
}

// build runs steps 1 to 4 of §5.3 from a configuration that does not yet carry the parameter.
func build(t *testing.T, withoutParam *types.PartitionDescriptionRecord) (genesis, []byte, *types.PartitionDescriptionRecord, []byte) {
	t.Helper()
	base, err := baseConfig(withoutParam)
	require.NoError(t, err)
	baseHash, err := configHash(base)
	require.NoError(t, err)
	chainID, err := strconv.ParseUint(base.PartitionParams[chainIDParam], 10, 64)
	require.NoError(t, err)
	g := genesis{
		NetworkID: uint64(base.NetworkID), PartitionID: uint64(base.PartitionID), ShardID: base.ShardID.Bytes(),
		ChainID: chainID, ASys: aSys, ASr: aSr,
		RegistryCodeHash: keccak(placeholderCode), BaseConfigHash: baseHash,
		ShardEpoch: base.Epoch, RootEpoch: 1,
	}
	c, err := g.commitment()
	require.NoError(t, err)
	full := *base
	full.PartitionParams = maps.Clone(base.PartitionParams)
	full.PartitionParams[genesisParam] = hex.EncodeToString(c)
	fullHash, err := configHash(&full)
	require.NoError(t, err)
	return g, c, &full, fullHash
}

// vectorConfig is the illustrative configuration of §5.4.
func vectorConfig() *types.PartitionDescriptionRecord {
	return &types.PartitionDescriptionRecord{
		Version:         1,
		NetworkID:       3,
		PartitionID:     8,
		T2Timeout:       5 * time.Second,
		PartitionParams: map[string]string{chainIDParam: "1337"},
		Epoch:           0,
		Validators: []*types.NodeInfo{
			{NodeID: "validator-1", SigKey: append([]byte{0x02}, make([]byte, 32)...), Stake: 1},
		},
	}
}

// The document's §5.4 values. A change to any of them is a change to the design, not a test update.
const (
	wantBaseConfigHash    = "3582bd0f44572e45c1e46f9b5c9797991dff8a59cdf85cd12e2879d7d67c5653"
	wantGenesisCBOR       = "8c781d554e49434954595f5345414c5f52454749535452595f47454e45534953010308418019053954ff0000000000000000000000000000000000000154ff000000000000000000000000000000000000025820bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a58203582bd0f44572e45c1e46f9b5c9797991dff8a59cdf85cd12e2879d7d67c56530001"
	wantGenesisCommitment = "071a4f34498689e1f26353434c92f763ddaaba8de9cc634aa68af6e1bf65eab8"
	wantFullShardConfHash = "3a2c73649214e56d5e98d1c2d06cff56e7a5d67037a25bcf0e43fcaff8987a6b"
)

var slotNames = []string{
	"layoutVersion", "genesisCommitment", "config.shardConfHash", "assignment.epoch", "assignment.rootEpoch",
	"clock.rootRound", "origin.rootEpoch", "origin.timestamp", "origin.treeRoot", "origin.identity",
	"origin.trHash", "round.authorized", "input.commitment", "certified.round", "certified.stateHash",
	"certified.hasBlockHash", "certified.blockHash", "phase", "outcomes.round", "outcomes.commitment",
	"transition.cursor", "inbox.consumed",
}

func TestGenesisVector(t *testing.T) {
	g, c, full, fullHash := build(t, vectorConfig())
	enc, err := g.encode()
	require.NoError(t, err)

	got := map[string]string{
		"baseConfigHash":    hex.EncodeToString(g.BaseConfigHash),
		"genesisCBOR":       hex.EncodeToString(enc),
		"genesisCommitment": hex.EncodeToString(c),
		"fullShardConfHash": hex.EncodeToString(fullHash),
	}
	want := map[string]string{
		"baseConfigHash":    wantBaseConfigHash,
		"genesisCBOR":       wantGenesisCBOR,
		"genesisCommitment": wantGenesisCommitment,
		"fullShardConfHash": wantFullShardConfHash,
	}
	for _, k := range []string{"baseConfigHash", "genesisCBOR", "genesisCommitment", "fullShardConfHash"} {
		t.Logf("%-18s %s", k, got[k])
	}
	for _, k := range []string{"baseConfigHash", "genesisCBOR", "genesisCommitment", "fullShardConfHash"} {
		require.Equal(t, want[k], got[k], k)
	}

	storageHash, err := verifyConfiguredGenesis(full, g)
	require.NoError(t, err)
	require.Equal(t, fullHash, storageHash, "registry storage holds the FULL configuration hash")
	require.NotEqual(t, g.BaseConfigHash, fullHash, "inserting the commitment must change the configuration hash")
}

func TestSlotKeys(t *testing.T) {
	seen := map[string]string{}
	for _, name := range slotNames {
		k := hex.EncodeToString(slotKey(name))
		require.NotContains(t, seen, k, "slot key collision between %s and %s", name, seen[k])
		seen[k] = name
		t.Logf("%-24s %s", name, k)
	}
}

func TestGenesisRefusals(t *testing.T) {
	g, _, full, _ := build(t, vectorConfig())

	t.Run("premise: the built configuration verifies", func(t *testing.T) {
		_, err := verifyConfiguredGenesis(full, g)
		require.NoError(t, err)
	})
	t.Run("no chain_id", func(t *testing.T) {
		bad := *full
		bad.PartitionParams = maps.Clone(full.PartitionParams)
		delete(bad.PartitionParams, chainIDParam)
		_, err := verifyConfiguredGenesis(&bad, g)
		require.ErrorIs(t, err, errNoChainID)
	})
	for name, value := range map[string]func(string) string{
		"0x prefix":  func(s string) string { return "0x" + s },
		"upper case": func(s string) string { return fmt.Sprintf("%X", mustHex(t, s)) },
		"truncated":  func(s string) string { return s[:63] },
	} {
		t.Run("encoding: "+name, func(t *testing.T) {
			bad := *full
			bad.PartitionParams = maps.Clone(full.PartitionParams)
			bad.PartitionParams[genesisParam] = value(full.PartitionParams[genesisParam])
			_, err := verifyConfiguredGenesis(&bad, g)
			require.ErrorIs(t, err, errGenesisEncoding)
		})
	}
	t.Run("configuration names a commitment for a different G", func(t *testing.T) {
		other := g
		other.RootEpoch = 2
		_, err := verifyConfiguredGenesis(full, other)
		require.ErrorIs(t, err, errGenesisMismatch)
	})
	t.Run("G built over the full hash instead of the base hash", func(t *testing.T) {
		fullHash, err := configHash(full)
		require.NoError(t, err)
		circular := g
		circular.BaseConfigHash = fullHash
		_, err = verifyConfiguredGenesis(full, circular)
		require.Error(t, err)
	})
	t.Run("another configuration field changed after G was built", func(t *testing.T) {
		bad := *full
		bad.PartitionParams = maps.Clone(full.PartitionParams)
		bad.T2Timeout = 6 * time.Second
		_, err := verifyConfiguredGenesis(&bad, g)
		require.Error(t, err)
	})
}

func TestEveryGenesisFieldIsCommitted(t *testing.T) {
	g, c, _, _ := build(t, vectorConfig())
	mutations := map[string]func(*genesis){
		"network":     func(x *genesis) { x.NetworkID++ },
		"partition":   func(x *genesis) { x.PartitionID++ },
		"shard":       func(x *genesis) { x.ShardID = []byte{0xc0} },
		"chain id":    func(x *genesis) { x.ChainID++ },
		"a_sys":       func(x *genesis) { x.ASys[19] ^= 0xff },
		"a_sr":        func(x *genesis) { x.ASr[19] ^= 0xff },
		"code hash":   func(x *genesis) { x.RegistryCodeHash = keccak([]byte{0x01}) },
		"base config": func(x *genesis) { x.BaseConfigHash = keccak([]byte("other")) },
		"shard epoch": func(x *genesis) { x.ShardEpoch++ },
		"root epoch":  func(x *genesis) { x.RootEpoch++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			m := g
			m.ShardID = append([]byte(nil), g.ShardID...)
			mutate(&m)
			mc, err := m.commitment()
			require.NoError(t, err)
			require.NotEqual(t, c, mc)
		})
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}
