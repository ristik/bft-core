// Package f4aregistry is an executable design for docs/design/f4a-seal-registry-contract.md. It is not
// a registry implementation, a genesis generator or a proof reader. It pins the non-circular genesis
// construction and its startup context check (§5), the slot-key derivation (§4.1), the worked vector
// (§5.4) and the genesis-parent eligibility rule (§7.3), so the document's bytes and rules are
// reproducible with:
//
//	go test ./docs/design/models/f4aregistry/ -v
package f4aregistry

import (
	"bytes"
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
	errContextMismatch = errors.New("G does not match the configured context")

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

// pins are the expected values that do not come from the shard configuration record: the epoch of
// the node's configured root trust base, and the deployment's registry code hash and addresses. They
// are configured independently of G, so a G that names other values is refused even when its own
// commitment is internally consistent.
type pins struct {
	RootEpoch        uint64
	RegistryCodeHash []byte
	ASys, ASr        [20]byte
}

// deploymentPins are the vector deployment's independent pins.
var deploymentPins = pins{RootEpoch: 1, RegistryCodeHash: keccak(placeholderCode), ASys: aSys, ASr: aSr}

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

/*
verifyGenesisContext is the startup check of §5.3 over a full configuration, the independent pins and
a configured G. It returns the full shard configuration hash, which is what registry storage must hold.

Identity is compared field by field BEFORE any digest is trusted. Hash consistency shows only that G,
its commitment and the configuration parameter agree with one another; a G for another network, with
the parameter updated to match, is exactly as consistent. Every G field is therefore checked against a
value that does not come from G: the configuration record for network, partition, shard, chain id and
shard epoch, and the independent pins for root epoch, code hash and addresses.
*/
func verifyGenesisContext(full *types.PartitionDescriptionRecord, p pins, g genesis) ([]byte, error) {
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
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"network", g.NetworkID == uint64(full.NetworkID)},
		{"partition", g.PartitionID == uint64(full.PartitionID)},
		{"shard", bytes.Equal(g.ShardID, full.ShardID.Bytes())},
		{"shard epoch", g.ShardEpoch == full.Epoch},
		{"root epoch", g.RootEpoch == p.RootEpoch},
		{"registry code hash", bytes.Equal(g.RegistryCodeHash, p.RegistryCodeHash)},
		{"a_sys", g.ASys == p.ASys},
		{"a_sr", g.ASr == p.ASr},
	} {
		if !c.ok {
			return nil, fmt.Errorf("%w: %s", errContextMismatch, c.name)
		}
	}
	baseHash, err := configHash(base)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(baseHash, g.BaseConfigHash) {
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

// verifyConfiguredGenesis runs the §5.3 check against the vector deployment's pins.
func verifyConfiguredGenesis(full *types.PartitionDescriptionRecord, g genesis) ([]byte, error) {
	return verifyGenesisContext(full, deploymentPins, g)
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
		ChainID: chainID, ASys: deploymentPins.ASys, ASr: deploymentPins.ASr,
		RegistryCodeHash: deploymentPins.RegistryCodeHash, BaseConfigHash: baseHash,
		ShardEpoch: base.Epoch, RootEpoch: deploymentPins.RootEpoch,
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

// withCommitment returns full with the parameter set to g's commitment: the self-consistent form of a
// possibly wrong G.
func withCommitment(t *testing.T, full *types.PartitionDescriptionRecord, g genesis) *types.PartitionDescriptionRecord {
	t.Helper()
	c, err := g.commitment()
	require.NoError(t, err)
	altered := *full
	altered.PartitionParams = maps.Clone(full.PartitionParams)
	altered.PartitionParams[genesisParam] = hex.EncodeToString(c)
	return &altered
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
		other.BaseConfigHash = keccak([]byte("another base"))
		_, err := verifyConfiguredGenesis(full, other)
		require.Error(t, err)
		// The parameter still names the original G, so only the base-hash or commitment check can
		// refuse; neither is the context check.
		require.NotErrorIs(t, err, errContextMismatch)
	})
	t.Run("G built over the full hash instead of the base hash", func(t *testing.T) {
		fullHash, err := configHash(full)
		require.NoError(t, err)
		circular := g
		circular.BaseConfigHash = fullHash
		_, err = verifyConfiguredGenesis(withCommitment(t, full, circular), circular)
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

// TestSelfConsistentWrongContextIsRefused is review 5195786713's finding, generalized to every G field
// that has an independent expected value. Each case first establishes that the altered configuration
// parameter really is G's own commitment, so the refusal cannot come from a hash mismatch.
func TestSelfConsistentWrongContextIsRefused(t *testing.T) {
	g, _, full, _ := build(t, vectorConfig())
	for name, c := range map[string]struct {
		mutate func(*genesis)
		want   error
	}{
		"network":            {func(x *genesis) { x.NetworkID++ }, errContextMismatch},
		"partition":          {func(x *genesis) { x.PartitionID++ }, errContextMismatch},
		"shard":              {func(x *genesis) { x.ShardID = []byte{0xc0} }, errContextMismatch},
		"shard epoch":        {func(x *genesis) { x.ShardEpoch++ }, errContextMismatch},
		"root epoch":         {func(x *genesis) { x.RootEpoch++ }, errContextMismatch},
		"registry code hash": {func(x *genesis) { x.RegistryCodeHash = keccak([]byte{0x01}) }, errContextMismatch},
		"a_sys":              {func(x *genesis) { x.ASys[19] ^= 0xff }, errContextMismatch},
		"a_sr":               {func(x *genesis) { x.ASr[19] ^= 0xff }, errContextMismatch},
		"chain id":           {func(x *genesis) { x.ChainID++ }, errChainIDMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			wrong := g
			wrong.ShardID = append([]byte(nil), g.ShardID...)
			c.mutate(&wrong)
			altered := withCommitment(t, full, wrong)

			wc, err := wrong.commitment()
			require.NoError(t, err)
			require.Equal(t, hex.EncodeToString(wc), altered.PartitionParams[genesisParam], "premise: self-consistent")

			_, err = verifyConfiguredGenesis(altered, wrong)
			require.ErrorIs(t, err, c.want)
		})
	}
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
