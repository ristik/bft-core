package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1registry"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	testobserve "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"
)

type b1Deployment struct {
	dir       string
	conf      *types.PartitionDescriptionRecord
	confPath  string
	tb        *types.RootTrustBaseV1
	tbPath    string
	profile   b1state.Profile
	profPath  string
	allocPath string
}

func newB1Deployment(t *testing.T) *b1Deployment {
	t.Helper()
	c := certifiedchain.New(t, 5, 0)
	d := &b1Deployment{dir: t.TempDir(), conf: certifiedchain.Config(5), tb: c.TrustBase}
	d.confPath = filepath.Join(d.dir, "shard-conf.json")
	d.tbPath = filepath.Join(d.dir, "trust-base.json")
	d.profPath = filepath.Join(d.dir, "b1-profile.json")
	require.NoError(t, util.WriteJsonFile(d.confPath, d.conf))
	require.NoError(t, util.WriteJsonFile(d.tbPath, d.tb))
	var err error
	d.profile, err = deriveB1Profile(d.tb, d.conf, 1, 7_000_000, 1000)
	require.NoError(t, err)
	d.writeProfile(t, d.profile)
	// A standard genesis source whose gas limit is the profile's block gas limit.
	d.allocPath = writeGenesisSource(t, 1337, map[string]any{})
	src, err := os.ReadFile(d.allocPath)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(src, &doc))
	doc["gasLimit"] = hexutil.EncodeUint64(d.profile.MaxGas)
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(d.allocPath, raw, 0o644))
	return d
}

func (d *b1Deployment) writeProfile(t *testing.T, p b1state.Profile) {
	t.Helper()
	enc, err := json.Marshal(b1ProfileFileOf(p))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(d.profPath, enc, 0o644))
}

func (d *b1Deployment) genesis(t *testing.T, extra ...string) (out, genesisPath, identities string, err error) {
	t.Helper()
	genesisPath = filepath.Join(d.dir, "genesis.json")
	identities = filepath.Join(d.dir, "identities.json")
	args := append([]string{"--shard-conf", d.confPath, "--trust-base", d.tbPath, "--b1-profile", d.profPath, "--alloc-source", d.allocPath, "--out", genesisPath, "--identities-out", identities}, extra...)
	out, err = runEngineAPIGenesis(t, args...)
	return out, genesisPath, identities, err
}

func TestB1Genesis_IdentitiesAreTheProfilesAndTheNodeAcceptsTheArtifact(t *testing.T) {
	d := newB1Deployment(t)
	out, genesisPath, identities, err := d.genesis(t)
	require.NoError(t, err)
	require.Contains(t, out, "registry layout:            3")

	raw, err := os.ReadFile(identities)
	require.NoError(t, err)
	var doc b1IdentitiesFile
	require.NoError(t, json.Unmarshal(raw, &doc))
	hash, err := d.profile.Hash()
	require.NoError(t, err)
	require.Equal(t, hexutil.Encode(d.profile.RootGenesisID[:]), doc.RootGenesisID)
	require.Equal(t, hexutil.Encode(hash[:]), doc.ProfileHash)
	require.Equal(t, d.profile.ExecutionChainID, doc.ExecutionChainID)
	// The registry itself holds the profile hash the document names, under its own slot.
	slot := common.Hash(b1state.FixedSlot("b1.profileHash")).Hex()
	require.Equal(t, hexutil.Encode(hash[:]), doc.RegistryWords[slot])

	// The node's own validation of the artifact reproduces the generated execution genesis.
	full := readFullShardConf(t, filepath.Join(d.dir, "genesis-full-shard-conf.json"))
	h, err := bindB1Profile(d.profile, d.tb, full)
	require.NoError(t, err)
	origin, boot, err := loadB1GenesisOrigin(full, d.profile, h, genesisPath, "")
	require.NoError(t, err)
	require.Equal(t, doc.EVMGenesisHash, origin.BlockHash().Hex())
	require.True(t, boot.Genesis())
	require.Equal(t, hash, [32]byte(boot.Fields().B1ProfileHash))
	require.Equal(t, uint64(registryproof.FreshB1), boot.Fields().Layout)
}

func readFullShardConf(t *testing.T, path string) *types.PartitionDescriptionRecord {
	t.Helper()
	conf, err := readShardConf(path)
	require.NoError(t, err)
	return conf
}

func TestB1Profile_RefusedWhenItDoesNotDescribeTheDeployment(t *testing.T) {
	d := newB1Deployment(t)
	cases := map[string]func(p *b1state.Profile){
		"another root genesis": func(p *b1state.Profile) { p.RootGenesisID[0] ^= 1 },
		"another network":      func(p *b1state.Profile) { p.Network++ },
		"another chain":        func(p *b1state.Profile) { p.ExecutionChainID++ },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := d.profile
			mutate(&p)
			_, err := bindB1Profile(p, d.tb, d.conf)
			require.ErrorIs(t, err, ErrB1Profile)
		})
	}
	t.Run("network of the profile and the shard conf but not the trust base", func(t *testing.T) {
		p, conf := d.profile, *d.conf
		p.Network, conf.NetworkID = d.profile.Network+1, d.conf.NetworkID+1
		_, err := bindB1Profile(p, d.tb, &conf)
		require.ErrorIs(t, err, ErrB1Profile)
	})
	t.Run("network of the shard conf only", func(t *testing.T) {
		conf := *d.conf
		conf.NetworkID++
		_, err := bindB1Profile(d.profile, d.tb, &conf)
		require.ErrorIs(t, err, ErrB1Profile)
	})
	t.Run("matching", func(t *testing.T) {
		_, err := bindB1Profile(d.profile, d.tb, d.conf)
		require.NoError(t, err)
	})
}

func TestB1Profile_FileIsStrictAndValidated(t *testing.T) {
	d := newB1Deployment(t)
	raw, err := os.ReadFile(d.profPath)
	require.NoError(t, err)

	_, err = readB1Profile(d.profPath)
	require.NoError(t, err)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	doc["extra"] = 1
	withUnknown, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(d.profPath, withUnknown, 0o644))
	_, err = readB1Profile(d.profPath)
	require.ErrorContains(t, err, "unknown field")

	delete(doc, "extra")
	doc["systemGas"] = 1 // below the envelope of the window
	bad, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(d.profPath, bad, 0o644))
	_, err = readB1Profile(d.profPath)
	require.ErrorIs(t, err, ErrB1Profile)

	require.NoError(t, os.WriteFile(d.profPath, append(raw, []byte(`{}`)...), 0o644))
	_, err = readB1Profile(d.profPath)
	require.ErrorContains(t, err, "trailing data")
}

func TestB1Genesis_RefusalsAreIsolated(t *testing.T) {
	t.Run("profile of another root", func(t *testing.T) {
		d := newB1Deployment(t)
		p := d.profile
		p.RootGenesisID[1] ^= 1
		d.writeProfile(t, p)
		_, _, _, err := d.genesis(t)
		require.ErrorIs(t, err, ErrB1Profile)
	})
	t.Run("layout contradiction", func(t *testing.T) {
		d := newB1Deployment(t)
		_, _, _, err := d.genesis(t, "--registry-layout", "2")
		require.ErrorContains(t, err, "contradicts it")
	})
	t.Run("no trust base", func(t *testing.T) {
		d := newB1Deployment(t)
		_, err := runEngineAPIGenesis(t, "--shard-conf", d.confPath, "--b1-profile", d.profPath, "--alloc-source", d.allocPath, "--out", filepath.Join(d.dir, "g.json"))
		require.ErrorContains(t, err, "requires --trust-base")
	})
	t.Run("identities without a profile", func(t *testing.T) {
		d := newB1Deployment(t)
		_, err := runEngineAPIGenesis(t, "--shard-conf", d.confPath, "--out", filepath.Join(d.dir, "g.json"), "--identities-out", filepath.Join(d.dir, "i.json"))
		require.ErrorContains(t, err, "require --b1-profile")
	})
	t.Run("gas limit other than the profile's", func(t *testing.T) {
		d := newB1Deployment(t)
		src, err := os.ReadFile(d.allocPath)
		require.NoError(t, err)
		var doc map[string]any
		require.NoError(t, json.Unmarshal(src, &doc))
		doc["gasLimit"] = hexutil.EncodeUint64(d.profile.MaxGas + 1)
		raw, err := json.Marshal(doc)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(d.allocPath, raw, 0o644))
		_, _, _, err = d.genesis(t)
		require.Error(t, err)
		require.ErrorIs(t, err, registrygenesis.ErrEVMParams)
	})
}

func TestB1Origin_ARegistryOfAnotherProfileIsNotAccepted(t *testing.T) {
	d := newB1Deployment(t)
	_, genesisPath, _, err := d.genesis(t)
	require.NoError(t, err)
	full := readFullShardConf(t, filepath.Join(d.dir, "genesis-full-shard-conf.json"))
	other := d.profile
	other.WCert, other.DeltaEV, other.DeltaHold = 2, 3, 4
	other.RestGas = b1registry.MinRestGas(other.WCert)
	var e error
	other.SystemGas, e = other.RequiredSystemGas()
	require.NoError(t, e)
	other.MaxGas = other.SystemGas + other.OrdinaryCapacity
	h, err := q3format.NewHistory(d.tb)
	require.NoError(t, err)
	_, _, err = loadB1GenesisOrigin(full, other, h, genesisPath, "")
	require.Error(t, err, "a genesis generated for window 1 must not validate under window 2")
}

// ---- proof fetcher -----------------------------------------------------------------------------------------------------------------------

type recordedCall struct {
	method string
	params []any
}

type fakeProofCaller struct {
	calls  []recordedCall
	result any
}

func (f *fakeProofCaller) Call(_ context.Context, method string, params []any) (json.RawMessage, error) {
	f.calls = append(f.calls, recordedCall{method, params})
	return json.Marshal(f.result)
}

func b1ParentSnapshot(t *testing.T) registryproof.Snapshot {
	t.Helper()
	d := newB1Deployment(t)
	_, genesisPath, _, err := d.genesis(t)
	require.NoError(t, err)
	full := readFullShardConf(t, filepath.Join(d.dir, "genesis-full-shard-conf.json"))
	h, err := bindB1Profile(d.profile, d.tb, full)
	require.NoError(t, err)
	_, boot, err := loadB1GenesisOrigin(full, d.profile, h, genesisPath, "")
	require.NoError(t, err)
	return boot
}

func TestB1ProofFetcher_AsksByBlockHashAndRefusesAnyOtherAnswer(t *testing.T) {
	snap := b1ParentSnapshot(t)
	keys := []common.Hash{common.HexToHash("0x01"), common.HexToHash("0x02")}
	good := func() registryproof.GetProofResult {
		return registryproof.GetProofResult{
			Address: registryproof.RegistryAddress,
			StorageProof: []registryproof.StorageProofResult{
				{Key: keys[0].Hex(), Proof: []hexutil.Bytes{{0xaa}, {0xbb}}},
				{Key: keys[1].Hex(), Proof: []hexutil.Bytes{{0xcc}}},
			},
		}
	}

	t.Run("accepted", func(t *testing.T) {
		rpc := &fakeProofCaller{result: good()}
		proofs, err := b1ProofFetcher(rpc)(context.Background(), snap, keys)
		require.NoError(t, err)
		require.Equal(t, [][][]byte{{{0xaa}, {0xbb}}, {{0xcc}}}, proofs)
		require.Len(t, rpc.calls, 1)
		require.Equal(t, "eth_getProof", rpc.calls[0].method)
		require.Equal(t, registryproof.RegistryAddress, rpc.calls[0].params[0])
		require.Equal(t, map[string]any{"blockHash": snap.ParentHash()}, rpc.calls[0].params[2])
	})
	refusals := map[string]func(r *registryproof.GetProofResult){
		"another account": func(r *registryproof.GetProofResult) { r.Address = common.HexToAddress("0x01") },
		"a missing proof": func(r *registryproof.GetProofResult) { r.StorageProof = r.StorageProof[:1] },
		"an extra proof":  func(r *registryproof.GetProofResult) { r.StorageProof = append(r.StorageProof, r.StorageProof[0]) },
		"reordered proofs": func(r *registryproof.GetProofResult) {
			r.StorageProof[0], r.StorageProof[1] = r.StorageProof[1], r.StorageProof[0]
		},
		"another key": func(r *registryproof.GetProofResult) { r.StorageProof[1].Key = common.HexToHash("0x03").Hex() },
	}
	for name, mutate := range refusals {
		t.Run(name, func(t *testing.T) {
			r := good()
			mutate(&r)
			_, err := b1ProofFetcher(&fakeProofCaller{result: r})(context.Background(), snap, keys)
			require.ErrorIs(t, err, ErrB1Proof)
		})
	}
	t.Run("no snapshot", func(t *testing.T) {
		rpc := &fakeProofCaller{result: good()}
		_, err := b1ProofFetcher(rpc)(context.Background(), registryproof.Snapshot{}, keys)
		require.ErrorIs(t, err, ErrB1Proof)
		require.Empty(t, rpc.calls)
	})
	t.Run("no keys", func(t *testing.T) {
		_, err := b1ProofFetcher(&fakeProofCaller{result: good()})(context.Background(), snap, nil)
		require.ErrorIs(t, err, ErrB1Proof)
	})
	t.Run("too many keys", func(t *testing.T) {
		rpc := &fakeProofCaller{result: good()}
		_, err := b1ProofFetcher(rpc)(context.Background(), snap, make([]common.Hash, b1MaxProofKeys+1))
		require.ErrorIs(t, err, ErrB1Proof)
		require.Empty(t, rpc.calls, "the bound is checked before the request")
	})
}

func TestB1ProfileCommand_WritesTheProfileAndTheClientFlags(t *testing.T) {
	d := newB1Deployment(t)
	out := filepath.Join(d.dir, "derived.json")
	var stdout bytes.Buffer
	cmd := New(testobserve.NewFactory(t))
	cmd.baseCmd.SetOut(&stdout)
	cmd.baseCmd.SetArgs([]string{"engine-api", "b1-profile", "--shard-conf", d.confPath, "--trust-base", d.tbPath, "--out", out})
	require.NoError(t, cmd.Execute(context.Background()))
	got, err := readB1Profile(out)
	require.NoError(t, err)
	require.Equal(t, d.profile, got)
	hash, _ := got.Hash()
	require.Contains(t, stdout.String(), "--unicity.profile-hash="+hexutil.Encode(hash[:]))
	require.Contains(t, stdout.String(), "--unicity.root-genesis-id="+hexutil.Encode(got.RootGenesisID[:]))
}

func TestB1RunFlags_EachRequirementIsEnforced(t *testing.T) {
	ok := func() *shardNodeRunFlags {
		f := &shardNodeRunFlags{B1Profile: "p.json", RegistryLayout: 1, Executor: "engine-api", GenesisFile: "g.json", ExecutionJournal: "j.db", TrustHistoryProfile2: true}
		return f
	}
	f := ok()
	require.NoError(t, validateB1RunFlags(f))
	require.EqualValues(t, b1RegistryLayout, f.RegistryLayout, "the profile selects the layout")

	cases := map[string]func(f *shardNodeRunFlags){
		"not engine-api":       func(f *shardNodeRunFlags) { f.Executor = "fake" },
		"no genesis":           func(f *shardNodeRunFlags) { f.GenesisFile = "" },
		"no execution journal": func(f *shardNodeRunFlags) { f.ExecutionJournal = "" },
		"no profile-2 trust":   func(f *shardNodeRunFlags) { f.TrustHistoryProfile2 = false },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := ok()
			mutate(f)
			require.ErrorContains(t, validateB1RunFlags(f), "--b1-profile requires")
		})
	}
	t.Run("another layout", func(t *testing.T) {
		f := ok()
		f.RegistryLayout = 2
		require.ErrorContains(t, validateB1RunFlags(f), "contradicts it")
	})
	t.Run("layout 3 without the profile", func(t *testing.T) {
		require.ErrorContains(t, validateB1RunFlags(&shardNodeRunFlags{RegistryLayout: 3}), "requires --b1-profile")
	})
	t.Run("no profile, ordinary layout", func(t *testing.T) {
		require.NoError(t, validateB1RunFlags(&shardNodeRunFlags{RegistryLayout: 2}))
	})
}
