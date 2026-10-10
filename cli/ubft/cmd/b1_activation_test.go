package cmd

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1registry"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/evmassign"
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

// A fresh-B1 genesis (registry layout 3) carries validator_coupling=true in the exported full configuration exactly as the layout 2 launch genesis
// does, so every root validator refuses an uncoupled committee change on any B1 deployment; an explicit opt-out is refused.
func TestB1Genesis_ExportsTheCouplingParameter(t *testing.T) {
	d := newB1Deployment(t)
	require.NotContains(t, d.conf.PartitionParams, evmassign.CouplingParam, "premise: the shard configuration does not name it")
	_, _, _, err := d.genesis(t)
	require.NoError(t, err)
	full := readFullShardConf(t, filepath.Join(d.dir, "genesis-full-shard-conf.json"))
	require.Equal(t, "true", full.PartitionParams[evmassign.CouplingParam])
	require.True(t, evmassign.CouplingRequired(full))
	without := *full
	without.PartitionParams = map[string]string{}
	for k, v := range full.PartitionParams {
		if k != evmassign.CouplingParam {
			without.PartitionParams[k] = v
		}
	}
	a, err := full.Hash(crypto.SHA256)
	require.NoError(t, err)
	b, err := without.Hash(crypto.SHA256)
	require.NoError(t, err)
	require.NotEqual(t, a, b, "the full configuration hash commits to the parameter")

	t.Run("naming it explicitly changes nothing", func(t *testing.T) {
		d := newB1Deployment(t)
		d.conf.PartitionParams[evmassign.CouplingParam] = "true"
		require.NoError(t, util.WriteJsonFile(d.confPath, d.conf))
		_, _, _, err := d.genesis(t)
		require.NoError(t, err)
		again := readFullShardConf(t, filepath.Join(d.dir, "genesis-full-shard-conf.json"))
		require.Equal(t, "true", again.PartitionParams[evmassign.CouplingParam])
	})
	t.Run("an explicit opt-out is refused", func(t *testing.T) {
		d := newB1Deployment(t)
		d.conf.PartitionParams[evmassign.CouplingParam] = "false"
		require.NoError(t, util.WriteJsonFile(d.confPath, d.conf))
		_, _, _, err := d.genesis(t)
		require.ErrorContains(t, err, "registry layout 3 genesis requires validator_coupling=true")
	})
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

// ---- the election hook's price ---------------------------------------------------------------------------------------------------------

func electDeployment(t *testing.T, m b1state.ElectMeasurement) (*b1Deployment, b1state.Profile, b1ProfileFile) {
	t.Helper()
	d := newB1Deployment(t)
	hooks := b1Hooks{RecordsCustody: [20]byte{0xc1}, HRecords: 2, HookRecordGas: 3_000_000, ElectionContract: [20]byte{0xe1}, Measurement: &m}
	p, err := deriveB1Profile(d.tb, d.conf, 1, 7_000_000, 1000, hooks)
	require.NoError(t, err)
	file := b1ProfileFileOf(p)
	file.ElectMeasurement, file.ElectCaps = &m, &b1state.ElectCaps{VMax: 16, LMax: 2, NMax: 8}
	return d, p, file
}

func (d *b1Deployment) writeFile(t *testing.T, f b1ProfileFile) {
	t.Helper()
	enc, err := json.Marshal(f)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(d.profPath, enc, 0o644))
}

func TestB1Profile_TheElectionPriceIsTheRecordedMeasurementPinnedWithTheMargin(t *testing.T) {
	m := b1state.ElectMeasurement{V: 16, L: 2, C: 8, Gas: 4_987_664}
	d, p, file := electDeployment(t, m)
	require.EqualValues(t, 6_234_580, p.ElectGas, "ceil(4,987,664 x 1.25)")
	require.Equal(t, [20]byte{0xe1}, p.ElectionContract)
	envelope, err := p.HookEnvelopeGas()
	require.NoError(t, err)
	require.Equal(t, b1state.HookReadsGas+2*3_000_000+p.ElectGas, envelope, "the price is part of the reserved system gas")

	d.writeFile(t, file)
	read, err := readB1Profile(d.profPath)
	require.NoError(t, err)
	require.Equal(t, p, read, "the file round-trips every pin")

	// a profile file with no hooks is unchanged: none of the new keys appear
	plain, err := json.Marshal(b1ProfileFileOf(d.profile))
	require.NoError(t, err)
	require.NotContains(t, string(plain), "elect")
	require.NotContains(t, string(plain), "recordsCustody")
}

func TestB1Profile_AHandTypedOrMissingElectionPriceIsRefused(t *testing.T) {
	m := b1state.ElectMeasurement{V: 16, L: 2, C: 8, Gas: 4_987_664}
	for name, change := range map[string]func(*b1ProfileFile){
		"a typed price":              func(f *b1ProfileFile) { f.ElectGas = 7_000_000 },
		"a price one above":          func(f *b1ProfileFile) { f.ElectGas++ },
		"the bare measurement":       func(f *b1ProfileFile) { f.ElectGas = f.ElectMeasurement.Gas },
		"no recorded measurement":    func(f *b1ProfileFile) { f.ElectMeasurement = nil },
		"a zero measurement":         func(f *b1ProfileFile) { f.ElectMeasurement = &b1state.ElectMeasurement{V: 16, L: 2, C: 8} },
		"a measurement without hook": func(f *b1ProfileFile) { f.ElectionContract, f.ElectGas = nil, 0 },
		"a price without a contract": func(f *b1ProfileFile) { f.ElectionContract, f.ElectMeasurement, f.ElectCaps = nil, nil, nil },
		"caps without a contract":    func(f *b1ProfileFile) { f.ElectionContract, f.ElectGas, f.ElectMeasurement = nil, 0, nil },
		"no recorded caps":           func(f *b1ProfileFile) { f.ElectCaps = nil },
		"caps above the measurement": func(f *b1ProfileFile) { f.ElectCaps = &b1state.ElectCaps{VMax: 128, LMax: 2, NMax: 8} },
		"caps below the measurement": func(f *b1ProfileFile) { f.ElectCaps = &b1state.ElectCaps{VMax: 16, LMax: 1, NMax: 8} },
		"committee cap differs":      func(f *b1ProfileFile) { f.ElectCaps = &b1state.ElectCaps{VMax: 16, LMax: 2, NMax: 16} },
		"caps outside the domain":    func(f *b1ProfileFile) { f.ElectCaps = &b1state.ElectCaps{VMax: 16, LMax: 3, NMax: 8} },
	} {
		t.Run(name, func(t *testing.T) {
			d, _, file := electDeployment(t, m)
			change(&file)
			d.writeFile(t, file)
			_, err := readB1Profile(d.profPath)
			require.ErrorIs(t, err, ErrB1Profile)
		})
	}
	d := newB1Deployment(t)
	_, err := deriveB1Profile(d.tb, d.conf, 1, 7_000_000, 1000, b1Hooks{RecordsCustody: [20]byte{0xc1}, HRecords: 1, HookRecordGas: 1, ElectionContract: [20]byte{0xe1}})
	require.Error(t, err, "an election without a measurement cannot be derived")
}

func TestB1Profile_TheHookFlagsGoTogether(t *testing.T) {
	m := b1state.ElectMeasurement{V: 16, L: 2, C: 8, Gas: 4_987_664}
	path := filepath.Join(t.TempDir(), "m.json")
	enc, _ := json.Marshal(m)
	require.NoError(t, os.WriteFile(path, enc, 0o644))
	ok, err := parseB1Hooks("0x00000000000000000000000000000000000000c1", 2, 3_000_000, "0x00000000000000000000000000000000000000e1", path, "16,2,8")
	require.NoError(t, err)
	require.Equal(t, m, *ok.Measurement)
	require.Equal(t, b1state.ElectCaps{VMax: 16, LMax: 2, NMax: 8}, *ok.Caps)
	for name, args := range map[string][]any{
		"flags without the records hook":  {"", uint32(2), uint64(1), "", "", ""},
		"election without a measurement":  {"0x00000000000000000000000000000000000000c1", uint32(2), uint64(1), "0x00000000000000000000000000000000000000e1", "", "16,2,8"},
		"measurement without an election": {"0x00000000000000000000000000000000000000c1", uint32(2), uint64(1), "", path, "16,2,8"},
		"not an address":                  {"c1", uint32(2), uint64(1), "", "", ""},
		"election not an address":         {"0x00000000000000000000000000000000000000c1", uint32(2), uint64(1), "e1", path, "16,2,8"},
		"missing measurement file":        {"0x00000000000000000000000000000000000000c1", uint32(2), uint64(1), "0x00000000000000000000000000000000000000e1", path + ".none", "16,2,8"},
		"election without caps":           {"0x00000000000000000000000000000000000000c1", uint32(2), uint64(1), "0x00000000000000000000000000000000000000e1", path, ""},
		"caps above the measurement":      {"0x00000000000000000000000000000000000000c1", uint32(2), uint64(1), "0x00000000000000000000000000000000000000e1", path, "128,2,8"},
		"caps below the measurement":      {"0x00000000000000000000000000000000000000c1", uint32(2), uint64(1), "0x00000000000000000000000000000000000000e1", path, "16,1,8"},
		"committee cap differs":           {"0x00000000000000000000000000000000000000c1", uint32(2), uint64(1), "0x00000000000000000000000000000000000000e1", path, "16,2,16"},
		"malformed caps":                  {"0x00000000000000000000000000000000000000c1", uint32(2), uint64(1), "0x00000000000000000000000000000000000000e1", path, "16,2"},
		"caps outside the domain":         {"0x00000000000000000000000000000000000000c1", uint32(2), uint64(1), "0x00000000000000000000000000000000000000e1", path, "16,3,8"},
	} {
		_, err := parseB1Hooks(args[0].(string), args[1].(uint32), args[2].(uint64), args[3].(string), args[4].(string), args[5].(string))
		require.Error(t, err, name)
	}
}

func TestEngineAPICheckElectGas(t *testing.T) {
	m := b1state.ElectMeasurement{V: 16, L: 2, C: 8, Gas: 4_987_664}
	d, _, file := electDeployment(t, m)
	d.writeFile(t, file)
	write := func(x b1state.ElectMeasurement) string {
		p := filepath.Join(t.TempDir(), "fresh.json")
		enc, _ := json.Marshal(x)
		require.NoError(t, os.WriteFile(p, enc, 0o644))
		return p
	}
	run := func(fresh string) (string, error) {
		cmd := engineAPICheckElectGasCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"--b1-profile", d.profPath, "--measurement", fresh})
		err := cmd.Execute()
		return out.String(), err
	}
	out, err := run(write(m))
	require.NoError(t, err)
	require.Contains(t, out, "covers the fresh measurement")
	_, err = run(write(b1state.ElectMeasurement{V: 16, L: 2, C: 8, Gas: 6_000_000}))
	require.NoError(t, err, "the contracts grew a little: inside the margin")
	_, err = run(write(b1state.ElectMeasurement{V: 16, L: 2, C: 8, Gas: 6_300_000}))
	require.ErrorIs(t, err, b1state.ErrElectGas, "the contracts grew past the margin: regenerate the profile")
	for name, fresh := range map[string]b1state.ElectMeasurement{
		"a larger V":          {V: 64, L: 2, C: 8, Gas: 1_000_000},
		"a smaller V":         {V: 8, L: 2, C: 8, Gas: 1_000_000},
		"fewer lots":          {V: 16, L: 1, C: 8, Gas: 1_000_000},
		"a smaller committee": {V: 16, L: 2, C: 4, Gas: 1_000_000},
	} {
		_, err = run(write(fresh))
		require.ErrorIs(t, err, b1state.ErrElectGas, name+": not the deployed caps")
	}

	// a profile with no election hook has nothing to check
	plain := newB1Deployment(t)
	cmd := engineAPICheckElectGasCmd()
	cmd.SetArgs([]string{"--b1-profile", plain.profPath, "--measurement", write(m)})
	require.Error(t, cmd.Execute())
}

func TestTheUrethFlagsPinEveryHookTheProfileHashCommits(t *testing.T) {
	m := b1state.ElectMeasurement{V: 16, L: 2, C: 8, Gas: 4_987_664}
	_, p, _ := electDeployment(t, m)
	hash, err := p.Hash()
	require.NoError(t, err)
	line := urethFlags(p, hash)
	for _, want := range []string{"--unicity.records-custody=0xc100000000000000000000000000000000000000", "--unicity.h-records=2",
		"--unicity.hook-record-gas=3000000", "--unicity.election=0xe100000000000000000000000000000000000000", "--unicity.elect-gas=6234580"} {
		require.Contains(t, line, want)
	}
	d := newB1Deployment(t)
	plainHash, err := d.profile.Hash()
	require.NoError(t, err)
	plain := urethFlags(d.profile, plainHash)
	require.NotContains(t, plain, "records-custody")
	require.NotContains(t, plain, "election")
	// the records hook alone prints no election flags
	records := p
	records.ElectionContract, records.ElectGas = [20]byte{}, 0
	rh, err := records.Hash()
	require.NoError(t, err)
	require.Contains(t, urethFlags(records, rh), "--unicity.records-custody")
	require.NotContains(t, urethFlags(records, rh), "election")
}

// The allocation manifest (T1/T4/T6 geneses) compiles into the fresh-B1 genesis too: the genesis carries the profile's block gas limit, the manifest's
// funded and contract accounts survive, and the node's own validation of the artifact accepts it.
func TestB1Genesis_AManifestCompilesIntoTheFreshB1Genesis(t *testing.T) {
	d := newB1Deployment(t)
	manifestPath := filepath.Join(t.TempDir(), "allocation-build.json")
	baseManifest, err := os.ReadFile(filepath.Join("..", "..", "..", "registrygenesis", "testdata", "allocation-build-v1.example.json"))
	require.NoError(t, err)
	manifestBytes, err := registrygenesis.ExportAllocationManifest(baseManifest)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, manifestBytes, 0o600))
	genesisPath := filepath.Join(d.dir, "manifest-genesis.json")
	_, err = runEngineAPIGenesis(t, "--shard-conf", d.confPath, "--trust-base", d.tbPath, "--b1-profile", d.profPath, "--manifest", manifestPath,
		"--out", genesisPath, "--identities-out", filepath.Join(d.dir, "manifest-identities.json"))
	require.NoError(t, err)
	doc := readFinalizedGenesis(t, genesisPath)
	require.Contains(t, doc.Alloc, "0x1000000000000000000000000000000000000001", "the manifest's funded account survives")
	require.NotEmpty(t, doc.Alloc["0x9b137463d4e7986d7f535f9b79e28b4ef1938e9b"].Code, "and its exported contract code")
	var raw struct {
		GasLimit string `json:"gasLimit"`
	}
	b, err := os.ReadFile(genesisPath)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &raw))
	require.Equal(t, hexutil.EncodeUint64(d.profile.MaxGas), raw.GasLimit, "the genesis carries the profile's block gas limit")
	full := readFullShardConf(t, filepath.Join(d.dir, "manifest-genesis-full-shard-conf.json"))
	h, err := bindB1Profile(d.profile, d.tb, full)
	require.NoError(t, err)
	_, _, err = loadB1GenesisOrigin(full, d.profile, h, genesisPath, "")
	require.NoError(t, err, "the node's own validation accepts the artifact")
}
