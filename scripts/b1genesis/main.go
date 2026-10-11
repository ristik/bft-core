// b1genesis exports an inactive fresh B1 allocation and complete storage manifest.
// It never contacts a node or deploys anything.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-core/b1registry"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-go-base/types"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	profile := flag.String("profile", "", "complete b1state.Profile JSON: hashes as 32-byte arrays, or the 0x-hex file `ubft engine-api b1-profile` writes")
	root := flag.String("root-genesis", "", "pinned self-signed RootTrustBaseV1 JSON")
	shard := flag.String("shard-conf", "", "unbound PartitionDescriptionRecord JSON")
	out := flag.String("out", "", "new output directory")
	verify := flag.String("verify", "", "instead of --out: the DEPLOYED genesis JSON (the chain spec the clients run) to compare with the regeneration, registry code and every storage word")
	flag.Parse()
	if *profile == "" || *root == "" || *shard == "" || (*out == "") == (*verify == "") {
		return fmt.Errorf("--profile, --root-genesis and --shard-conf are required, and exactly one of --out and --verify")
	}
	read := func(path string, v any) error {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return json.Unmarshal(b, v)
	}
	var p b1state.Profile
	var tb types.RootTrustBaseV1
	var conf types.PartitionDescriptionRecord
	if err := readProfile(*profile, &p); err != nil {
		return err
	}
	if err := read(*root, &tb); err != nil {
		return err
	}
	if err := read(*shard, &conf); err != nil {
		return err
	}
	suppliedCommitment, hasCommitment := "", false
	if *verify != "" {
		// the deployed chain's configuration is the FULL one (it carries the genesis commitment); the regeneration starts from its base, and the
		// commitment it carried is compared with the regenerated one below
		suppliedCommitment, hasCommitment = conf.PartitionParams[registrygenesis.GenesisParam]
		delete(conf.PartitionParams, registrygenesis.GenesisParam)
	}
	h, err := q3format.NewHistory(&tb)
	if err != nil {
		return err
	}
	g, err := registrygenesis.GenerateB1(&conf, p, h, registrygenesis.EVMParams{GasLimit: p.MaxGas, BaseFee: registrygenesis.DefaultEVMParams.BaseFee})
	if err != nil {
		return err
	}
	full, err := g.FullConfig()
	if err != nil {
		return err
	}
	if *verify != "" {
		// the commitment hashes the derived record (ids, addresses, code hash, base configuration hash, root genesis id and the B1 profile hash), not the
		// genesis bytes (a base configuration without the parameter has nothing to compare): a profile that differs from the one the chain committed to in fields that change neither would otherwise pass
		if want := hex.EncodeToString(g.GenesisCommitment().Bytes()); hasCommitment && suppliedCommitment != want {
			return fmt.Errorf("%w: supplied %q, regenerated %s", ErrCommitment, suppliedCommitment, want)
		}
		return verifyFile(g, full, p, h, *verify)
	}
	origin, err := registrygenesis.B1Origin(full, p, h, g.GenesisJSON(), nil, registrygenesis.GenesisJSONLimits{})
	if err != nil {
		return err
	}
	words := map[string]string{}
	for k, v := range g.B1Words() {
		words[k.Hex()] = v.Hex()
	}
	hash, _ := p.Hash()
	manifest := map[string]any{"active": false, "contractsSource": b1registry.Source, "codeHash": p.RuntimeHash, "compilerHash": p.CompilerHash, "profileHash": hash, "genesisCommitment": g.GenesisCommitment().Hex(), "executionGenesisHash": g.EVMGenesisHash().Hex(), "executionGenesisStateRoot": g.StateRoot().Hex(), "originIdentity": origin.Identity().Hex(), "storageWords": words}
	fullJSON, err := json.MarshalIndent(full, "", "  ")
	if err != nil {
		return err
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.Mkdir(*out, 0755); err != nil {
		return err
	}
	for name, raw := range map[string][]byte{"genesis.json": g.GenesisJSON(), "shard-conf.json": fullJSON, "manifest.json": manifestJSON} {
		if err := os.WriteFile(filepath.Join(*out, name), append(raw, '\n'), 0644); err != nil {
			return err
		}
	}
	return nil
}

// verifyFile is --verify: the independent comparison of the deployed registry account with the regeneration, then the node's own validation of the
// whole finalized genesis against the authenticated root genesis and the profile (registrygenesis.B1Origin), both of which must pass.
func verifyFile(g *registrygenesis.Genesis, full *types.PartitionDescriptionRecord, p b1state.Profile, h *q3format.History, path string) error {
	deployed, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path
	if err != nil {
		return err
	}
	words, err := verifyDeployed(g, p.RuntimeHash, deployed)
	if err != nil {
		return err
	}
	if _, err := registrygenesis.B1Origin(full, p, h, deployed, nil, registrygenesis.DefaultGenesisJSONLimits()); err != nil {
		return fmt.Errorf("b1genesis verify: the deployed genesis does not validate against the root genesis and the profile: %w", err)
	}
	code, _ := b1registry.Runtime()
	fmt.Printf("b1genesis verify: the deployed registry account matches the regeneration (code %d bytes keccak %s, %d storage words, none extra or missing); the whole genesis validates as the B1 origin\n",
		len(code), crypto.Keccak256Hash(code).Hex(), words)
	return nil
}

// readProfile reads a profile in either JSON form: b1state.Profile's own (hashes as arrays of numbers), or the file `ubft engine-api b1-profile`
// writes (0x-prefixed hex hashes and addresses, the recorded election measurement and caps beside the fields).
func readProfile(path string, p *b1state.Profile) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if json.Unmarshal(b, p) == nil {
		return nil
	}
	var f struct {
		Network             uint16          `json:"network"`
		RootGenesisID       common.Hash     `json:"rootGenesisId"`
		ExecutionChainID    uint64          `json:"executionChainId"`
		RuntimeHash         common.Hash     `json:"runtimeHash"`
		CompilerHash        common.Hash     `json:"compilerHash"`
		WCert               uint64          `json:"wCert"`
		DeltaEV             uint64          `json:"deltaEv"`
		DeltaHold           uint64          `json:"deltaHold"`
		SystemGas           uint64          `json:"systemGas"`
		ForcedGas           uint64          `json:"forcedGas"`
		MaxGas              uint64          `json:"maxGas"`
		OrdinaryCapacity    uint64          `json:"ordinaryCapacity"`
		RestGas             uint64          `json:"restGas"`
		CompanionBytes      uint64          `json:"companionBytes"`
		OtherCompanionBytes uint64          `json:"otherCompanionBytes"`
		GenesisUCTime       uint64          `json:"genesisUcTime"`
		RecordsCustody      common.Address  `json:"recordsCustody"`
		HRecords            uint32          `json:"hRecords"`
		HookRecordGas       uint64          `json:"hookRecordGas"`
		ElectionContract    common.Address  `json:"electionContract"`
		ElectGas            uint64          `json:"electGas"`
		ElectMeasurement    json.RawMessage `json:"electMeasurement"`
		ElectCaps           json.RawMessage `json:"electCaps"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return fmt.Errorf("the profile %s is in neither JSON form: %w", path, err)
	}
	*p = b1state.Profile{Network: f.Network, RootGenesisID: f.RootGenesisID, ExecutionChainID: f.ExecutionChainID,
		RuntimeHash: f.RuntimeHash, CompilerHash: f.CompilerHash, WCert: f.WCert, DeltaEV: f.DeltaEV, DeltaHold: f.DeltaHold,
		SystemGas: f.SystemGas, ForcedGas: f.ForcedGas, MaxGas: f.MaxGas, OrdinaryCapacity: f.OrdinaryCapacity, RestGas: f.RestGas,
		CompanionBytes: f.CompanionBytes, OtherCompanionBytes: f.OtherCompanionBytes, GenesisUCTime: f.GenesisUCTime,
		RecordsCustody: f.RecordsCustody, HRecords: f.HRecords, HookRecordGas: f.HookRecordGas,
		ElectionContract: f.ElectionContract, ElectGas: f.ElectGas}
	return nil
}
