// b1genesis exports an inactive fresh B1 allocation and complete storage manifest.
// It never contacts a node or deploys anything.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

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
	profile := flag.String("profile", "", "complete b1state.Profile JSON (hashes are 32-byte arrays)")
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
	if err := read(*profile, &p); err != nil {
		return err
	}
	if err := read(*root, &tb); err != nil {
		return err
	}
	if err := read(*shard, &conf); err != nil {
		return err
	}
	if *verify != "" {
		// the deployed chain's configuration is the FULL one (it carries the genesis commitment); the regeneration starts from its base
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
