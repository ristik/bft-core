// b1genesis exports an inactive fresh B1 allocation and complete storage manifest.
// It never contacts a node or deploys anything.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

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
	flag.Parse()
	if *profile == "" || *root == "" || *shard == "" || *out == "" {
		return fmt.Errorf("--profile, --root-genesis, --shard-conf and --out are required")
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
