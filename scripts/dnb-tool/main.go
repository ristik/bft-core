// Command dnb-tool holds the operator tools of the bridge deployment that stay with native bridge v2 (docs/design/native-bridge-v2.md):
//
//	dnb-tool trust-bundle --trust-base trust-base.json --out trust-base.bundle.cbor --out-pin genesis-entry-id.hex
//	dnb-tool b1check --request req.bin --trust-base trust-base.json --profile b1-profile.json --clock N
//	dnb-tool deployment --identities genesis-identities.json --agg-conf shard-conf-7_0.json --out deployment.json
//	dnb-tool pdr --full-shard-conf shard-conf.json --out pdr.cbor
//
// deployment and pdr serve only the combined CI lane's protocol 6/7 bridge deploy until that lane is migrated; the lock-proof
// commands (lockproof, lockproof-serve) were removed with that bridge (bft-core#1106).
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/utb"
	"github.com/unicitynetwork/bft-go-base/types"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dnb-tool deployment|trust-bundle|pdr|b1check ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "deployment":
		err = deployment(os.Args[2:])
	case "trust-bundle":
		err = trustBundle(os.Args[2:])
	case "pdr":
		err = pdr(os.Args[2:])
	case "b1check":
		err = b1check(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "dnb-tool:", err)
		os.Exit(1)
	}
}

// The protocol 6/7 deployment document of the combined CI lane (scripts/lib/agg-lib.sh, scripts/reth-paired-devnet.sh), which still
// deploys that bridge from its pinned contracts. bridgeprofile was removed (bft-core#1106); the three values it supplied are inlined
// here byte for byte (TestDeploymentBytesArePinned). Remove deployment and pdr when the lane leaves the protocol 6/7 bridge.

// emptyPrefixShard is the one-byte native encoding of the empty shard prefix (depth 0): 0x80, not the empty byte string.
var emptyPrefixShard = []byte{0x80}

// semanticProfileHash is the SHA-256 of the protocol 7 semantic profile artifact (bridgeprofile/testdata/semantic-profile.json,
// native-bridge-plugins protocol/vectors/config/semantic-profile.json before bft-core#1106).
const semanticProfileHash = "0xbdca358b6e1a64fa9161b4947020090876573d5f0b0f9786532de3d5d384324a"

// policyBody is the partition policy body C(b("UNICITY_BR_AGG_PARTITION"), 2, partition): canonical CBOR, a 3-array of a byte
// string and two unsigned integers.
func policyBody(partition uint32) []byte {
	const domain = "UNICITY_BR_AGG_PARTITION"
	out := append([]byte{0x83}, cborHead(2, uint64(len(domain)))...)
	out = append(out, domain...)
	out = append(out, cborHead(0, 2)...)
	return append(out, cborHead(0, uint64(partition))...)
}

// cborHead is the shortest CBOR head of major type major and argument n.
func cborHead(major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return []byte{m | byte(n)}
	case n <= 0xff:
		return []byte{m | 24, byte(n)}
	case n <= 0xffff:
		return []byte{m | 25, byte(n >> 8), byte(n)}
	case n <= 0xffffffff:
		return []byte{m | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return []byte{m | 27, byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32), byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

type identities struct {
	RootGenesisID    string `json:"rootGenesisId"`
	EVMGenesisHash   string `json:"evmGenesisHash"`
	ProfileHash      string `json:"profileHash"`
	ExecutionChainID uint64 `json:"executionChainId"`
}

func deployment(args []string) error {
	fs := flag.NewFlagSet("deployment", flag.ContinueOnError)
	idPath := fs.String("identities", "", "genesis identity document")
	aggConfPath := fs.String("agg-conf", "", "the aggregator shard configurations as registered with the root chain: one file, or a comma-separated list in increasing shard-id order")
	evmPartition := fs.Uint64("evm-partition", 8, "EVM partition id")
	network := fs.Uint64("network", 3, "network id")
	out := fs.String("out", "", "output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *idPath == "" || *aggConfPath == "" || *out == "" {
		return fmt.Errorf("--identities, --agg-conf and --out are required")
	}
	raw, err := os.ReadFile(*idPath)
	if err != nil {
		return err
	}
	var id identities
	if err := json.Unmarshal(raw, &id); err != nil {
		return err
	}
	// The registered shard configurations of the aggregation partition: protocol 4's policy names only the partition (the UCs
	// authenticate each shard's configuration), so they serve to read and cross-check that partition.
	var partition uint32
	for i, path := range strings.Split(*aggConfPath, ",") {
		rawConf, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var conf types.PartitionDescriptionRecord
		if err := json.Unmarshal(rawConf, &conf); err != nil {
			return fmt.Errorf("decoding the aggregator shard configuration %s: %w", path, err)
		}
		if i == 0 {
			partition = uint32(conf.PartitionID)
		} else if partition != uint32(conf.PartitionID) {
			return fmt.Errorf("shard configuration %s belongs to partition %d, not %d", path, conf.PartitionID, partition)
		}
	}
	doc := map[string]any{
		"network":             *network,
		"rootGenesis":         id.RootGenesisID,
		"executionGenesis":    id.EVMGenesisHash,
		"evmPartition":        *evmPartition,
		"evmShard":            hexutil.Encode(emptyPrefixShard),
		"semanticProfileHash": semanticProfileHash,
		"b1ProfileHash":       id.ProfileHash,
		"policyBody":          hexutil.Encode(policyBody(partition)),
	}
	enc, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(*out, append(enc, '\n'), 0o644) // #nosec G306 -- public configuration
}

// trustBundle writes the release bundle of the deployment's trust-base history at its genesis (the entry a root is started with,
// ubft trust-base utb-genesis) and its genesis EntryID: the trust input of native bridge v2 (Γ.rootGenesis32 and the wallets' trust input,
// deploy/testnet/bridge/nb2/deploy_nb2.py) and its pin. The bundle holds the genesis only: past a root epoch change give the wallet the
// exported history (ubft trust-base utb-export) instead; its pin is unchanged. The bundle is checked to install under its pin with the
// installation budget of a release bundle (trustBundleLimits, as nb2ref.LoadTrustInput).
func trustBundle(args []string) error {
	fs := flag.NewFlagSet("trust-bundle", flag.ContinueOnError)
	in := fs.String("trust-base", "", "the genesis (epoch 1) trust base JSON")
	out := fs.String("out", "", "where to write the release bundle")
	outPin := fs.String("out-pin", "", "where to write the genesis EntryID (hex)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	var tb types.RootTrustBaseV1
	if err := json.Unmarshal(raw, &tb); err != nil {
		return err
	}
	genesis, err := utb.BuildUnsigned(nil, utb.FromProjection(&tb))
	if err != nil {
		return err
	}
	enc, err := types.Cbor.Marshal(genesis)
	if err != nil {
		return err
	}
	bundle, err := types.EncodeTrustBaseBundle([][]byte{enc})
	if err != nil {
		return err
	}
	id, err := genesis.EntryID()
	if err != nil {
		return err
	}
	if err := checkTrustBundle(bundle, id); err != nil {
		return fmt.Errorf("the bundle is not a loadable trust input: %w", err)
	}
	if err := os.WriteFile(*out, bundle, 0o644); err != nil { // #nosec G306 -- public configuration
		return err
	}
	return os.WriteFile(*outPin, []byte(hex.EncodeToString(id[:])+"\n"), 0o644) // #nosec G306 -- public configuration
}

// trustBundleLimits is the installation budget of a release bundle (nb2ref's trustBundleLimits).
var trustBundleLimits = types.TrustBaseLimits{MaxBytes: 1 << 20, MaxEntries: 1 << 16}

// checkTrustBundle is the installation check of nb2ref.LoadTrustInput: the bundle decodes within the budget, its genesis is the pin, and the
// history verifies from it.
func checkTrustBundle(bundle []byte, pin [32]byte) error {
	b, err := types.DecodeTrustBaseBundle(bundle, trustBundleLimits)
	if err != nil {
		return err
	}
	if id, err := b.Entries[0].EntryID(); err != nil || id != pin {
		return fmt.Errorf("the bundle's genesis EntryID is not the pin")
	}
	return types.VerifyTrustBaseBundle(b, pin)
}

// pdr writes the canonical CBOR of the EVM shard's full configuration: the artifact a lock proof carries and the manifest pins.
func pdr(args []string) error {
	fs := flag.NewFlagSet("pdr", flag.ContinueOnError)
	in := fs.String("full-shard-conf", "", "full shard configuration JSON")
	out := fs.String("out", "", "output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	var conf types.PartitionDescriptionRecord
	if err := json.Unmarshal(raw, &conf); err != nil {
		return err
	}
	enc, err := types.Cbor.Marshal(&conf)
	if err != nil {
		return err
	}
	return os.WriteFile(*out, enc, 0o644) // #nosec G306 -- public configuration
}

// b1check evaluates a CERT_BATCH_V2 request with the Go reference verifier (b1ref) against a format-2 registry holding the deployment's genesis
// authority, at a given registry clock: the first place to look when the native call answers false. A v1 request (same claim layout) is read
// as v2.
func b1check(args []string) error {
	fs := flag.NewFlagSet("b1check", flag.ContinueOnError)
	req := fs.String("request", "", "CERT_BATCH_V2 (or v1) request bytes")
	tbPath := fs.String("trust-base", "", "root trust base")
	profPath := fs.String("profile", "", "b1 profile JSON (hex form)")
	clock := fs.Uint64("clock", 0, "registry clock.rootRound")
	if err := fs.Parse(args); err != nil {
		return err
	}
	in, err := os.ReadFile(*req)
	if err != nil {
		return err
	}
	rawTB, err := os.ReadFile(*tbPath)
	if err != nil {
		return err
	}
	var tb types.RootTrustBaseV1
	if err := json.Unmarshal(rawTB, &tb); err != nil {
		return err
	}
	rawProf, err := os.ReadFile(*profPath)
	if err != nil {
		return err
	}
	var pf struct {
		Network uint16
	}
	if err := json.Unmarshal(rawProf, &pf); err != nil {
		return err
	}
	h, err := q3format.NewHistory(&tb)
	if err != nil {
		return err
	}
	first, err := h.ForEpoch(1)
	if err != nil {
		return err
	}
	entries, err := h.B1Entries(first.Start())
	if err != nil {
		return err
	}
	last := entries[len(entries)-1].Epoch
	model := b1ref.Model{GenesisCommitment: [32]byte{1}, ProfileHash: [32]byte{1}, Phase: 2, Network: pf.Network, GenesisEpoch: entries[0].Epoch,
		ImportedTip: last, OriginReady: true, Origin: last, RootRound: *clock, Epochs: entries}
	if len(in) > 0 && in[0] == 1 {
		in = append([]byte{2}, in[1:]...)
	}
	v, err := b1ref.Cert(in, model.Words(), b1ref.Pins{GenesisCommitment: model.GenesisCommitment, ProfileHash: model.ProfileHash})
	fmt.Printf("valid=%v why=%v err=%v gas=%d (epoch entry: start=%d members=%d)\n", v.Valid, v.Why, err, v.Gas, entries[0].Start, len(entries[0].Members))
	return nil
}
