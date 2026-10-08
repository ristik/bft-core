package cmd

// B1 activation of a paired deployment (docs/design B1 PR4, DN-B): the single fresh-genesis profile that enables the B1 registry layout,
// the pair-side Update admission and the ureth bindings. One profile file is the source of all three: `ubft engine-api b1-profile` derives
// it from the root trust base and the shard configuration, `engine-api genesis --b1-profile` allocates the registry from it, and
// `shard-node run --b1-profile` admits Updates under it. Nothing here is a second source of authority: the profile is checked against the
// trust base's own history and against the registry words the paired client proves.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-core/b1paired"
	"github.com/unicitynetwork/bft-core/b1registry"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/registrywitness"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier"
	"github.com/unicitynetwork/bft-go-base/types"
)

// b1RegistryLayout is the layout selector of a B1 deployment: the one fresh-genesis registry (registryproof.FreshB1).
const b1RegistryLayout = registryproof.FreshB1

var (
	// ErrB1Profile is returned for a profile file that does not describe this deployment's trust base, shard configuration or pinned registry.
	ErrB1Profile = errors.New("b1 profile does not describe this deployment")
	// ErrB1Proof is returned when the paired client's proof response is not the one asked for.
	ErrB1Proof = errors.New("b1 registry proof response does not match the request")
)

// b1ProfileFile is the JSON form of b1state.Profile: hashes are 0x-prefixed hex, never arrays of numbers.
type b1ProfileFile struct {
	Network             uint16      `json:"network"`
	RootGenesisID       common.Hash `json:"rootGenesisId"`
	ExecutionChainID    uint64      `json:"executionChainId"`
	RuntimeHash         common.Hash `json:"runtimeHash"`
	CompilerHash        common.Hash `json:"compilerHash"`
	WCert               uint64      `json:"wCert"`
	DeltaEV             uint64      `json:"deltaEv"`
	DeltaHold           uint64      `json:"deltaHold"`
	SystemGas           uint64      `json:"systemGas"`
	ForcedGas           uint64      `json:"forcedGas"`
	MaxGas              uint64      `json:"maxGas"`
	OrdinaryCapacity    uint64      `json:"ordinaryCapacity"`
	RestGas             uint64      `json:"restGas"`
	CompanionBytes      uint64      `json:"companionBytes"`
	OtherCompanionBytes uint64      `json:"otherCompanionBytes"`
	GenesisUCTime       uint64      `json:"genesisUcTime"`
}

func (f b1ProfileFile) profile() b1state.Profile {
	return b1state.Profile{
		Network: f.Network, RootGenesisID: [32]byte(f.RootGenesisID), ExecutionChainID: f.ExecutionChainID,
		RuntimeHash: [32]byte(f.RuntimeHash), CompilerHash: [32]byte(f.CompilerHash),
		WCert: f.WCert, DeltaEV: f.DeltaEV, DeltaHold: f.DeltaHold,
		SystemGas: f.SystemGas, ForcedGas: f.ForcedGas, MaxGas: f.MaxGas, OrdinaryCapacity: f.OrdinaryCapacity,
		RestGas: f.RestGas, CompanionBytes: f.CompanionBytes, OtherCompanionBytes: f.OtherCompanionBytes, GenesisUCTime: f.GenesisUCTime,
	}
}

func b1ProfileFileOf(p b1state.Profile) b1ProfileFile {
	return b1ProfileFile{
		Network: p.Network, RootGenesisID: common.Hash(p.RootGenesisID), ExecutionChainID: p.ExecutionChainID,
		RuntimeHash: common.Hash(p.RuntimeHash), CompilerHash: common.Hash(p.CompilerHash),
		WCert: p.WCert, DeltaEV: p.DeltaEV, DeltaHold: p.DeltaHold,
		SystemGas: p.SystemGas, ForcedGas: p.ForcedGas, MaxGas: p.MaxGas, OrdinaryCapacity: p.OrdinaryCapacity,
		RestGas: p.RestGas, CompanionBytes: p.CompanionBytes, OtherCompanionBytes: p.OtherCompanionBytes, GenesisUCTime: p.GenesisUCTime,
	}
}

// readB1Profile reads a profile file strictly (unknown fields are refused) and validates it against the pinned registry.
func readB1Profile(path string) (b1state.Profile, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied config path, same trust level as --shard-conf
	if err != nil {
		return b1state.Profile{}, fmt.Errorf("reading the b1 profile %q: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f b1ProfileFile
	if err := dec.Decode(&f); err != nil {
		return b1state.Profile{}, fmt.Errorf("decoding the b1 profile %q: %w", path, err)
	}
	if dec.More() {
		return b1state.Profile{}, fmt.Errorf("decoding the b1 profile %q: trailing data", path)
	}
	p := f.profile()
	if err := b1registry.ValidateProfile(p); err != nil {
		return b1state.Profile{}, fmt.Errorf("%w: %v", ErrB1Profile, err)
	}
	return p, nil
}

// bindB1Profile checks that the profile is this deployment's: the root history, network and chain it names are the trust base's and the
// shard configuration's. It returns the verified history the registry genesis and the Update admission are derived from.
func bindB1Profile(p b1state.Profile, tb *types.RootTrustBaseV1, conf *types.PartitionDescriptionRecord) (*q3format.History, error) {
	h, err := q3format.NewHistory(tb)
	if err != nil {
		return nil, fmt.Errorf("%w: the root trust base has no verifiable history: %v", ErrB1Profile, err)
	}
	if h.Genesis() != p.RootGenesisID || h.Network() != uint64(p.Network) || uint64(conf.NetworkID) != uint64(p.Network) {
		return nil, fmt.Errorf("%w: root genesis %x / network %d against the trust base (%x / %d) and the shard configuration's network %d",
			ErrB1Profile, p.RootGenesisID, p.Network, h.Genesis(), h.Network(), conf.NetworkID)
	}
	chainID, ok := zkverifier.ParseChainIDFromParams(conf.PartitionParams)
	if !ok || chainID != p.ExecutionChainID {
		return nil, fmt.Errorf("%w: execution chain %d against the shard configuration's chain_id (%d, present=%v)", ErrB1Profile, p.ExecutionChainID, chainID, ok)
	}
	return h, nil
}

// deriveB1Profile builds the profile of this deployment with the oracle's frozen envelope for the certificate window.
func deriveB1Profile(tb *types.RootTrustBaseV1, conf *types.PartitionDescriptionRecord, wCert, ordinaryCapacity, genesisUCTime uint64) (b1state.Profile, error) {
	h, err := q3format.NewHistory(tb)
	if err != nil {
		return b1state.Profile{}, fmt.Errorf("the root trust base has no verifiable history: %w", err)
	}
	chainID, ok := zkverifier.ParseChainIDFromParams(conf.PartitionParams)
	if !ok {
		return b1state.Profile{}, fmt.Errorf("shard conf has no chain_id partition param")
	}
	p := b1state.Profile{
		Network: uint16(conf.NetworkID), RootGenesisID: h.Genesis(), ExecutionChainID: chainID,
		RuntimeHash: [32]byte(common.HexToHash(b1registry.CodeHashHex)), CompilerHash: b1registry.CompilerHash(),
		WCert: wCert, DeltaEV: wCert + 1, DeltaHold: wCert + 2,
		RestGas: b1registry.MinRestGas(wCert), CompanionBytes: 1 << 20, OtherCompanionBytes: 65536, OrdinaryCapacity: ordinaryCapacity, GenesisUCTime: genesisUCTime,
	}
	if p.SystemGas, err = p.RequiredSystemGas(); err != nil {
		return b1state.Profile{}, err
	}
	p.MaxGas = p.SystemGas + p.OrdinaryCapacity
	if err := b1registry.ValidateProfile(p); err != nil {
		return b1state.Profile{}, err
	}
	return p, nil
}

func engineAPIB1ProfileCmd(baseFlags *baseFlags) *cobra.Command {
	var trustBasePath, out string
	var wCert, capacity, genesisUCTime uint64
	flags := &shardConfFlags{}
	cmd := &cobra.Command{
		Use:   "b1-profile",
		Short: "Derive the B1 execution profile of a deployment from its root trust base and shard configuration",
		Long: `Writes the one profile file the B1 deployment shares: ` + "`engine-api genesis --b1-profile`" + ` allocates the registry from it,
` + "`shard-node run --b1-profile`" + ` admits Updates under it, and the printed ureth flags pin the paired client to it. The root genesis
identity comes from the trust base's own history; the gas envelope is the frozen oracle envelope for the certificate window.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if trustBasePath == "" || out == "" {
				return fmt.Errorf("--trust-base and --out are required")
			}
			confs, err := flags.loadShardConfs(baseFlags)
			if err != nil {
				return fmt.Errorf("loading shard conf: %w", err)
			}
			if len(confs) != 1 {
				return fmt.Errorf("b1-profile requires exactly one --shard-conf, got %d", len(confs))
			}
			tb, err := readTrustBase(trustBasePath)
			if err != nil {
				return err
			}
			p, err := deriveB1Profile(tb, confs[0], wCert, capacity, genesisUCTime)
			if err != nil {
				return err
			}
			enc, err := json.MarshalIndent(b1ProfileFileOf(p), "", "  ")
			if err != nil {
				return err
			}
			if err := os.WriteFile(out, append(enc, '\n'), 0o644); err != nil { // #nosec G306 -- public configuration
				return fmt.Errorf("writing %q: %w", out, err)
			}
			hash, _ := p.Hash()
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "wrote %s\n", out)
			fmt.Fprintf(w, "profile hash:    %s\n", hexutil.Encode(hash[:]))
			fmt.Fprintf(w, "ureth flags:     --unicity.network-id=%d --unicity.root-genesis-id=%s --unicity.chain-id=%d --unicity.profile-hash=%s --unicity.w-cert=%d --unicity.max-gas=%d --unicity.system-gas=%d\n",
				p.Network, hexutil.Encode(p.RootGenesisID[:]), p.ExecutionChainID, hexutil.Encode(hash[:]), p.WCert, p.MaxGas, p.SystemGas)
			return nil
		},
	}
	flags.addShardConfFlags(cmd, false)
	cmd.Flags().StringVar(&trustBasePath, "trust-base", "", "the signed root trust base JSON (required)")
	cmd.Flags().StringVar(&out, "out", "", "output path for the profile JSON (required)")
	cmd.Flags().Uint64Var(&wCert, "w-cert", 1, "certificate window W_cert; the registry keeps W_cert+1 authority intervals")
	cmd.Flags().Uint64Var(&capacity, "ordinary-capacity", 7_000_000, "ordinary transaction gas capacity of a block (the block gas limit is this plus the system reservation)")
	cmd.Flags().Uint64Var(&genesisUCTime, "genesis-uc-time", 1000, "the pinned genesis UC time recorded in the registry (records.ucTime) before any import; a DEV value")
	return cmd
}

// ---- pair-side admission -------------------------------------------------------------------------------------------------------------------

// b1MaxProofKeys bounds one proof request: the six common words plus the widest admitted ring (registryproof.Snapshot.VerifyWords).
const b1MaxProofKeys = 6 + 524*16

// b1ProofFetcher returns the untrusted storage-proof source of the pair's Update admission: eth_getProof of the registry for the named
// verified parent, by block hash. The caller verifies every node against the parent's authenticated storage root; this function cannot
// grant authority, only fail to supply it.
func b1ProofFetcher(rpc registrywitness.Caller) func(context.Context, registryproof.Snapshot, []common.Hash) ([][][]byte, error) {
	return func(ctx context.Context, parent registryproof.Snapshot, keys []common.Hash) ([][][]byte, error) {
		if !parent.Valid() || len(keys) == 0 || len(keys) > b1MaxProofKeys {
			return nil, ErrB1Proof
		}
		raw, err := rpc.Call(ctx, "eth_getProof", []any{registryproof.RegistryAddress, keys, map[string]any{"blockHash": parent.ParentHash()}})
		if err != nil {
			return nil, fmt.Errorf("eth_getProof for the registry at %s: %w", parent.ParentHash(), err)
		}
		var res registryproof.GetProofResult
		if err := json.Unmarshal(raw, &res); err != nil {
			return nil, fmt.Errorf("%w: undecodable result: %v", ErrB1Proof, err)
		}
		if res.Address != registryproof.RegistryAddress || len(res.StorageProof) != len(keys) {
			return nil, fmt.Errorf("%w: %d proofs for %d keys at %s", ErrB1Proof, len(res.StorageProof), len(keys), res.Address)
		}
		out := make([][][]byte, len(keys))
		for i, sp := range res.StorageProof {
			if common.HexToHash(sp.Key) != keys[i] {
				return nil, fmt.Errorf("%w: proof %d is for key %s, not %s", ErrB1Proof, i, sp.Key, keys[i])
			}
			out[i] = make([][]byte, len(sp.Proof))
			for j, node := range sp.Proof {
				out[i][j] = []byte(node)
			}
		}
		return out, nil
	}
}

// newB1PairConfig is the pair's Update admission configuration: the profile, the authority of the node's own verified root history, and
// the proof source of its paired client.
func newB1PairConfig(p b1state.Profile, rt *q3active.Runtime, ethURL string, timeout time.Duration) (*b1paired.Config, error) {
	if rt == nil {
		return nil, fmt.Errorf("%w: no verified root history", ErrB1Profile)
	}
	return &b1paired.Config{Profile: p, Authority: rt.B1Authority(), Proofs: b1ProofFetcher(registrywitness.NewHTTPCaller(ethURL, timeout))}, nil
}

// b1IdentitiesFile is the genesis tool's identity document the vault deployment is checked against
// (unicity-pos-contracts script/BridgeGenesisBinding.sol): every hash 0x-prefixed.
type b1IdentitiesFile struct {
	RootGenesisID    string            `json:"rootGenesisId"`
	EVMGenesisHash   string            `json:"evmGenesisHash"`
	ProfileHash      string            `json:"profileHash"`
	ExecutionChainID uint64            `json:"executionChainId"`
	RegistryCodeHash string            `json:"registryCodeHash"`
	RegistryWords    map[string]string `json:"registryWords"`
}

func newB1Identities(p b1state.Profile, evmGenesisHash common.Hash, words map[common.Hash]common.Hash) ([]byte, error) {
	hash, err := p.Hash()
	if err != nil {
		return nil, err
	}
	doc := b1IdentitiesFile{
		RootGenesisID: hexutil.Encode(p.RootGenesisID[:]), EVMGenesisHash: evmGenesisHash.Hex(), ProfileHash: hexutil.Encode(hash[:]),
		ExecutionChainID: p.ExecutionChainID, RegistryCodeHash: hexutil.Encode(p.RuntimeHash[:]), RegistryWords: map[string]string{},
	}
	keys := make([]common.Hash, 0, len(words))
	for k := range words {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })
	for _, k := range keys {
		doc.RegistryWords[k.Hex()] = words[k].Hex()
	}
	enc, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(enc, '\n'), nil
}

// loadB1GenesisOrigin validates the finalized genesis of a B1 deployment against the full shard configuration, the profile and the trust
// base's own history, and returns the origin and the block-0 snapshot the first derivation takes as its parent.
func loadB1GenesisOrigin(full *types.PartitionDescriptionRecord, p b1state.Profile, h *q3format.History, genesisPath, expectedIdentity string) (registrygenesis.GenesisOrigin, registryproof.Snapshot, error) {
	finalized, err := os.ReadFile(genesisPath) // #nosec G304 -- operator-supplied config path, same trust level as --shard-conf
	if err != nil {
		return registrygenesis.GenesisOrigin{}, registryproof.Snapshot{}, fmt.Errorf("reading the finalized genesis %q: %w", genesisPath, err)
	}
	var expected *common.Hash
	if expectedIdentity != "" {
		id, err := parseHash32(expectedIdentity)
		if err != nil {
			return registrygenesis.GenesisOrigin{}, registryproof.Snapshot{}, fmt.Errorf("parsing --expected-origin-identity: %w", err)
		}
		expected = &id
	}
	origin, err := registrygenesis.B1Origin(full, p, h, finalized, expected, registrygenesis.DefaultGenesisJSONLimits())
	if err != nil {
		return registrygenesis.GenesisOrigin{}, registryproof.Snapshot{}, fmt.Errorf("validating the finalized B1 genesis against the full shard configuration: %w", err)
	}
	bootstrap, err := registryproof.Verify(origin.ProofContext(), origin.BlockHash(), origin.Evidence())
	if err != nil {
		return registrygenesis.GenesisOrigin{}, registryproof.Snapshot{}, fmt.Errorf("verifying the configured bootstrap snapshot: %w", err)
	}
	if !bootstrap.Valid() || !bootstrap.Genesis() || bootstrap.Number() != 0 || bootstrap.StateRoot() != origin.StateRoot() {
		return registrygenesis.GenesisOrigin{}, registryproof.Snapshot{}, fmt.Errorf("the configured bootstrap snapshot is not block 0 of the configured genesis origin")
	}
	return origin, bootstrap, nil
}

// loadB1Deployment reads the profile and binds it to the node's own pinned trust base and full shard configuration.
func loadB1Deployment(path string, tb *types.RootTrustBaseV1, conf *types.PartitionDescriptionRecord) (b1state.Profile, *q3format.History, error) {
	p, err := readB1Profile(path)
	if err != nil {
		return b1state.Profile{}, nil, err
	}
	h, err := bindB1Profile(p, tb, conf)
	if err != nil {
		return b1state.Profile{}, nil, err
	}
	return p, h, nil
}

// validateB1RunFlags refuses a --b1-profile that lacks what its checks need, and registry layout 3 without the profile that defines it.
func validateB1RunFlags(flags *shardNodeRunFlags) error {
	if flags.B1Profile != "" {
		if flags.RegistryLayout != 1 && flags.RegistryLayout != b1RegistryLayout {
			return fmt.Errorf("--b1-profile selects registry layout %d; --registry-layout %d contradicts it", b1RegistryLayout, flags.RegistryLayout)
		}
		flags.RegistryLayout = b1RegistryLayout
		if flags.Executor != "engine-api" || flags.GenesisFile == "" || flags.ExecutionJournal == "" || !flags.TrustHistoryProfile2 {
			return errors.New("--b1-profile requires --executor=engine-api, --genesis, --execution-journal and --trust-history-profile-2")
		}
		return nil
	}
	if flags.RegistryLayout == b1RegistryLayout {
		return errors.New("registry layout 3 is the fresh-B1 layout and requires --b1-profile")
	}
	return nil
}
