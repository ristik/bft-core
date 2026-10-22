// Command dnb-tool derives the DN-B lane's bridge deployment inputs from a running (or just generated) B1 devnet:
//
//	dnb-tool deployment --identities genesis-identities.json --b1-profile b1-profile.json --agg-conf shard-conf-7_0.json --out deployment.json
//
// The deployment document is what unicity-pos-contracts script/BridgeDeploy.s.sol reads beside the genesis identity document.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-core/bridgeprofile"
	"github.com/unicitynetwork/bft-core/gettrustbase"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/utb"
	"github.com/unicitynetwork/bft-go-base/types"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dnb-tool deployment ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "deployment":
		err = deployment(os.Args[2:])
	case "trust-bundle":
		err = trustBundle(os.Args[2:])
	case "b1check":
		err = b1check(os.Args[2:])
	case "pdr":
		err = pdr(os.Args[2:])
	case "lockproof":
		err = lockProof(os.Args[2:])
	case "lockproof-serve":
		err = lockProofServe(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "dnb-tool:", err)
		os.Exit(1)
	}
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
	pol := bridgeprofile.NewPolicy(partition)
	semantic := sha256.Sum256(bridgeprofile.SemanticProfileJSON())
	doc := map[string]any{
		"network":             *network,
		"rootGenesis":         id.RootGenesisID,
		"executionGenesis":    id.EVMGenesisHash,
		"evmPartition":        *evmPartition,
		"evmShard":            hexutil.Encode(bridgeprofile.EmptyPrefixShard),
		"semanticProfileHash": hexutil.Encode(semantic[:]),
		"b1ProfileHash":       id.ProfileHash,
		"policyBody":          hexutil.Encode(pol.Bytes()),
	}
	enc, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(*out, append(enc, '\n'), 0o644) // #nosec G306 -- public configuration
}

// trustBundle writes the release bundle of the deployment's trust-base history at its genesis (the entry a root is started with,
// ubft trust-base utb-genesis) and its genesis EntryID: the trust input of the bridge profile (protocol 5) and its pin. The bundle
// holds the genesis only: a lock certified after a root epoch change needs the later entries (the plug-in reports ErrNoEntryForEpoch,
// retryable), so past an epoch change give the plug-in the exported history (ubft trust-base utb-export) instead; its pin is unchanged.
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
	bundle, err := bridgeprofile.TrustBundle(genesis)
	if err != nil {
		return err
	}
	id, err := genesis.EntryID()
	if err != nil {
		return err
	}
	if _, err := bridgeprofile.LoadTrustInput(bundle, id); err != nil {
		return fmt.Errorf("the bundle is not a loadable trust input: %w", err)
	}
	if err := os.WriteFile(*out, bundle, 0o644); err != nil { // #nosec G306 -- public configuration
		return err
	}
	return os.WriteFile(*outPin, []byte(hex.EncodeToString(id[:])+"\n"), 0o644) // #nosec G306 -- public configuration
}

// lockProof assembles the LockProof (bridgeprofile.LockProof) of vault.lockDigest[nonce] at a certified EVM block: the archived resulting
// certificate and header of that block, the full shard configuration the certificate commits to, and the account and storage proof nodes the
// paired client serves for the block.
func lockProof(args []string) error {
	fs := flag.NewFlagSet("lockproof", flag.ContinueOnError)
	archiveDir := fs.String("archive", "", "a validator's immutable archive v2 directory")
	blockHashText := fs.String("block-hash", "", "the certified block that holds the lock")
	ethURL := fs.String("eth-url", "", "the paired client's plain endpoint")
	vaultText := fs.String("vault", "", "vault address")
	nonce := fs.Uint64("nonce", 0, "lock nonce")
	fullConf := fs.String("full-shard-conf", "", "the EVM shard's full configuration (as registered with the root chain)")
	trustBundlePath := fs.String("trust-bundle", "", "the trust-base release bundle (trust-bundle)")
	cfgHash := fs.String("cfg", "", "the vault's CFG")
	out := fs.String("out", "", "output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	src, err := newLockProofSource(context.Background(), *archiveDir, *ethURL, *vaultText, *fullConf, *trustBundlePath, *cfgHash)
	if err != nil {
		return err
	}
	lp, err := src.build(context.Background(), common.HexToHash(*blockHashText), *nonce)
	if err != nil {
		return err
	}
	return os.WriteFile(*out, lp, 0o644) // #nosec G306 -- public proof
}

// lockProofSource holds what every lock proof of one deployment shares (the shard configuration, the trust-base ID, the vault and its CFG); build reads
// one block's certificate and header from the archive and the lock's storage proof from the paired client. Between calls it keeps only the archive
// locator's Contexts (a locator, never evidence).
type lockProofSource struct {
	archive     *archiveLocator
	ethURL      string
	vault       common.Address
	cfg         [32]byte
	pdr         []byte
	pdrHash     [32]byte
	trustBaseID [32]byte
}

// errNotFound marks a request for a block the archive does not (yet) hold or a nonce with no lock at that block.
var errNotFound = errors.New("not found")

// archiveRescanEvery bounds how often a lookup that misses rereads the archive directory for Contexts not yet seen.
const archiveRescanEvery = 10 * time.Second

func newLockProofSource(ctx context.Context, archiveDir, ethURL, vaultText, fullConf, trustBundlePath, cfgHash string) (*lockProofSource, error) {
	rawConf, err := os.ReadFile(fullConf)
	if err != nil {
		return nil, err
	}
	var conf types.PartitionDescriptionRecord
	if err := json.Unmarshal(rawConf, &conf); err != nil {
		return nil, err
	}
	pdr, err := types.Cbor.Marshal(&conf)
	if err != nil {
		return nil, err
	}
	bundle, err := os.ReadFile(trustBundlePath)
	if err != nil {
		return nil, err
	}
	// trustBaseId is the genesis EntryID of the history the bundle carries
	decoded, err := gettrustbase.DecodeBundle(bundle, gettrustbase.BundleLimits{MaxBytes: 1 << 20, MaxEntries: 1 << 16})
	if err != nil {
		return nil, err
	}
	tbID, err := decoded.Entries[0].EntryID()
	if err != nil {
		return nil, err
	}
	store, err := archive.Open(archiveDir)
	if err != nil {
		return nil, err
	}
	locator, err := newArchiveLocator(ctx, archiveDir, store, archiveRescanEvery)
	if err != nil {
		return nil, err
	}
	s := &lockProofSource{archive: locator, ethURL: ethURL, vault: common.HexToAddress(vaultText), pdr: pdr, pdrHash: sha256.Sum256(pdr), trustBaseID: tbID}
	copy(s.cfg[:], common.HexToHash(cfgHash).Bytes())
	return s, nil
}

func (s *lockProofSource) build(ctx context.Context, blockHash common.Hash, nonce uint64) ([]byte, error) {
	_, rec, err := s.archive.locate(ctx, blockHash)
	if errors.Is(err, errNotFound) {
		return nil, fmt.Errorf("%w: the archive holds no receipt-complete record of block %s", errNotFound, blockHash)
	}
	if err != nil {
		return nil, err
	}
	var hdr gethtypes.Header
	if err := rlp.DecodeBytes(rec.Header, &hdr); err != nil || hdr.Hash() != blockHash {
		return nil, fmt.Errorf("archived header is not block %s", blockHash)
	}
	var uc types.UnicityCertificate
	if err := types.Cbor.Unmarshal(rec.ResultingUC, &uc); err != nil {
		return nil, err
	}
	if !bytes.Equal(s.pdrHash[:], uc.ShardConfHash) {
		return nil, fmt.Errorf("the full shard configuration is not the configuration the block's certificate commits to")
	}
	slot := crypto.Keccak256Hash(common.LeftPadBytes(new(big.Int).SetUint64(nonce).Bytes(), 32), common.LeftPadBytes([]byte{5}, 32))
	raw, err := rpcCall(ctx, s.ethURL, "eth_getProof", []any{s.vault, []common.Hash{slot}, map[string]any{"blockHash": blockHash}})
	var refused *rpcError
	if errors.As(err, &refused) {
		// the client answered and refused: typically a block older than its proof window (--rpc.eth-proof-window)
		return nil, fmt.Errorf("%w: the paired client serves no eth_getProof at block %s (%w)", errNotFound, blockHash, err)
	}
	if err != nil {
		return nil, err
	}
	var proof struct {
		Address      common.Address  `json:"address"`
		AccountProof []hexutil.Bytes `json:"accountProof"`
		StorageProof []struct {
			Value *hexutil.Big    `json:"value"`
			Proof []hexutil.Bytes `json:"proof"`
		} `json:"storageProof"`
	}
	if err := json.Unmarshal(raw, &proof); err != nil {
		return nil, err
	}
	if proof.Address != s.vault || len(proof.StorageProof) != 1 {
		return nil, fmt.Errorf("unexpected eth_getProof answer")
	}
	if v := proof.StorageProof[0].Value; v == nil || v.ToInt().Sign() == 0 {
		return nil, fmt.Errorf("%w: no lock with nonce %d at block %s", errNotFound, nonce, blockHash)
	}
	lp := bridgeprofile.LockProof{TrustBaseID: s.trustBaseID, PDR: s.pdr, UC: bytes.Clone(rec.ResultingUC), Header: bytes.Clone(rec.Header), Cfg: s.cfg}
	for _, n := range proof.AccountProof {
		lp.AccountNodes = append(lp.AccountNodes, []byte(n))
	}
	for _, n := range proof.StorageProof[0].Proof {
		lp.StorageNodes = append(lp.StorageNodes, []byte(n))
	}
	return lp.Bytes(), nil
}

func rpcCall(ctx context.Context, url, method string, params []any) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct{ Message string }
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Error != nil {
		return nil, &rpcError{method: method, message: out.Error.Message}
	}
	return out.Result, nil
}

// rpcError is a JSON-RPC error answer (the client was reached and refused), as distinct from a transport failure.
type rpcError struct{ method, message string }

func (e *rpcError) Error() string { return e.method + ": " + e.message }

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
