// Command dnb-tool derives the DN-B lane's bridge deployment inputs from a running (or just generated) B1 devnet:
//
//	dnb-tool deployment --identities genesis-identities.json --b1-profile b1-profile.json --agg-conf shard-conf-9_0.json --out deployment.json
//
// The deployment document is what unicity-pos-contracts script/BridgeDeploy.s.sol reads beside the genesis identity document.
package main

import (
	"bytes"
	"context"
	stdcrypto "crypto"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-core/bridgeprofile"
	"github.com/unicitynetwork/bft-core/q3format"
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
	case "trust-doc":
		err = trustDoc(os.Args[2:])
	case "b1check":
		err = b1check(os.Args[2:])
	case "pdr":
		err = pdr(os.Args[2:])
	case "lockproof":
		err = lockProof(os.Args[2:])
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
	aggConfPath := fs.String("agg-conf", "", "the aggregator shard's configuration as registered with the root chain")
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
	rawConf, err := os.ReadFile(*aggConfPath)
	if err != nil {
		return err
	}
	var conf types.PartitionDescriptionRecord
	if err := json.Unmarshal(rawConf, &conf); err != nil {
		return fmt.Errorf("decoding the aggregator shard configuration: %w", err)
	}
	h, err := conf.Hash(stdcrypto.SHA256)
	if err != nil {
		return err
	}
	pol := bridgeprofile.Policy{Partition: uint32(conf.PartitionID)}
	copy(pol.ShardConf[:], h)
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

// trustDoc renders the SDK RootTrustBase JSON document of the signed root trust base: the one pinned trust input of the fixed-base profile.
func trustDoc(args []string) error {
	fs := flag.NewFlagSet("trust-doc", flag.ContinueOnError)
	in := fs.String("trust-base", "", "signed root trust base JSON")
	out := fs.String("out", "", "output path")
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
	doc, err := bridgeprofile.RenderTrustBaseJSON(&tb)
	if err != nil {
		return err
	}
	if _, err := bridgeprofile.LoadTrustInput(doc); err != nil {
		return fmt.Errorf("the rendered document is not a loadable trust input: %w", err)
	}
	return os.WriteFile(*out, doc, 0o644) // #nosec G306 -- public configuration
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
	trustDocPath := fs.String("trust-doc", "", "the pinned SDK trust-base document")
	cfgHash := fs.String("cfg", "", "the vault's CFG")
	out := fs.String("out", "", "output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	blockHash := common.HexToHash(*blockHashText)
	request, err := requestForBlock(*archiveDir, blockHash)
	if err != nil {
		return err
	}
	store, err := archive.Open(*archiveDir)
	if err != nil {
		return err
	}
	rec, err := store.GetReceiptComplete(request)
	if err != nil {
		return fmt.Errorf("the archive does not hold block %s: %w", blockHash, err)
	}
	var hdr gethtypes.Header
	if err := rlp.DecodeBytes(rec.Header, &hdr); err != nil || hdr.Hash() != blockHash {
		return fmt.Errorf("archived header is not block %s", blockHash)
	}
	rawConf, err := os.ReadFile(*fullConf)
	if err != nil {
		return err
	}
	var conf types.PartitionDescriptionRecord
	if err := json.Unmarshal(rawConf, &conf); err != nil {
		return err
	}
	pdr, err := types.Cbor.Marshal(&conf)
	if err != nil {
		return err
	}
	var uc types.UnicityCertificate
	if err := types.Cbor.Unmarshal(rec.ResultingUC, &uc); err != nil {
		return err
	}
	sum := sha256.Sum256(pdr)
	if !bytes.Equal(sum[:], uc.ShardConfHash) {
		return fmt.Errorf("the full shard configuration is not the configuration the block's certificate commits to")
	}
	doc, err := os.ReadFile(*trustDocPath)
	if err != nil {
		return err
	}
	tbID := sha256.Sum256(doc)
	vault := common.HexToAddress(*vaultText)
	slot := crypto.Keccak256Hash(common.LeftPadBytes(new(big.Int).SetUint64(*nonce).Bytes(), 32), common.LeftPadBytes([]byte{5}, 32))
	raw, err := rpcCall(*ethURL, "eth_getProof", []any{vault, []common.Hash{slot}, map[string]any{"blockHash": blockHash}})
	if err != nil {
		return err
	}
	var proof struct {
		Address      common.Address  `json:"address"`
		AccountProof []hexutil.Bytes `json:"accountProof"`
		StorageProof []struct {
			Proof []hexutil.Bytes `json:"proof"`
		} `json:"storageProof"`
	}
	if err := json.Unmarshal(raw, &proof); err != nil {
		return err
	}
	if proof.Address != vault || len(proof.StorageProof) != 1 {
		return fmt.Errorf("unexpected eth_getProof answer")
	}
	lp := bridgeprofile.LockProof{TrustBaseID: tbID, PDR: pdr, UC: bytes.Clone(rec.ResultingUC), Header: bytes.Clone(rec.Header)}
	copy(lp.Cfg[:], common.HexToHash(*cfgHash).Bytes())
	for _, n := range proof.AccountProof {
		lp.AccountNodes = append(lp.AccountNodes, []byte(n))
	}
	for _, n := range proof.StorageProof[0].Proof {
		lp.StorageNodes = append(lp.StorageNodes, []byte(n))
	}
	return os.WriteFile(*out, lp.Bytes(), 0o644) // #nosec G306 -- public proof
}

func rpcCall(url, method string, params []any) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
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
		return nil, fmt.Errorf("%s: %s", method, out.Error.Message)
	}
	return out.Result, nil
}

func requestForBlock(dir string, blockHash common.Hash) (archive.Request, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return archive.Request{}, err
	}
	var matches []archive.Request
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "v2-") {
			continue
		}
		manifest, readErr := os.ReadFile(filepath.Join(dir, entry.Name(), "manifest"))
		if readErr != nil || len(manifest) < 12 || !bytes.Equal(manifest[:8], []byte("ARCHIVE2")) {
			continue
		}
		requestLen := binary.BigEndian.Uint32(manifest[8:12])
		if requestLen == 0 || uint64(requestLen)+12 > uint64(len(manifest)) {
			continue
		}
		request, decodeErr := archive.DecodeRequest(manifest[12 : 12+requestLen])
		if decodeErr == nil && request.BlockHash == [32]byte(blockHash) {
			matches = append(matches, request)
		}
	}
	if len(matches) != 1 {
		return archive.Request{}, fmt.Errorf("expected one receipt-complete archive request for %s, found %d", blockHash, len(matches))
	}
	return matches[0], nil
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

// b1check evaluates a UC_V1 request with the Go reference verifier (b1ref) against the registry context of the deployment's genesis profile, at
// a given registry clock: the first place to look when the native call answers false.
func b1check(args []string) error {
	fs := flag.NewFlagSet("b1check", flag.ContinueOnError)
	req := fs.String("request", "", "UC_V1 request bytes")
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
		WCert   uint64 `json:"wCert"`
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
	reg := &b1ref.Registry{GenesisCommitment: [32]byte{1}, ProfileHash: [32]byte{1}, Initialized: true, Phase: 2, Network: pf.Network, WCert: pf.WCert, Origin: entries[0].Epoch, RootRound: *clock, Epochs: map[uint64]b1ref.EpochEntry{}}
	for _, e := range entries {
		reg.Epochs[e.Epoch] = e
	}
	v, err := b1ref.UC(in, reg)
	fmt.Printf("valid=%v why=%v err=%v gas=%d (epoch entry: start=%d members=%d)\n", v.Valid, v.Why, err, v.Gas, entries[0].Start, len(entries[0].Members))
	return nil
}
