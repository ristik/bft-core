// Command nb2-evidence builds native bridge v2 wallet evidence from the standard node RPC behind the public gateway, and checks it with
// the Go reference (nb2ref). It is the evidence-fetch stage of the NB2-09 (bft-core#1105) run and the executable form of the wallet
// RPC contract (docs/design/native-bridge-v2.md, "Wallet RPC contract"): every byte it carries comes from the methods listed there,
// through one RPC URL, and no bridge-specific service is contacted.
//
//	nb2-evidence receipt -rpc URL -tx HASH -emitter ADDR -topic0 T [-out FILE]        a DepositProof container for the first log of the
//	                                                                                   transaction from ADDR with topic0 T (a Deposited
//	                                                                                   receipt proof, or a SegmentSealed seal receipt)
//	nb2-evidence newest-seal -rpc URL -emitter ADDR -from N [-out FILE]               the seal receipt of the newest SegmentSealed log
//	                                                                                   at or after block N, paging eth_getLogs backwards
//	nb2-evidence segments -rpc URL -emitter ADDR -from N -start A                     the SegmentSealed logs of segments A.. in order, paging
//	                                                                                   forwards (the history a redemption folds)
//	nb2-evidence verify -proof FILE -emitter ADDR -partition P -shard S -trust-bundle B -event deposited|sealed [-k K]
//	                                                                                   section 6.2 steps 2 to 5 (and the event's topic and
//	                                                                                   data shape) with nb2ref.VerifyReceiptLog
//	nb2-evidence gamma -network N -root-genesis H -execution-genesis H -chain-id N -evm-partition P -evm-shard S
//	                   -aggregator-partition P -vault ADDR -verifier ADDR -verifier-code-hash H -profile-hash H -k K -b B -qmax Q
//	                                                                                   Γ (section 4.1) with the section 4.2 derivations, and D,
//	                                                                                   as JSON; with -decode FILE, the fields of an encoded Γ
//	nb2-evidence verify-return -gamma FILE -trust-bundle B -pin P [-build test|production] EVIDENCE...
//	                                                                                   the reference verifier (nb2ref.VerifyReturn) on each
//	                                                                                   evidence file: one JSON line per file with the 192-byte
//	                                                                                   verdict ABI, or the section 14 rule that refuses it
//	nb2-evidence seed -rpc URL -chain-id N                                            devnet only: deploy a two-topic log emitter with the
//	                                                                                   public Anvil key and emit one Deposited and one
//	                                                                                   SegmentSealed event of the exact ABI shape (until the
//	                                                                                   NB2-04 vault exists)
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/rawdb"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/nb2ref"
)

// Event topics of section 13.2.
var (
	TopicDeposited     = crypto.Keccak256Hash([]byte("Deposited(uint64,bytes32,uint256,bytes32,bytes)"))
	TopicSegmentSealed = crypto.Keccak256Hash([]byte("SegmentSealed(uint64,bytes32,bytes32,bytes)"))
	TopicPaid          = crypto.Keccak256Hash([]byte("Paid(bytes32,address,uint256)"))
)

// LogBlockRange is the public gateway's eth_getLogs window (deploy/testnet/gateway.py LOG_BLOCK_RANGE).
const LogBlockRange = 10000

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: nb2-evidence receipt|newest-seal|segments|verify|gamma|verify-return|seed [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "receipt":
		err = receiptCmd(os.Args[2:])
	case "newest-seal":
		err = newestSealCmd(os.Args[2:])
	case "segments":
		err = segmentsCmd(os.Args[2:])
	case "verify":
		err = verifyCmd(os.Args[2:])
	case "gamma":
		err = gammaCmd(os.Args[2:], os.Stdout)
	case "verify-return":
		err = verifyReturnCmd(os.Args[2:])
	case "seed":
		err = seedCmd(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "nb2-evidence:", err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------------------------------------------------------------
// The wallet's RPC client: one URL, JSON-RPC 2.0 POSTs, one request per call (the gateway takes no batches).

type Client struct {
	URL  string
	HTTP *http.Client
}

func NewClient(url string) *Client {
	return &Client{URL: url, HTTP: &http.Client{Timeout: 45 * time.Second}}
}

// RPCError is a JSON-RPC error object, or a gateway refusal (HTTP status and its JSON error text).
type RPCError struct {
	Status  int
	Code    int
	Message string
}

func (e *RPCError) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("gateway HTTP %d: %s", e.Status, e.Message)
}

// Call makes one request. A rate-limit refusal (HTTP 429) is waited out and retried, a few times: it is the gateway's back-off
// signal, never an answer.
func (c *Client) Call(ctx context.Context, method string, params []any, out any) error {
	for attempt := 0; ; attempt++ {
		err := c.call(ctx, method, params, out)
		var rpcErr *RPCError
		if attempt < 10 && errors.As(err, &rpcErr) && rpcErr.Status == http.StatusTooManyRequests {
			select {
			case <-time.After(time.Duration(attempt+1) * 500 * time.Millisecond):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return err
	}
}

func (c *Client) call(ctx context.Context, method string, params []any, out any) error {
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if xff := os.Getenv("NB2_EVIDENCE_FORWARDED_FOR"); xff != "" {
		// the package gateway reached through its trusted proxy address (a host-side lane run) names the client as the proxy would
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return err
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if resp.StatusCode != http.StatusOK {
		var g struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &g)
		return &RPCError{Status: resp.StatusCode, Message: g.Error}
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	if env.Error != nil {
		return &RPCError{Status: resp.StatusCode, Code: env.Error.Code, Message: env.Error.Message}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(env.Result, out)
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Receipt proof: the DepositProof container of section 6.1, [1, b(evmUC), b(headerRLP), txIndex, logIndex, [b(receiptNodeRLP)...]].

// ErrNotYetCertified means the block's certificate is not served yet: the child block that carries it does not exist yet, or
// the node has not stored its companion. Retry later.
var ErrNotYetCertified = errors.New("the block's certificate is not served yet (no child block or companion): retry")

// ErrPruned means the node no longer serves the evidence: a companion below its published retention horizon, or a block it does
// not hold. Ask a node that retains it (an archive), or the deployment's documented source.
var ErrPruned = errors.New("the evidence has been pruned on this node")

type receiptJSON struct {
	BlockHash        common.Hash      `json:"blockHash"`
	BlockNumber      hexutil.Uint64   `json:"blockNumber"`
	TransactionIndex hexutil.Uint64   `json:"transactionIndex"`
	Status           hexutil.Uint64   `json:"status"`
	Logs             []*gethtypes.Log `json:"logs"`
}

type companionLookup struct {
	Status    string `json:"status"`
	Horizon   uint64 `json:"horizon"`
	Companion struct {
		Witnesses []hexutil.Bytes `json:"witnesses"`
	} `json:"companion"`
}

// ReceiptProof is the built container and the facts it was built from.
type ReceiptProof struct {
	Proof       *nb2ref.DepositProof
	BlockHash   common.Hash
	BlockNumber uint64
	LogTopics   []common.Hash
}

// BuildReceiptProof builds the container for the first log of transaction txHash emitted by emitter with topic0. The methods it
// uses are exactly: eth_getTransactionReceipt, eth_getBlockByHash, eth_getBlockByNumber, unicity_getSealCompanionV1 and
// eth_getBlockReceipts.
func BuildReceiptProof(ctx context.Context, c *Client, txHash common.Hash, emitter common.Address, topic0 common.Hash) (*ReceiptProof, error) {
	var r *receiptJSON
	if err := c.Call(ctx, "eth_getTransactionReceipt", []any{txHash}, &r); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("transaction %s has no receipt on this node (pending, unknown or pruned)", txHash)
	}
	if r.Status != 1 {
		return nil, fmt.Errorf("transaction %s failed: its logs never count", txHash)
	}
	logIndex := -1
	for i, l := range r.Logs {
		if l.Address == emitter && len(l.Topics) > 0 && l.Topics[0] == topic0 {
			logIndex = i
			break
		}
	}
	if logIndex < 0 {
		return nil, fmt.Errorf("transaction %s emitted no %s log from %s", txHash, topic0, emitter)
	}
	header, headerRLP, err := headerByHash(ctx, c, r.BlockHash)
	if err != nil {
		return nil, err
	}
	uc, err := certificateOf(ctx, c, header)
	if err != nil {
		return nil, err
	}
	nodes, err := receiptPath(ctx, c, header, uint64(r.TransactionIndex))
	if err != nil {
		return nil, err
	}
	return &ReceiptProof{
		Proof:       &nb2ref.DepositProof{UC: uc, Header: headerRLP, TxIndex: uint64(r.TransactionIndex), LogIndex: uint64(logIndex), Nodes: nodes},
		BlockHash:   r.BlockHash,
		BlockNumber: header.Number.Uint64(),
		LogTopics:   r.Logs[logIndex].Topics,
	}, nil
}

// headerByHash reads the block header and its exact RLP, which must hash to the requested block hash.
func headerByHash(ctx context.Context, c *Client, hash common.Hash) (*gethtypes.Header, []byte, error) {
	var h *gethtypes.Header
	if err := c.Call(ctx, "eth_getBlockByHash", []any{hash, false}, &h); err != nil {
		return nil, nil, err
	}
	if h == nil {
		return nil, nil, fmt.Errorf("%w: block %s is not held by this node", ErrPruned, hash)
	}
	raw, err := rlp.EncodeToBytes(h)
	if err != nil {
		return nil, nil, err
	}
	if crypto.Keccak256Hash(raw) != hash {
		return nil, nil, fmt.Errorf("the header served for %s does not re-encode to its hash", hash)
	}
	return h, raw, nil
}

// certificateOf returns the certificate of block N: witness 0 of the companion retained for its child, block N+1, which the paired
// shard node built on N under the certificate of N. A block's certificate is therefore served once its child exists.
func certificateOf(ctx context.Context, c *Client, header *gethtypes.Header) ([]byte, error) {
	var child *gethtypes.Header
	if err := c.Call(ctx, "eth_getBlockByNumber", []any{hexutil.Uint64(header.Number.Uint64() + 1), false}, &child); err != nil {
		return nil, err
	}
	if child == nil {
		return nil, ErrNotYetCertified
	}
	if child.ParentHash != header.Hash() {
		return nil, fmt.Errorf("block %d is not on this node's canonical chain", header.Number.Uint64())
	}
	var l companionLookup
	if err := c.Call(ctx, "unicity_getSealCompanionV1", []any{child.Hash()}, &l); err != nil {
		return nil, err
	}
	switch l.Status {
	case "found":
	case "unavailable":
		return nil, fmt.Errorf("%w: companion of block %d is below the node's retention horizon %d", ErrPruned, child.Number.Uint64(), l.Horizon)
	default:
		return nil, fmt.Errorf("%w (companion status %q)", ErrNotYetCertified, l.Status)
	}
	if len(l.Companion.Witnesses) != 2 {
		return nil, fmt.Errorf("the companion of block %d carries %d witnesses, not [certificate, technical record]", child.Number.Uint64(), len(l.Companion.Witnesses))
	}
	raw := []byte(l.Companion.Witnesses[0])
	var uc types.UnicityCertificate
	if err := types.Cbor.Unmarshal(raw, &uc); err != nil || uc.InputRecord == nil {
		return nil, fmt.Errorf("witness 0 of block %d's companion is not a certificate", child.Number.Uint64())
	}
	// A convenience check before the full verification: the certificate names this block and state.
	if !bytes.Equal(uc.InputRecord.BlockHash, header.Hash().Bytes()) || !bytes.Equal(uc.InputRecord.Hash, header.Root.Bytes()) {
		return nil, fmt.Errorf("the certificate in block %d's companion does not certify block %d", child.Number.Uint64(), header.Number.Uint64())
	}
	return raw, nil
}

// receiptPath rebuilds the block's receipt trie from eth_getBlockReceipts, requires its root to be the header's, and returns the
// root-to-leaf path of RLP(txIndex): the hash-referenced nodes in order (an embedded node travels inside its parent).
func receiptPath(ctx context.Context, c *Client, header *gethtypes.Header, txIndex uint64) ([][]byte, error) {
	var receipts []*gethtypes.Receipt
	if err := c.Call(ctx, "eth_getBlockReceipts", []any{header.Hash()}, &receipts); err != nil {
		return nil, err
	}
	if txIndex >= uint64(len(receipts)) {
		return nil, fmt.Errorf("block %d has %d receipts, no index %d", header.Number.Uint64(), len(receipts), txIndex)
	}
	t := trie.NewEmpty(triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil))
	for i, r := range receipts {
		key, _ := rlp.EncodeToBytes(uint64(i))
		enc, err := r.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if err := t.Update(key, enc); err != nil {
			return nil, err
		}
	}
	if t.Hash() != header.ReceiptHash {
		return nil, fmt.Errorf("the receipts served for block %d do not hash to its receiptsRoot", header.Number.Uint64())
	}
	key, _ := rlp.EncodeToBytes(txIndex)
	var path orderedProof
	if err := t.Prove(key, &path); err != nil {
		return nil, err
	}
	return path.nodes, nil
}

// orderedProof keeps the nodes trie.Prove writes, in the root-to-leaf order it writes them.
type orderedProof struct{ nodes [][]byte }

func (p *orderedProof) Put(_ []byte, value []byte) error {
	p.nodes = append(p.nodes, bytes.Clone(value))
	return nil
}
func (p *orderedProof) Delete([]byte) error { return errors.New("not supported") }

// ---------------------------------------------------------------------------------------------------------------------------------
// Logs, paged by the gateway's window.

type logFilter struct {
	Address   common.Address  `json:"address"`
	Topics    [][]common.Hash `json:"topics,omitempty"`
	FromBlock hexutil.Uint64  `json:"fromBlock"`
	ToBlock   hexutil.Uint64  `json:"toBlock"`
}

func head(ctx context.Context, c *Client) (uint64, error) {
	var n hexutil.Uint64
	err := c.Call(ctx, "eth_blockNumber", nil, &n)
	return uint64(n), err
}

// Logs returns emitter's logs matching topics in [from, to], one window of at most LogBlockRange blocks per request, in order.
func Logs(ctx context.Context, c *Client, emitter common.Address, topics [][]common.Hash, from, to uint64) ([]*gethtypes.Log, error) {
	var out []*gethtypes.Log
	for lo := from; lo <= to; lo += LogBlockRange {
		hi := min(lo+LogBlockRange-1, to)
		var page []*gethtypes.Log
		if err := c.Call(ctx, "eth_getLogs", []any{logFilter{Address: emitter, Topics: topics, FromBlock: hexutil.Uint64(lo), ToBlock: hexutil.Uint64(hi)}}, &page); err != nil {
			return nil, fmt.Errorf("eth_getLogs %d..%d: %w", lo, hi, err)
		}
		for _, l := range page {
			if !l.Removed {
				out = append(out, l)
			}
		}
	}
	return out, nil
}

// NewestSeal returns the newest SegmentSealed log of emitter at or after block from, paging backwards from the head.
func NewestSeal(ctx context.Context, c *Client, emitter common.Address, from uint64) (*gethtypes.Log, error) {
	top, err := head(ctx, c)
	if err != nil {
		return nil, err
	}
	for hi := top; ; {
		lo := from
		if hi >= from+LogBlockRange {
			lo = hi - LogBlockRange + 1
		}
		logs, err := Logs(ctx, c, emitter, [][]common.Hash{{TopicSegmentSealed}}, lo, hi)
		if err != nil {
			return nil, err
		}
		if len(logs) > 0 {
			return logs[len(logs)-1], nil
		}
		if lo == from {
			return nil, nil
		}
		hi = lo - 1
	}
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Commands.

func writeOut(path string, b []byte) error {
	if path == "" {
		_, err := fmt.Println(hex.EncodeToString(b))
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func receiptCmd(args []string) error {
	fs := flag.NewFlagSet("receipt", flag.ContinueOnError)
	url := fs.String("rpc", "", "the public RPC URL")
	tx := fs.String("tx", "", "transaction hash")
	emitter := fs.String("emitter", "", "the vault (emitter) address")
	topic0 := fs.String("topic0", TopicDeposited.Hex(), "the event's topic0 (Deposited by default)")
	out := fs.String("out", "", "write the container here (default: hex on stdout)")
	wait := fs.Duration("wait", 60*time.Second, "how long to wait for the block's certificate to be served")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := buildWaiting(context.Background(), NewClient(*url), common.HexToHash(*tx), common.HexToAddress(*emitter), common.HexToHash(*topic0), *wait)
	if err != nil {
		return err
	}
	return writeOut(*out, p.Proof.Bytes())
}

// buildWaiting is BuildReceiptProof, retried while the block's certificate is not served yet (its child block is about one round
// away).
func buildWaiting(ctx context.Context, c *Client, tx common.Hash, emitter common.Address, topic0 common.Hash, wait time.Duration) (*ReceiptProof, error) {
	deadline := time.Now().Add(wait)
	for {
		p, err := BuildReceiptProof(ctx, c, tx, emitter, topic0)
		if errors.Is(err, ErrNotYetCertified) && time.Now().Before(deadline) {
			time.Sleep(time.Second)
			continue
		}
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "block %d %s tx %d log %d: %d receipt-path nodes, UC %d bytes, header %d bytes\n", p.BlockNumber, p.BlockHash, p.Proof.TxIndex, p.Proof.LogIndex, len(p.Proof.Nodes), len(p.Proof.UC), len(p.Proof.Header))
		return p, nil
	}
}

func newestSealCmd(args []string) error {
	fs := flag.NewFlagSet("newest-seal", flag.ContinueOnError)
	url := fs.String("rpc", "", "the public RPC URL")
	emitter := fs.String("emitter", "", "the vault address")
	from := fs.Uint64("from", 0, "the vault's deployment block")
	out := fs.String("out", "", "write the container here (default: hex on stdout)")
	wait := fs.Duration("wait", 60*time.Second, "how long to wait for the block's certificate to be served")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	c := NewClient(*url)
	l, err := NewestSeal(ctx, c, common.HexToAddress(*emitter), *from)
	if err != nil {
		return err
	}
	if l == nil {
		fmt.Fprintln(os.Stderr, "no SegmentSealed log: sign a = 0 (start head H_0)")
		return nil
	}
	p, err := buildWaiting(ctx, c, l.TxHash, common.HexToAddress(*emitter), TopicSegmentSealed, *wait)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "newest seal: segment %s in block %d; sign a = j + 1\n", new(big.Int).SetBytes(l.Topics[1][:]), p.BlockNumber)
	return writeOut(*out, p.Proof.Bytes())
}

func segmentsCmd(args []string) error {
	fs := flag.NewFlagSet("segments", flag.ContinueOnError)
	url := fs.String("rpc", "", "the public RPC URL")
	emitter := fs.String("emitter", "", "the vault address")
	from := fs.Uint64("from", 0, "the vault's deployment block")
	start := fs.Uint64("start", 0, "the first segment index a")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	c := NewClient(*url)
	top, err := head(ctx, c)
	if err != nil {
		return err
	}
	logs, err := Logs(ctx, c, common.HexToAddress(*emitter), [][]common.Hash{{TopicSegmentSealed}}, *from, top)
	if err != nil {
		return err
	}
	next := *start
	for _, l := range logs {
		if len(l.Topics) != 2 {
			return fmt.Errorf("SegmentSealed log in block %d has %d topics", l.BlockNumber, len(l.Topics))
		}
		j := new(big.Int).SetBytes(l.Topics[1][:])
		if !j.IsUint64() || j.Uint64() < next {
			continue
		}
		if j.Uint64() != next {
			return fmt.Errorf("segment %d is missing (next log is segment %s): the node's log history is incomplete", next, j)
		}
		fmt.Printf("%d %d %s %s\n", j.Uint64(), l.BlockNumber, l.TxHash, hex.EncodeToString(l.Data))
		next++
	}
	fmt.Fprintf(os.Stderr, "segments %d..%d (%d logs, head %d)\n", *start, next, next-*start, top)
	return nil
}

func verifyCmd(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	proofPath := fs.String("proof", "", "the container")
	emitter := fs.String("emitter", "", "the vault address (Γ.vault20)")
	partition := fs.Uint("partition", 0, "Γ.evmPartition")
	shard := fs.String("shard", "0x80", "Γ.evmShard, canonical native shard ID in hex")
	bundlePath := fs.String("trust-bundle", "", "the trust-base release bundle (tag 39015)")
	pinText := fs.String("pin", "", "the genesis EntryID (Γ.rootGenesis32), hex")
	event := fs.String("event", "deposited", "deposited|sealed")
	k := fs.Uint64("k", 64, "K, for the SegmentSealed data length")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := os.ReadFile(*proofPath)
	if err != nil {
		return err
	}
	if b, err := hex.DecodeString(strings.TrimSpace(string(raw))); err == nil {
		raw = b
	}
	p, err := nb2ref.DecodeDepositProof(raw)
	if err != nil {
		return fmt.Errorf("container: %w", err)
	}
	bundle, err := os.ReadFile(*bundlePath)
	if err != nil {
		return err
	}
	pin, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(*pinText), "0x"))
	if err != nil || len(pin) != 32 {
		return errors.New("-pin must be 32 bytes of hex")
	}
	trust, err := nb2ref.LoadTrustInput(bundle, [32]byte(pin))
	if err != nil {
		return err
	}
	shardID, err := hex.DecodeString(strings.TrimPrefix(*shard, "0x"))
	if err != nil {
		return err
	}
	cfg := &nb2ref.Config{Vault: common.HexToAddress(*emitter), EVMPartition: uint32(*partition), EVMShard: shardID, K: *k}
	l, err := nb2ref.VerifyReceiptLog(cfg, trust, p)
	if err != nil {
		return fmt.Errorf("%s: %w", nb2ref.RuleName(err), err)
	}
	var topic0 common.Hash
	var dataLen int
	switch *event {
	case "deposited":
		topic0, dataLen = TopicDeposited, 224
	case "sealed":
		topic0, dataLen = TopicSegmentSealed, 128+32*int(*k)
	default:
		return fmt.Errorf("unknown event %q", *event)
	}
	if len(l.Topics) != 2 || l.Topics[0] != topic0 {
		return errors.New("LogTopics: not [topic0, u256(index)] of the event")
	}
	if len(l.Data) != dataLen {
		return fmt.Errorf("LogData: %d bytes, want %d", len(l.Data), dataLen)
	}
	fmt.Printf("verified %s receipt: emitter %x, index %s, txIndex %d, logIndex %d\n", *event, l.Address, new(big.Int).SetBytes(l.Topics[1][:]), p.TxIndex, p.LogIndex)
	return nil
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Devnet seeding (until the NB2-04 vault exists). The emitter's runtime is LOG2(calldata[64:], calldata[0:32], calldata[32:64]):
//
//	PUSH1 0x20 CALLDATALOAD PUSH1 0 CALLDATALOAD CALLDATASIZE PUSH1 0x40 SWAP1 SUB DUP1 PUSH1 0x40 PUSH1 0 CALLDATACOPY PUSH1 0 LOG2 STOP
//
// so it emits exactly the two-topic events of section 13.2. The key is the public Anvil account 0: devnets only.

const (
	emitterRuntime = "60203560003536604090038060406000376000a200"
	emitterInit    = "601580600b6000396000f3" + emitterRuntime
	anvilKey       = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)

func seedCmd(args []string) error {
	fs := flag.NewFlagSet("seed", flag.ContinueOnError)
	url := fs.String("rpc", "", "the RPC URL (the gateway passes eth_sendRawTransaction)")
	chainID := fs.Int64("chain-id", 31337, "chain ID")
	k := fs.Int("k", 4, "K for the SegmentSealed ids")
	fillers := fs.Int("fillers", 20, "transfers sent just ahead of the deposit, to share its block")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	c := NewClient(*url)
	key, _ := crypto.HexToECDSA(anvilKey)
	from := crypto.PubkeyToAddress(key.PublicKey)
	var nonce hexutil.Uint64
	if err := c.Call(ctx, "eth_getTransactionCount", []any{from, "latest"}, &nonce); err != nil {
		return err
	}
	var gasPrice hexutil.Big
	if err := c.Call(ctx, "eth_gasPrice", nil, &gasPrice); err != nil {
		return err
	}
	fee := new(big.Int).Mul(gasPrice.ToInt(), big.NewInt(2))
	signer := gethtypes.LatestSignerForChainID(big.NewInt(*chainID))
	// submit signs and sends one transaction without waiting for it.
	submit := func(to *common.Address, data []byte) (common.Hash, error) {
		tx, err := gethtypes.SignNewTx(key, signer, &gethtypes.DynamicFeeTx{ChainID: big.NewInt(*chainID), Nonce: uint64(nonce), GasTipCap: big.NewInt(1), GasFeeCap: fee, Gas: 1_000_000, To: to, Data: data})
		if err != nil {
			return common.Hash{}, err
		}
		raw, _ := tx.MarshalBinary()
		_ = c.Call(ctx, "eth_sendRawTransaction", []any{hexutil.Bytes(raw)}, nil) // a partial broadcast still lands (see send)
		nonce++
		return tx.Hash(), nil
	}
	send := func(to *common.Address, data []byte) (common.Hash, error) {
		tx, err := gethtypes.SignNewTx(key, signer, &gethtypes.DynamicFeeTx{ChainID: big.NewInt(*chainID), Nonce: uint64(nonce), GasTipCap: big.NewInt(1), GasFeeCap: fee, Gas: 1_000_000, To: to, Data: data})
		if err != nil {
			return common.Hash{}, err
		}
		raw, _ := tx.MarshalBinary()
		h := tx.Hash()
		// The gateway broadcasts to every validator and reports a partial broadcast when their answers differ (one that already
		// received the transaction by gossip says so): the transaction may still be in, so look for its receipt either way.
		sendErr := c.Call(ctx, "eth_sendRawTransaction", []any{hexutil.Bytes(raw)}, nil)
		nonce++
		for i := 0; i < 120; i++ {
			var r *receiptJSON
			if err := c.Call(ctx, "eth_getTransactionReceipt", []any{h}, &r); err == nil && r != nil {
				if r.Status != 1 {
					return h, fmt.Errorf("transaction %s failed", h)
				}
				return h, nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		return h, fmt.Errorf("transaction %s not included (send: %v)", h, sendErr)
	}
	initCode, _ := hex.DecodeString(emitterInit)
	deployTx, err := send(nil, initCode)
	if err != nil {
		return err
	}
	emitter := crypto.CreateAddress(from, uint64(nonce)-1)
	word := func(n uint64) []byte { return common.BigToHash(new(big.Int).SetUint64(n)).Bytes() }
	d := crypto.Keccak256([]byte("nb2-1102 devnet domain"))
	rho := crypto.Keccak256([]byte("nb2-1102 devnet rho"))
	owner := append([]byte{0xd9, 0x98, 0x78, 0x83, 0x01, 0x41, 0x01, 0x58, 0x21, 0x02}, bytes.Repeat([]byte{0x11}, 32)...)
	deposited := bytes.Join([][]byte{TopicDeposited[:], word(1), d, word(1_000_000_000), rho, word(0x80), word(42), common.RightPadBytes(owner, 64)}, nil)
	// A few transfers ahead of the deposit, sent together, put it at a nonzero index of a block with several receipts, so its
	// receipt-trie path has inner nodes.
	for i := 0; i < *fillers; i++ {
		if _, err := submit(&from, nil); err != nil {
			return err
		}
	}
	depositTx, err := send(&emitter, deposited)
	if err != nil {
		return err
	}
	ids := make([][]byte, *k)
	for i := range ids {
		ids[i] = common.BigToHash(new(big.Int).Lsh(big.NewInt(int64(i+1)), 200)).Bytes()
	}
	sealed := bytes.Join(append([][]byte{TopicSegmentSealed[:], word(0), crypto.Keccak256([]byte("H0")), crypto.Keccak256([]byte("H1")), word(0x60), word(uint64(32 * *k))}, ids...), nil)
	sealTx, err := send(&emitter, sealed)
	if err != nil {
		return err
	}
	var deployed hexutil.Uint64
	var dr *receiptJSON
	if err := c.Call(ctx, "eth_getTransactionReceipt", []any{deployTx}, &dr); err == nil && dr != nil {
		deployed = dr.BlockNumber
	}
	out, _ := json.MarshalIndent(map[string]string{"emitter": emitter.Hex(), "deploymentBlock": strconv.FormatUint(uint64(deployed), 10),
		"depositTx": depositTx.Hex(), "sealTx": sealTx.Hex()}, "", "  ")
	fmt.Println(string(out))
	return nil
}
