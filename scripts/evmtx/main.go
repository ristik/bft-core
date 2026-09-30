// Command evmtx is an F1 test helper: it prints a funded genesis alloc and signs one EIP-1559
// transaction, so scripts/reth-paired-devnet.sh can prove the Go adapter actually builds,
// certifies and commits a real EVM block rather than only certifying quiet rounds.
//
// It exists because an idle Unicity shard produces no EVM blocks at all at the F1 baseline: every
// round after the first is quiet (unchanged state root, nil block hash, see
// shardnode/round.go), so reth's canonical head stays at genesis no matter how many rounds
// certify. Making the adapter build a block needs something to execute, and executing anything
// needs a funded account — which the generated genesis does not have (`alloc` is empty). Real
// genesis funding is T1 (#28); this is a test-only stand-in.
//
// The transaction is assembled by hand (RLP + Keccak-256 + a recoverable secp256k1 signature)
// rather than with go-ethereum, deliberately: go-ethereum is only an indirect dependency here, and
// promoting it drags in gnark-crypto, blst, c-kzg-4844 and go-verkle. That is a lot of new
// cryptographic surface for a consensus repository to carry for one test helper. Everything below
// uses packages already in the module graph.
//
// The signing key is the universally known Hardhat/Anvil account 0. NEVER use it for anything
// real. It is public, and it is used here precisely because it is.
//
//	go run ./scripts/evmtx -alloc                                   # funded alloc object
//	go run ./scripts/evmtx -send -eth-url URL -chain-id N -nonce K  # sign + send, prints tx hash
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// Hardhat/Anvil account 0 — public by construction, see the package comment.
const testKeyHex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

// eip1559TxType is the EIP-2718 envelope byte for a dynamic-fee transaction.
const eip1559TxType = 0x02

func main() {
	var (
		alloc         = flag.Bool("alloc", false, "print a genesis alloc object funding the test account")
		address       = flag.Bool("address", false, "print the funded test account address")
		send          = flag.Bool("send", false, "sign a transfer and submit it with eth_sendRawTransaction")
		create        = flag.Bool("create", false, "create a contract instead of sending to an address")
		createAddress = flag.Bool("create-address", false, "print the CREATE address for the funded key and nonce")
		lockInitcode  = flag.Bool("lock-initcode", false, "print initcode for the demo payable Locked(uint256) receipt contract")
		eventTopic    = flag.String("event-topic", "", "print the Keccak-256 topic for an event signature")
		ethURL        = flag.String("eth-url", "http://127.0.0.1:8545", "eth_* endpoint")
		chainID       = flag.Int64("chain-id", 31337, "chain id to sign for")
		nonce         = flag.Uint64("nonce", 0, "sender nonce")
		tip           = flag.Int64("tip", 1_000_000_000, "maxPriorityFeePerGas in wei")
		feeCap        = flag.Int64("fee-cap", 10_000_000_000, "maxFeePerGas in wei")
		to            = flag.String("to", "0x00000000000000000000000000000000000000ff", "transaction recipient")
		value         = flag.String("value", "1", "transaction value in decimal or 0x-prefixed hex")
		data          = flag.String("data", "0x", "transaction calldata or contract creation bytecode")
		call          = flag.String("call", "", "zero-argument call signature; encoded as its 4-byte selector")
		gasLimit      = flag.Uint64("gas-limit", 21000, "transaction gas limit")
	)
	flag.Parse()

	keyBytes, err := hex.DecodeString(testKeyHex)
	if err != nil {
		fatal("decoding the test key: %v", err)
	}
	key := secp256k1.PrivKeyFromBytes(keyBytes)
	from := addressOf(key)

	switch {
	case *address:
		fmt.Println(from)
	case *createAddress:
		fmt.Println(createAddressFor(from, *nonce))
	case *lockInitcode:
		fmt.Println("0x" + hex.EncodeToString(lockInitcodeBytes()))
	case *eventTopic != "":
		fmt.Println("0x" + hex.EncodeToString(keccak([]byte(*eventTopic))))
	case *alloc:
		// 10000 ETH, enough that fee experiments never run the account dry.
		out, err := json.MarshalIndent(map[string]any{
			from: map[string]string{"balance": "0x21e19e0c9bab2400000"},
		}, "", "  ")
		if err != nil {
			fatal("encoding alloc: %v", err)
		}
		fmt.Println(string(out))
	case *send:
		var toBytes []byte
		if !*create {
			toBytes, err = hex.DecodeString(strings.TrimPrefix(*to, "0x"))
			if err != nil || len(toBytes) != 20 {
				fatal("recipient %q must be a 20-byte hex address", *to)
			}
		}
		valueBig, ok := parseQuantity(*value)
		if !ok || valueBig.Sign() < 0 {
			fatal("value %q must be a non-negative decimal or 0x quantity", *value)
		}
		dataBytes, err := hex.DecodeString(strings.TrimPrefix(*data, "0x"))
		if err != nil {
			fatal("data must be 0x-prefixed hex: %v", err)
		}
		if *call != "" {
			if *data != "0x" && *data != "" {
				fatal("--call and --data cannot be combined")
			}
			dataBytes = methodSelector(*call)
		}
		if *gasLimit == 0 {
			fatal("gas limit must be positive")
		}
		raw, err := signTx(key, *chainID, *nonce, *tip, *feeCap, toBytes, valueBig, dataBytes, *gasLimit)
		if err != nil {
			fatal("%v", err)
		}
		hash, err := sendRaw(*ethURL, raw)
		if err != nil {
			fatal("%v", err)
		}
		fmt.Println(hash)
	default:
		fmt.Fprintf(os.Stderr, "from: %s\n", from)
		flag.Usage()
		os.Exit(2)
	}
}

// addressOf derives the Ethereum address: the low 20 bytes of Keccak-256 over the uncompressed
// public key with its 0x04 prefix stripped.
func addressOf(key *secp256k1.PrivateKey) string {
	pub := key.PubKey().SerializeUncompressed()
	return "0x" + hex.EncodeToString(keccak(pub[1:])[12:])
}

func keccak(parts ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// signTx builds and signs an EIP-1559 (type 0x02) transfer, returning the EIP-2718 encoding.
func signTx(key *secp256k1.PrivateKey, chainID int64, nonce uint64, tip, feeCap int64,
	to []byte, value *big.Int, data []byte, gasLimit uint64) ([]byte, error) {
	// The nine signed fields, in EIP-1559 order. An empty access list is an empty RLP list.
	fields := [][]byte{
		rlpUint(big.NewInt(chainID)),
		rlpUint(new(big.Int).SetUint64(nonce)),
		rlpUint(big.NewInt(tip)),
		rlpUint(big.NewInt(feeCap)),
		rlpUint(new(big.Int).SetUint64(gasLimit)),
		rlpBytes(to),
		rlpUint(value),
		rlpBytes(data),
		rlpList(), // empty access list
	}

	// Signing hash is keccak256(0x02 || rlp(fields)).
	sigHash := keccak([]byte{eip1559TxType}, rlpList(fields...))

	// SignCompact gives a recoverable signature as [v | r | s] with v = 27 + recovery id for an
	// uncompressed key. EIP-1559 wants yParity, which is that recovery id. decred canonicalises
	// to low-S, which is what EIP-2 requires.
	compact := ecdsa.SignCompact(key, sigHash, false)
	if len(compact) != 65 {
		return nil, fmt.Errorf("unexpected compact signature length %d", len(compact))
	}
	yParity := int64(compact[0] - 27)
	if yParity != 0 && yParity != 1 {
		return nil, fmt.Errorf("unexpected recovery id %d", yParity)
	}
	r, s := compact[1:33], compact[33:65]

	signed := append(fields[:len(fields):len(fields)],
		rlpUint(big.NewInt(yParity)),
		rlpBytes(trimLeadingZeros(r)),
		rlpBytes(trimLeadingZeros(s)),
	)
	return append([]byte{eip1559TxType}, rlpList(signed...)...), nil
}

func parseQuantity(raw string) (*big.Int, bool) {
	base := 10
	text := raw
	if strings.HasPrefix(text, "0x") {
		base = 16
		text = strings.TrimPrefix(text, "0x")
	}
	if text == "" {
		return new(big.Int), true
	}
	n, ok := new(big.Int).SetString(text, base)
	return n, ok
}

func methodSelector(signature string) []byte {
	digest := keccak([]byte(signature))
	return append([]byte(nil), digest[:4]...)
}

func createAddressFor(from string, nonce uint64) string {
	address, err := hex.DecodeString(strings.TrimPrefix(from, "0x"))
	if err != nil || len(address) != 20 {
		fatal("invalid sender address %q", from)
	}
	raw := rlpList(rlpBytes(address), rlpUint(new(big.Int).SetUint64(nonce)))
	digest := keccak(raw)
	return "0x" + hex.EncodeToString(digest[len(digest)-20:])
}

func lockInitcodeBytes() []byte {
	// Runtime accepts native value and emits Locked(uint256) with msg.value as data.
	// The explicit init wrapper returns this exact runtime, including its event topic.
	topic := keccak([]byte("Locked(uint256)"))
	runtime := []byte{0x34, 0x60, 0x00, 0x52, 0x7f}
	runtime = append(runtime, topic...)
	runtime = append(runtime, 0x60, 0x20, 0x60, 0x00, 0xa1, 0x00)
	if len(runtime) > 255 {
		fatal("demo lock runtime is unexpectedly too large")
	}
	init := []byte{0x60, byte(len(runtime)), 0x60, 0x0c, 0x60, 0x00, 0x39,
		0x60, byte(len(runtime)), 0x60, 0x00, 0xf3}
	return append(init, runtime...)
}

func sendRaw(ethURL string, raw []byte) (string, error) {
	req, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction",
		"params": []string{"0x" + hex.EncodeToString(raw)},
	})
	if err != nil {
		return "", fmt.Errorf("encoding request: %w", err)
	}
	resp, err := http.Post(ethURL, "application/json", bytes.NewReader(req)) //nolint:gosec // test helper, operator-supplied local URL
	if err != nil {
		return "", fmt.Errorf("posting to %s: %w", ethURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	var out struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("decoding response %q: %w", body, err)
	}
	if out.Error != nil {
		if strings.Contains(strings.ToLower(out.Error.Message), "already known") {
			// This request carries the exact signed bytes, so its deterministic hash
			// makes transaction seeding safe to retry after an interrupted run.
			return "0x" + hex.EncodeToString(keccak(raw)), nil
		}
		return "", fmt.Errorf("eth_sendRawTransaction: %s", out.Error.Message)
	}
	if out.Result == "" {
		return "", fmt.Errorf("eth_sendRawTransaction returned no hash: %s", body)
	}
	return out.Result, nil
}

// --- minimal RLP (Ethereum Yellow Paper appendix B) -------------------------------------------

func rlpBytes(b []byte) []byte {
	switch {
	case len(b) == 1 && b[0] < 0x80:
		return b
	case len(b) <= 55:
		return append([]byte{byte(0x80 + len(b))}, b...)
	default:
		l := lengthBytes(len(b))
		out := append([]byte{byte(0xb7 + len(l))}, l...)
		return append(out, b...)
	}
}

func rlpList(items ...[]byte) []byte {
	var payload []byte
	for _, it := range items {
		payload = append(payload, it...)
	}
	if len(payload) <= 55 {
		return append([]byte{byte(0xc0 + len(payload))}, payload...)
	}
	l := lengthBytes(len(payload))
	out := append([]byte{byte(0xf7 + len(l))}, l...)
	return append(out, payload...)
}

// rlpUint encodes a non-negative integer as a minimal big-endian byte string; zero is the empty
// string, which is what RLP requires and what distinguishes it from a single zero byte.
func rlpUint(v *big.Int) []byte {
	if v.Sign() == 0 {
		return rlpBytes(nil)
	}
	return rlpBytes(v.Bytes())
}

func lengthBytes(n int) []byte {
	return new(big.Int).SetInt64(int64(n)).Bytes()
}

func trimLeadingZeros(b []byte) []byte {
	i := 0
	for i < len(b) && b[i] == 0 {
		i++
	}
	return b[i:]
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "evmtx: "+format+"\n", args...)
	os.Exit(1)
}
