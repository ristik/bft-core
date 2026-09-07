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
		alloc   = flag.Bool("alloc", false, "print a genesis alloc object funding the test account")
		send    = flag.Bool("send", false, "sign a transfer and submit it with eth_sendRawTransaction")
		ethURL  = flag.String("eth-url", "http://127.0.0.1:8545", "eth_* endpoint")
		chainID = flag.Int64("chain-id", 31337, "chain id to sign for")
		nonce   = flag.Uint64("nonce", 0, "sender nonce")
		tip     = flag.Int64("tip", 1_000_000_000, "maxPriorityFeePerGas in wei")
		feeCap  = flag.Int64("fee-cap", 10_000_000_000, "maxFeePerGas in wei")
	)
	flag.Parse()

	keyBytes, err := hex.DecodeString(testKeyHex)
	if err != nil {
		fatal("decoding the test key: %v", err)
	}
	key := secp256k1.PrivKeyFromBytes(keyBytes)
	from := addressOf(key)

	switch {
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
		raw, err := signTx(key, *chainID, *nonce, *tip, *feeCap)
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
func signTx(key *secp256k1.PrivateKey, chainID int64, nonce uint64, tip, feeCap int64) ([]byte, error) {
	to, err := hex.DecodeString("00000000000000000000000000000000000000ff")
	if err != nil {
		return nil, fmt.Errorf("decoding recipient: %w", err)
	}

	// The nine signed fields, in EIP-1559 order. An empty access list is an empty RLP list.
	fields := [][]byte{
		rlpUint(big.NewInt(chainID)),
		rlpUint(new(big.Int).SetUint64(nonce)),
		rlpUint(big.NewInt(tip)),
		rlpUint(big.NewInt(feeCap)),
		rlpUint(big.NewInt(21000)), // a plain transfer
		rlpBytes(to),
		rlpUint(big.NewInt(1)), // 1 wei, so the transfer is real but trivially affordable
		rlpBytes(nil),          // no calldata
		rlpList(),              // empty access list
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
