package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/unicitynetwork/bft-core/nb2ref"
)

// The reference side of the NB2-09 (bft-core#1105) live run: Γ built by the Go reference (the deployment encodes exactly these bytes, and the
// vault constructor and the TypeScript plug-in must accept them), and the reference verifier's verdict on live evidence, which the run compares
// byte for byte with the deployed Solidity verifier's and the plug-in's.

// readBytes reads a file holding raw bytes or their hex (with or without 0x).
func readBytes(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if t := strings.TrimPrefix(strings.TrimSpace(string(raw)), "0x"); len(t)%2 == 0 {
		if b, err := hex.DecodeString(t); err == nil {
			return b, nil
		}
	}
	return raw, nil
}

func fixed32(name, s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("-%s must be 32 bytes of hex", name)
	}
	copy(out[:], b)
	return out, nil
}

func fixed20(name, s string) ([20]byte, error) {
	if !common.IsHexAddress(s) {
		return [20]byte{}, fmt.Errorf("-%s must be an address", name)
	}
	return common.HexToAddress(s), nil
}

// gammaJSON is the field view of Γ (hex byte strings, decimal integers).
type gammaJSON struct {
	Gamma               string `json:"gamma"`
	Domain              string `json:"domain"`
	Network             uint16 `json:"network"`
	RootGenesis         string `json:"rootGenesis"`
	ExecutionGenesis    string `json:"executionGenesis"`
	ChainID             uint64 `json:"chainId"`
	EVMPartition        uint32 `json:"evmPartition"`
	EVMShard            string `json:"evmShard"`
	AggregatorPartition uint32 `json:"aggregatorPartition"`
	Vault               string `json:"vault"`
	Asset               string `json:"asset"`
	Ty                  string `json:"ty"`
	Aid                 string `json:"aid"`
	SemanticProfileHash string `json:"semanticProfileHash"`
	Verifier            string `json:"verifier"`
	VerifierCodeHash    string `json:"verifierCodeHash"`
	K                   uint64 `json:"K"`
	B                   uint64 `json:"B"`
	Qmax                string `json:"Qmax"`
	Build               string `json:"build"`
}

func hx(b []byte) string { return "0x" + hex.EncodeToString(b) }

func viewOf(c *nb2ref.Config) gammaJSON {
	g := c.Bytes()
	d := c.Domain()
	return gammaJSON{
		Gamma: hx(g), Domain: hx(d[:]), Network: c.Network, RootGenesis: hx(c.RootGenesis[:]), ExecutionGenesis: hx(c.ExecutionGenesis[:]),
		ChainID: c.ChainID, EVMPartition: c.EVMPartition, EVMShard: hx(c.EVMShard), AggregatorPartition: c.AggregatorPartition,
		Vault: hx(c.Vault[:]), Asset: hx(c.Asset[:]), Ty: hx(c.Ty[:]), Aid: hx(c.Aid[:]), SemanticProfileHash: hx(c.SemanticProfileHash[:]),
		Verifier: hx(c.Verifier[:]), VerifierCodeHash: hx(c.VerifierCodeHash[:]), K: c.K, B: c.B, Qmax: c.Qmax.String(), Build: nb2ref.BuildOf(c.K),
	}
}

func gammaCmd(args []string) error {
	fs := flag.NewFlagSet("gamma", flag.ContinueOnError)
	decode := fs.String("decode", "", "decode this encoded Γ (raw or hex) instead of building one")
	network := fs.Uint("network", 0, "α, the SDK network ID")
	rootGenesis := fs.String("root-genesis", "", "g_root: the genesis EntryID of the trust-base history")
	execGenesis := fs.String("execution-genesis", "", "g_evm: the EVM genesis block hash")
	chainID := fs.Uint64("chain-id", 0, "the EVM chain ID")
	evmPartition := fs.Uint("evm-partition", 8, "β_evm")
	evmShard := fs.String("evm-shard", "0x80", "the EVM shard's canonical native shard ID, hex")
	aggPartition := fs.Uint("aggregator-partition", 7, "β_agg")
	vault := fs.String("vault", "", "a_V: the vault's (predicted) address")
	verifier := fs.String("verifier", "", "the token verifier's address")
	verifierCodeHash := fs.String("verifier-code-hash", "", "EXTCODEHASH of the verifier")
	profileHash := fs.String("profile-hash", "", "SHA-256 of the exact bytes of the plug-ins' protocol/profile.json")
	k := fs.Uint64("k", 64, "K")
	b := fs.Uint64("b", 16, "B")
	qmax := fs.String("qmax", "", "Qmax, decimal")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *decode != "" {
		raw, err := readBytes(*decode)
		if err != nil {
			return err
		}
		c, err := nb2ref.DecodeConfig(raw, nb2ref.BuildParams(buildOfGamma(raw)))
		if err != nil {
			return fmt.Errorf("%s: %w", nb2ref.RuleName(err), err)
		}
		return json.NewEncoder(os.Stdout).Encode(viewOf(c))
	}
	c := &nb2ref.Config{ChainID: *chainID, EVMPartition: uint32(*evmPartition), AggregatorPartition: uint32(*aggPartition), K: *k, B: *b, Asset: nb2ref.AssetUCT}
	if *network == 0 || *network > 65535 {
		return errors.New("-network must be 1..65535")
	}
	c.Network = uint16(*network)
	var err error
	if c.RootGenesis, err = fixed32("root-genesis", *rootGenesis); err != nil {
		return err
	}
	if c.ExecutionGenesis, err = fixed32("execution-genesis", *execGenesis); err != nil {
		return err
	}
	if c.EVMShard, err = hex.DecodeString(strings.TrimPrefix(*evmShard, "0x")); err != nil {
		return fmt.Errorf("-evm-shard: %w", err)
	}
	if c.Vault, err = fixed20("vault", *vault); err != nil {
		return err
	}
	if c.Verifier, err = fixed20("verifier", *verifier); err != nil {
		return err
	}
	if c.VerifierCodeHash, err = fixed32("verifier-code-hash", *verifierCodeHash); err != nil {
		return err
	}
	if c.SemanticProfileHash, err = fixed32("profile-hash", *profileHash); err != nil {
		return err
	}
	q, ok := new(big.Int).SetString(*qmax, 10)
	if !ok {
		return errors.New("-qmax must be a decimal integer")
	}
	c.Qmax = q
	c.Ty = nb2ref.DeriveType(c.Network, c.RootGenesis, c.ExecutionGenesis, c.ChainID)
	c.Aid = nb2ref.DeriveCoin(c.Network, c.RootGenesis, c.ExecutionGenesis, c.ChainID)
	// the encoding must be one the reference itself accepts (widths, ranges, the build's admitted (K, B))
	if _, err := nb2ref.DecodeConfig(c.Bytes(), nb2ref.BuildParams(nb2ref.BuildOf(c.K))); err != nil {
		return fmt.Errorf("%s: %w", nb2ref.RuleName(err), err)
	}
	return json.NewEncoder(os.Stdout).Encode(viewOf(c))
}

// buildOfGamma picks the build whose admitted set holds Γ's K, so that decoding reports the real refusal rather than the build's.
func buildOfGamma(raw []byte) string {
	if _, err := nb2ref.DecodeConfig(raw, nb2ref.TestParams); err == nil {
		return "test"
	}
	return "production"
}

// returnResult is one line of verify-return.
type returnResult struct {
	File    string `json:"file"`
	Verdict string `json:"verdict,omitempty"` // the 192-byte verdict ABI
	Rule    string `json:"rule,omitempty"`    // the section 14 rule that refuses it
	Error   string `json:"error,omitempty"`
}

func verifyReturnCmd(args []string) error {
	fs := flag.NewFlagSet("verify-return", flag.ContinueOnError)
	gammaPath := fs.String("gamma", "", "Γ (raw or hex)")
	bundlePath := fs.String("trust-bundle", "", "the trust-base history bundle (tag 39015)")
	pinText := fs.String("pin", "", "its genesis EntryID (Γ.rootGenesis32), hex or a file holding it")
	build := fs.String("build", "", "test|production (default: the build that admits Γ's K)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	gamma, err := readBytes(*gammaPath)
	if err != nil {
		return err
	}
	bundle, err := os.ReadFile(*bundlePath)
	if err != nil {
		return err
	}
	pinHex := *pinText
	if b, err := os.ReadFile(pinHex); err == nil {
		pinHex = string(b)
	}
	pin, err := fixed32("pin", pinHex)
	if err != nil {
		return err
	}
	trust, err := nb2ref.LoadTrustInput(bundle, pin)
	if err != nil {
		return err
	}
	b := *build
	if b == "" {
		b = buildOfGamma(gamma)
	}
	enc := json.NewEncoder(os.Stdout)
	for _, path := range fs.Args() {
		res := returnResult{File: path}
		ev, err := readBytes(path)
		if err != nil {
			return err
		}
		v, err := nb2ref.VerifyReturn(gamma, ev, trust, nb2ref.BuildParams(b))
		if err != nil {
			res.Rule, res.Error = nb2ref.RuleName(err), err.Error()
		} else {
			res.Verdict = hx(v.ABI())
		}
		if err := enc.Encode(res); err != nil {
			return err
		}
	}
	return nil
}
