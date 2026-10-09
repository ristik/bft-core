package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-core/b1registry"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
)

// Refusals of the deployed-genesis comparison, each named so a lane (and a test) can tell them apart.
var (
	ErrDeployedGenesis = errors.New("b1genesis verify: the deployed genesis is not a genesis JSON this tool can read")
	ErrDeployedAbsent  = errors.New("b1genesis verify: the deployed genesis has no registry account")
	ErrDeployedAccount = errors.New("b1genesis verify: the deployed registry account has a nonce or balance")
	ErrDeployedCode    = errors.New("b1genesis verify: the deployed registry code differs from the pinned runtime")
	ErrDeployedStorage = errors.New("b1genesis verify: the deployed registry storage differs from the regeneration")
	ErrRegeneratedCode = errors.New("b1genesis verify: the pinned runtime is not the one the profile commits to")
)

type deployedAccount struct {
	Balance string            `json:"balance"`
	Nonce   string            `json:"nonce"`
	Code    string            `json:"code"`
	Storage map[string]string `json:"storage"`
}

func hexBytes(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return hex.DecodeString(s)
}

func hexWord(s string) (common.Hash, error) {
	b, err := hexBytes(s)
	if err != nil || len(b) > 32 {
		return common.Hash{}, fmt.Errorf("%q is not a 32-byte word", s)
	}
	return common.BytesToHash(b), nil
}

// verifyDeployed compares the registry account of the DEPLOYED genesis (the chain spec the execution clients run) with a regeneration made from the pinned
// source: the runtime code byte for byte, and every storage word, none extra, none missing (a zero word is absent). It does not use the node's own
// validation (registrygenesis.B1Origin), which the caller runs as well: this comparison is the independent one.
func verifyDeployed(g *registrygenesis.Genesis, profileRuntimeHash [32]byte, deployed []byte) (words int, err error) {
	code, err := b1registry.Runtime()
	if err != nil {
		return 0, err
	}
	if crypto.Keccak256Hash(code) != common.Hash(profileRuntimeHash) {
		return 0, ErrRegeneratedCode
	}
	var spec struct {
		Alloc map[string]deployedAccount `json:"alloc"`
	}
	if err := json.Unmarshal(deployed, &spec); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrDeployedGenesis, err)
	}
	var acct *deployedAccount
	for k, v := range spec.Alloc {
		if common.HexToAddress(k) == registryproof.RegistryAddress {
			v := v
			acct = &v
			break
		}
	}
	if acct == nil {
		return 0, fmt.Errorf("%w: %s", ErrDeployedAbsent, registryproof.RegistryAddress)
	}
	if bal, ok := new(big.Int).SetString(strings.TrimPrefix(acct.Balance, "0x"), 16); acct.Balance != "" && (!ok || bal.Sign() != 0) {
		return 0, fmt.Errorf("%w: balance %s", ErrDeployedAccount, acct.Balance)
	}
	if n, ok := new(big.Int).SetString(strings.TrimPrefix(acct.Nonce, "0x"), 16); acct.Nonce != "" && (!ok || n.Sign() != 0) {
		return 0, fmt.Errorf("%w: nonce %s", ErrDeployedAccount, acct.Nonce)
	}
	got, err := hexBytes(acct.Code)
	if err != nil || !bytes.Equal(got, code) {
		return 0, fmt.Errorf("%w: %d bytes deployed, %d pinned", ErrDeployedCode, len(got), len(code))
	}
	want := map[common.Hash]common.Hash{}
	for k, v := range g.B1Words() {
		if v != (common.Hash{}) {
			want[k] = v
		}
	}
	have := map[common.Hash]common.Hash{}
	for k, v := range acct.Storage {
		key, kerr := hexWord(k)
		val, verr := hexWord(v)
		if kerr != nil || verr != nil {
			return 0, fmt.Errorf("%w: unreadable word %s=%s", ErrDeployedStorage, k, v)
		}
		if val != (common.Hash{}) {
			have[key] = val
		}
	}
	var diffs []string
	for k, v := range want {
		if h, ok := have[k]; !ok {
			diffs = append(diffs, fmt.Sprintf("missing %s", k.Hex()))
		} else if h != v {
			diffs = append(diffs, fmt.Sprintf("differs %s: deployed %s, regenerated %s", k.Hex(), h.Hex(), v.Hex()))
		}
	}
	for k := range have {
		if _, ok := want[k]; !ok {
			diffs = append(diffs, fmt.Sprintf("extra %s", k.Hex()))
		}
	}
	if len(diffs) != 0 {
		sort.Strings(diffs)
		return 0, fmt.Errorf("%w: %s", ErrDeployedStorage, strings.Join(diffs, "; "))
	}
	return len(want), nil
}
