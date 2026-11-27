// Disposable testnet faucet account. Secret output goes only into private files.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
)

func main() {
	if len(os.Args) == 4 && os.Args[1] == "owners" {
		owners(os.Args[2], os.Args[3])
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "address" {
		// the address of a hex private key file, read from the file so the key never appears in a process list
		raw, err := os.ReadFile(os.Args[2])
		must(err)
		key, err := crypto.HexToECDSA(strings.TrimPrefix(strings.TrimSpace(string(raw)), "0x"))
		must(err)
		fmt.Println(crypto.PubkeyToAddress(key.PublicKey).Hex())
		return
	}
	if len(os.Args) != 2 && len(os.Args) != 3 {
		panic("usage: keygen <new private directory> [<genesis balance, wei>] | keygen address <key file> | keygen owners <new private directory> <identities>")
	}
	balance := DefaultFaucetBalanceWei
	if len(os.Args) == 3 {
		balance = os.Args[2]
	}
	must(faucet(os.Args[1], balance, os.Stdout))
}

// DefaultFaucetBalanceWei is the faucet account's genesis balance when generate.py names none: 50,000 UCT, 250 claims at the package's default payout of
// 200 UCT (5 days at its default 50 claims a day).
const DefaultFaucetBalanceWei = "50000000000000000000000"

// faucet makes the faucet account in a new 0700 directory (its keystore and password in 0600 files) and writes the genesis alloc that funds it with
// balanceWei (a positive decimal integer, wei) to out.
func faucet(dir, balanceWei string, out io.Writer) error {
	balance, ok := new(big.Int).SetString(balanceWei, 10)
	if !ok || balance.Sign() <= 0 || balance.String() != balanceWei {
		return fmt.Errorf("faucet balance must be a positive decimal number of wei, got %q", balanceWei)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	password := make([]byte, 32)
	if _, err = rand.Read(password); err != nil {
		return err
	}
	pass := hex.EncodeToString(password)
	address := crypto.PubkeyToAddress(key.PublicKey)
	data, err := keystore.EncryptKey(&keystore.Key{Id: uuid.New(), Address: address, PrivateKey: key}, pass, keystore.StandardScryptN, keystore.StandardScryptP)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "keystore.json"), data, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "password"), []byte(pass), 0600); err != nil {
		return err
	}
	// Fresh genesis funds only this random account, never the public Hardhat key.
	alloc := map[string]any{address.Hex(): map[string]string{"balance": balance.String()}}
	return json.NewEncoder(out).Encode(alloc)
}

// owners writes one secp256k1 key per role (owner, withdrawal, payee) of each genesis identity of the PoS profile, as 0x-prefixed hex private keys (the form `ubft pos-relayer --sender-key` reads) in 0600 files under a new 0700
// directory, and prints only the addresses (JSON) for the genesis plan. The keys are never part of the shipped network files.
func owners(dir, count string) {
	n, err := strconv.Atoi(count)
	must(err)
	must(os.Mkdir(dir, 0700))
	var identities []map[string]any
	for i := 1; i <= n; i++ {
		identity := map[string]any{"stakingId": i}
		sub := filepath.Join(dir, fmt.Sprintf("identity-%d", i))
		must(os.Mkdir(sub, 0700))
		for _, role := range []string{"owner", "withdrawal", "payee"} {
			key, err := crypto.GenerateKey()
			must(err)
			must(os.WriteFile(filepath.Join(sub, role+".key"), []byte("0x"+hex.EncodeToString(crypto.FromECDSA(key))+"\n"), 0600))
			identity[role] = crypto.PubkeyToAddress(key.PublicKey).Hex()
		}
		identities = append(identities, identity)
	}
	must(json.NewEncoder(os.Stdout).Encode(identities))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
