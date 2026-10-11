// Disposable testnet faucet account. Secret output goes only into private files.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	if len(os.Args) != 2 {
		panic("usage: keygen <new private directory> | keygen address <key file> | keygen owners <new private directory> <identities>")
	}
	dir := os.Args[1]
	must(os.Mkdir(dir, 0700))
	key, err := crypto.GenerateKey()
	must(err)
	password := make([]byte, 32)
	_, err = rand.Read(password)
	must(err)
	pass := hex.EncodeToString(password)
	address := crypto.PubkeyToAddress(key.PublicKey)
	data, err := keystore.EncryptKey(&keystore.Key{Id: uuid.New(), Address: address, PrivateKey: key}, pass, keystore.StandardScryptN, keystore.StandardScryptP)
	must(err)
	must(os.WriteFile(filepath.Join(dir, "keystore.json"), data, 0600))
	must(os.WriteFile(filepath.Join(dir, "password"), []byte(pass), 0600))
	// Fresh genesis funds only this random account, never the public Hardhat key.
	alloc := map[string]any{address.Hex(): map[string]string{"balance": "1000000000000000000000"}}
	must(json.NewEncoder(os.Stdout).Encode(alloc))
}

// owners writes one secp256k1 key per role (owner, withdrawal, payee) of each genesis identity of the PoS profile, as hex private keys in 0600 files under a new 0700
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
			must(os.WriteFile(filepath.Join(sub, role+".key"), []byte(hex.EncodeToString(crypto.FromECDSA(key))+"\n"), 0600))
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
