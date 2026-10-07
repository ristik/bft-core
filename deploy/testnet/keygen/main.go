// Disposable testnet faucet account. Secret output goes only into private files.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: keygen <new private directory>")
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
func must(err error) {
	if err != nil {
		panic(err)
	}
}
