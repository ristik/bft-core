package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	fmt.Printf("%s %s\n", slot("assignment.rootEpoch"), slot("transition.cursor"))
}

func slot(name string) string {
	return crypto.Keccak256Hash([]byte("unicity.seal-registry.v1/" + name)).Hex()
}
