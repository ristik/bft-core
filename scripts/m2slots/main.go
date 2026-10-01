package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	// root epoch, transition cursor, shard assignment epoch (layout 2 keeps the shard epoch unchanged on a
	// coupled configuration-only advance).
	fmt.Printf("%s %s %s\n", slot("assignment.rootEpoch"), slot("transition.cursor"), slot("assignment.epoch"))
}

func slot(name string) string {
	return crypto.Keccak256Hash([]byte("unicity.seal-registry.v1/" + name)).Hex()
}
