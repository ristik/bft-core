package main

import (
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	// root epoch, transition cursor, shard assignment epoch (layout 2 keeps the shard epoch unchanged on a
	// coupled configuration-only advance).
	fmt.Printf("%s %s %s\n", slot("assignment.rootEpoch"), slot("transition.cursor"), slot("assignment.epoch"))
}

// slot is the storage key of a registry field: layout 2 names its slots under "unicity.seal-registry.v1/", the fresh-B1 registry (layout 3, H3_SLOT_LAYOUT=3)
// under "unicity.seal-registry/".
func slot(name string) string { return slotUnder(os.Getenv("H3_SLOT_LAYOUT"), name) }

func slotUnder(layout, name string) string {
	prefix := "unicity.seal-registry.v1/"
	if layout == "3" {
		prefix = "unicity.seal-registry/"
	}
	return crypto.Keccak256Hash([]byte(prefix + name)).Hex()
}
