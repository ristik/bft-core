// Command h3slots prints the sealRegistry/v2 storage slots the H3 lane reads over eth_getStorageAt:
// shard epoch, root epoch, active configuration hash and transition cursor.
package main

import (
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	// sealRegistry/v2 names its slots under "unicity.seal-registry.v1/"; the fresh-B1 registry (layout 3) under "unicity.seal-registry/"
	prefix := "unicity.seal-registry.v1/"
	if os.Getenv("H3_SLOT_LAYOUT") == "3" {
		prefix = "unicity.seal-registry/"
	}
	for _, name := range []string{"assignment.epoch", "assignment.rootEpoch", "assignment.activeConfHash", "transition.cursor"} {
		fmt.Printf("%s ", crypto.Keccak256Hash([]byte(prefix+name)).Hex())
	}
	fmt.Println()
}
