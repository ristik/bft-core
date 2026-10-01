// Command h3slots prints the sealRegistry/v2 storage slots the H3 lane reads over eth_getStorageAt:
// shard epoch, root epoch, active configuration hash and transition cursor.
package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	for _, name := range []string{"assignment.epoch", "assignment.rootEpoch", "assignment.activeConfHash", "transition.cursor"} {
		fmt.Printf("%s ", crypto.Keccak256Hash([]byte("unicity.seal-registry.v1/"+name)).Hex())
	}
	fmt.Println()
}
