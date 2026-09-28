package main

import (
	"fmt"
	"github.com/unicitynetwork/bft-core/registryproof"
)

func main() {
	fmt.Printf("%s %s\n", registryproof.SlotKey(4).Hex(), registryproof.SlotKey(20).Hex())
}
