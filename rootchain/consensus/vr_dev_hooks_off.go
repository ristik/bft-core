//go:build !vrdev

package consensus

import (
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
)

// devStagedExtras is the development staging hook of the vrdev build; a production build has none.
func devStagedExtras(ids []evmassign.Identity, roots []evmroot.Member) ([]evmassign.Identity, []evmroot.Member) {
	return ids, roots
}

// devShardExtras is the development hook of the vrdev build; a production build has none.
func devShardExtras(ids []string) []string { return ids }
