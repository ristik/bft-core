//go:build vrdev

package consensus

import (
	"os"
	"strings"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
)

// maxDevExtras bounds each extra list.
const maxDevExtras = 4

// Development-only knobs, compiled into a binary only with the vrdev build tag (the VR lane builds with it; a production build never has them,
// and no flag or environment variable can turn them on in one).

// devStagedExtras adds extra staged roots and EVM nodes named by UBFT_VR_DEV_STAGE_EXTRA_ROOTS and _EVM (scripts/vr-joiner-steps.sh): they let a
// joiner's following of the committed chain be tried before the Foundation's governance delays allow an admission.
func devStagedExtras(ids []evmassign.Identity, roots []evmroot.Member) ([]evmassign.Identity, []evmroot.Member) {
	for i, id := range strings.Split(os.Getenv("UBFT_VR_DEV_STAGE_EXTRA_ROOTS"), ",") {
		if id != "" && i < maxDevExtras {
			roots = append(roots[:len(roots):len(roots)], evmroot.Member{NodeID: id, StakingID: id, Weight: 1})
		}
	}
	for i, id := range strings.Split(os.Getenv("UBFT_VR_DEV_STAGE_EXTRA_EVM"), ",") {
		if id != "" && i < maxDevExtras {
			ids = append(ids[:len(ids):len(ids)], evmassign.Identity{EVMNodeID: id})
		}
	}
	return ids, roots
}
