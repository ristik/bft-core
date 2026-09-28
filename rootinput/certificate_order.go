package rootinput

import (
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
)

// CheckEpochCertificates applies the base certificate continuity rules with
// root rounds ordered within their signing epochs. An adjacent handoff may
// reset the scalar root round; partition state still has to extend normally.
func CheckEpochCertificates(previous, next *types.UnicityCertificate) error {
	if previous == nil || next == nil || previous.UnicitySeal == nil || next.UnicitySeal == nil {
		return fmt.Errorf("missing root certificate")
	}
	a, b := previous.GetRootEpoch(), next.GetRootEpoch()
	if b < a || b > a && (a == ^uint64(0) || b != a+1) || b == a && next.GetRootRoundNumber() < previous.GetRootRoundNumber() {
		return fmt.Errorf("non-contiguous root certificate epochs or rounds")
	}
	if b == a {
		return types.CheckNonEquivocatingCertificates(previous, next)
	}
	oldCopy, newCopy := *previous, *next
	oldSeal, newSeal := *previous.UnicitySeal, *next.UnicitySeal
	oldSeal.RootChainRoundNumber, newSeal.RootChainRoundNumber = 0, 0
	oldCopy.UnicitySeal, newCopy.UnicitySeal = &oldSeal, &newSeal
	return types.CheckNonEquivocatingCertificates(&oldCopy, &newCopy)
}
