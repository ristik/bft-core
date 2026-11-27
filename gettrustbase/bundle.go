package gettrustbase

import (
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
)

// The complete release bundle (encode, decode, offline verification) is bft-go-base's: types.EncodeTrustBaseBundle, types.DecodeTrustBaseBundle and
// types.VerifyTrustBaseBundle. What stays here is the orchestration over the entry store.

// ErrBundleInstall is a bundle refused by the entry store.
var ErrBundleInstall = errors.New("gettrustbase: bundle refused by the entry store")

// ExportStore writes the store's entire retained history as one bundle.
func ExportStore(s Source) ([]byte, error) {
	tip := s.Tip()
	var raw [][]byte
	for from := s.GenesisEpoch(); ; {
		page, next, more, err := s.Range(from, tip.Epoch, 1<<16, 1<<30)
		if err != nil {
			return nil, fmt.Errorf("exporting from epoch %d: %w", from, err)
		}
		raw = append(raw, page...)
		if !more {
			break
		}
		from = next
	}
	return types.EncodeTrustBaseBundle(raw)
}

// Installer is a store that bundles load into. *utbstore.Store implements it.
type Installer interface {
	Append(b []byte) (bool, error)
}

// InstallBundle loads a decoded bundle into a store through Append, the only way in. On an empty store (genesis only) it installs the shipped
// history; on an existing store every overlapping epoch must be the held one (a different unsigned record is a conflict, an older bundle neither
// truncates history nor rolls the tip back) and each new entry is authenticated from the latest held entry. Entries are appended in order, so a refusal
// leaves the store at the last good entry. It returns the number of new entries.
func InstallBundle(s Installer, b *types.TrustBaseBundle) (int, error) {
	added := 0
	for i, raw := range b.Raw {
		isNew, err := s.Append(raw)
		if err != nil {
			return added, fmt.Errorf("%w: epoch %d: %w", ErrBundleInstall, b.Entries[i].Epoch, err)
		}
		// not new: the store checked it is the held record's EntryID with a valid witness and kept the first stored witness
		if isNew {
			added++
		}
	}
	return added, nil
}
