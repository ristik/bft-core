package gettrustbase

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/utb"
)

// A complete release bundle is one Response with status OK, from = the genesis epoch, effectiveEnd = the release tip, endEntryID = EntryID(tip), every
// entry in ascending order and no cursor. It is the same object, tag and entry encoding as a page; only the size policy differs: peer pages are capped
// at 64 entries / 1 MiB, a bundle is bounded by an explicit budget the release supplies, never a fixed history length.

var (
	ErrBundle        = errors.New("gettrustbase: not a complete trust-base bundle")
	ErrBundleChain   = errors.New("gettrustbase: bundle history does not verify")
	ErrBundleInstall = errors.New("gettrustbase: bundle refused by the entry store")
)

// BundleLimits is the file budget, checked before allocation.
type BundleLimits struct {
	MaxBytes   int
	MaxEntries int
}

// Bundle is a decoded complete history.
type Bundle struct {
	Network types.NetworkID
	Raw     [][]byte // the canonical bytes of each entry, ascending from the genesis
	Entries []*types.RootTrustBaseV2
}

// Tip is the release tip.
func (b *Bundle) Tip() *types.RootTrustBaseV2 { return b.Entries[len(b.Entries)-1] }

// EncodeBundle packs the retained history (ascending, genesis first) into the one tagged response. It fails on a gap, a duplicate or a broken link
// rather than shortening the history.
func EncodeBundle(raw [][]byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: no entries", ErrBundle)
	}
	entries := make([]cbor.RawMessage, len(raw))
	for i, r := range raw {
		entries[i] = r
	}
	first, err := types.DecodeRootTrustBaseV2(raw[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBundle, err)
	}
	last, err := types.DecodeRootTrustBaseV2(raw[len(raw)-1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBundle, err)
	}
	id, err := last.EntryID()
	if err != nil {
		return nil, err
	}
	out, err := (&Response{Version: Version, Network: first.NetworkID, Status: StatusOK, FromEpoch: first.Epoch, EffectiveEnd: last.Epoch,
		EndEntryID: id[:], Entries: entries}).Encode()
	if err != nil {
		return nil, err
	}
	// the exporter proves what it wrote with the same decoder that loads it
	if _, err := DecodeBundle(out, BundleLimits{MaxBytes: len(out), MaxEntries: len(raw)}); err != nil {
		return nil, err
	}
	return out, nil
}

// DecodeBundle strictly decodes a complete bundle: status OK, starting at a genesis entry, no cursor, exactly effectiveEnd-genesis+1 consecutive
// entries linked by predecessor EntryID, ending at effectiveEnd with the matching endEntryID, nothing after. It checks structure and links, not
// signatures (see VerifyBundle); a final partial-range page is refused even though its cursor is null.
func DecodeBundle(data []byte, lim BundleLimits) (*Bundle, error) {
	resp, decoded, err := DecodeResponse(data, Limits{MaxBytes: lim.MaxBytes, MaxEntries: lim.MaxEntries})
	if err != nil {
		return nil, err
	}
	switch {
	case resp.Status != StatusOK:
		return nil, fmt.Errorf("%w: status %s", ErrBundle, resp.Status)
	case resp.NextEpoch != nil:
		return nil, fmt.Errorf("%w: a continuation cursor", ErrBundle)
	case !decoded[0].IsGenesis():
		return nil, fmt.Errorf("%w: epoch %d is not a genesis entry (a partial range)", ErrBundle, decoded[0].Epoch)
	}
	b := &Bundle{Network: resp.Network, Entries: decoded, Raw: make([][]byte, len(resp.Entries))}
	for i, e := range resp.Entries {
		b.Raw[i] = e
	}
	return b, nil
}

// VerifyBundle is the offline verifier: the genesis must be the pinned identity and every later entry must carry a strict quorum of its predecessor's
// members over its unsigned bytes. It needs no node, store or network.
func VerifyBundle(b *Bundle, pin [types.TrustBaseV2IDLen]byte) error {
	g := b.Entries[0]
	if err := g.VerifyGenesis(); err != nil {
		return fmt.Errorf("%w: %v", ErrBundleChain, err)
	}
	id, err := g.EntryID()
	if err != nil || id != pin {
		return fmt.Errorf("%w: the genesis is not the pinned identity", ErrBundleChain)
	}
	for i := 1; i < len(b.Entries); i++ {
		if len(b.Entries[i].RootNodes) > utb.MaxMembers {
			return fmt.Errorf("%w: epoch %d has %d members", ErrBundleChain, b.Entries[i].Epoch, len(b.Entries[i].RootNodes))
		}
		if err := b.Entries[i].VerifySuccessor(b.Entries[i-1]); err != nil {
			return fmt.Errorf("%w: epoch %d: %v", ErrBundleChain, b.Entries[i].Epoch, err)
		}
	}
	return nil
}

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
	return EncodeBundle(raw)
}

// Installer is a store that bundles load into. *utbstore.Store implements it.
type Installer interface {
	Append(b []byte) (bool, error)
}

// InstallBundle loads a decoded bundle into a store through Append, the only way in. On an empty store (genesis only) it installs the shipped
// history; on an existing store every overlapping epoch must be the held one (a different unsigned record is a conflict, an older bundle neither
// truncates history nor rolls the tip back) and each new entry is authenticated from the latest held entry. Entries are appended in order, so a refusal
// leaves the store at the last good entry. It returns the number of new entries.
func InstallBundle(s Installer, b *Bundle) (int, error) {
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
