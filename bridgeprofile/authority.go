package bridgeprofile

import (
	"bytes"
	stdcrypto "crypto"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/gettrustbase"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
)

// This file isolates the trust-authority decisions, so each changes in exactly
// one place. The trust input is the network's Unicity Trust Base history (the
// same release bundle and genesis pin the state-transition SDKs install); the
// profile builds no bridge-private epoch bundle and no bridge-owned weighted
// verifier.

// verifyNativeUC is the Go SDK's UC verification (input record, shard and
// unicity trees, seal hash) under entry, the trust-base entry of the seal's
// epoch (TrustInput.entryFor), with the seal's signatures judged by the seal
// rule, the upstream rule: quorumweight.Checked wraps the entry in the seal
// quorum (unknown signers and signatures that do not recover to their member
// contribute zero, valid weights are summed overflow-checked and must reach the
// entry's threshold). This is the same function every other UC verification of
// the repository uses, so a seal has one verdict standalone, token-carried,
// backing or grouped. The entry's own VerifyQuorumSignatures, the strict check
// of a successor entry, is not used for seals.
func verifyNativeUC(entry *types.RootTrustBaseV2, uc *types.UnicityCertificate, partition types.PartitionID, shard types.ShardID, conf []byte) error {
	return uc.Verify(quorumweight.Checked(entry), stdcrypto.SHA256, partition, shard, conf)
}

// TrustInput is the network's Unicity Trust Base history, installed from a
// release bundle (tag 39015: the genesis entry and every later entry, each
// witnessed by its predecessor's committee) and pinned by the EntryID of its
// genesis entry. trustBaseId is that EntryID: a lock proof names it, and two
// histories are the same trust input exactly when they have the same genesis.
// A certificate is verified under the entry of its own seal epoch, within that
// epoch's root-round interval [start_e, start_e+1).
type TrustInput struct {
	Bundle  []byte
	Entries []*types.RootTrustBaseV2 // ascending from the genesis
	id      [32]byte
}

// ID is trustBaseId: the genesis EntryID.
func (t *TrustInput) ID() [32]byte { return t.id }

// Network is the history's network.
func (t *TrustInput) Network() types.NetworkID { return t.Entries[0].NetworkID }

// Tip is the latest held entry.
func (t *TrustInput) Tip() *types.RootTrustBaseV2 { return t.Entries[len(t.Entries)-1] }

// trustBundleLimits is the installation budget of a release bundle.
var trustBundleLimits = gettrustbase.BundleLimits{MaxBytes: 1 << 20, MaxEntries: 1 << 16}

// LoadTrustInput installs a release bundle under the pinned genesis EntryID:
// complete (no continuation), contiguous from its genesis, every link witnessed
// by the predecessor's strict quorum. A bundle whose genesis is another is
// ErrTrustBaseDigest; anything else that does not install is ErrTrustBase.
func LoadTrustInput(bundle []byte, pin [32]byte) (*TrustInput, error) {
	b, err := gettrustbase.DecodeBundle(bundle, trustBundleLimits)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrustBase, err)
	}
	if id, err := b.Entries[0].EntryID(); err != nil || id != pin {
		return nil, ErrTrustBaseDigest
	}
	if err := gettrustbase.VerifyBundle(b, pin); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrustBase, err)
	}
	return &TrustInput{Bundle: bytes.Clone(bundle), Entries: b.Entries, id: pin}, nil
}

// TrustBundle encodes entries (ascending from a genesis) as a release bundle.
func TrustBundle(entries ...*types.RootTrustBaseV2) ([]byte, error) {
	var raw [][]byte
	for _, e := range entries {
		b, err := types.Cbor.Marshal(e)
		if err != nil {
			return nil, err
		}
		raw = append(raw, b)
	}
	return gettrustbase.EncodeBundle(raw)
}

// entryFor selects the entry of the seal's epoch: another network is
// ErrSealNetwork; an epoch newer than the latest held one is
// ErrNoEntryForEpoch (retryable once the history holds it); an epoch before
// the genesis, or a root round outside the epoch's interval, is ErrSealEpoch.
func (t *TrustInput) entryFor(seal *types.UnicitySeal) (*types.RootTrustBaseV2, error) {
	if seal == nil || seal.NetworkID != t.Network() {
		return nil, ErrSealNetwork
	}
	genesis, tip := t.Entries[0].Epoch, t.Tip().Epoch
	switch {
	case seal.Epoch > tip:
		return nil, ErrNoEntryForEpoch
	case seal.Epoch < genesis:
		return nil, ErrSealEpoch
	}
	i := seal.Epoch - genesis
	e := t.Entries[i]
	if seal.RootChainRoundNumber < e.EpochStart || (i+1 < uint64(len(t.Entries)) && seal.RootChainRoundNumber >= t.Entries[i+1].EpochStart) {
		return nil, ErrSealEpoch
	}
	return e, nil
}

// checkTrust binds the proof to the installed history (its trustBaseId is the
// history's genesis) and returns the entry the certificate is verified under.
func checkTrust(p *LockProof, t *TrustInput, uc *types.UnicityCertificate) (*types.RootTrustBaseV2, error) {
	if t == nil || len(t.Entries) == 0 || p.TrustBaseID != t.ID() {
		return nil, ErrTrustBaseDigest
	}
	return t.entryFor(uc.UnicitySeal)
}
