package bridgeprofile

import (
	"bytes"
	stdcrypto "crypto"
	"fmt"
	"slices"
	"sort"

	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/b1ref"
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
// epoch (TrustInput.entryFor), with the seal's signatures judged by the B1
// profile rule (b1Seal), the rule the bridge contract and both SDKs apply.
func verifyNativeUC(entry *types.RootTrustBaseV2, uc *types.UnicityCertificate, partition types.PartitionID, shard types.ShardID, conf []byte) error {
	// routed through quorumweight.Checked like every production UC verification (it wraps only V1 trust bases; b1Seal's own
	// tally is overflow-checked)
	return uc.Verify(quorumweight.Checked(b1Seal{entry}), stdcrypto.SHA256, partition, shard, conf)
}

// b1Seal is a trust-base entry whose quorum check is the B1 profile seal rule:
// every supplied signature must be a member's and pass b1ref.CheckSealSignature
// (64 bytes or 65 with recovery byte 0/1, r and low s in range, compact
// verification of r||s), any other signer or signature fails the seal, and the
// valid signers' weights must reach the entry's threshold, overflow-checked.
// The entry's own check (65-byte recoverable signatures) is the native message
// rule, not the seal profile's (briefs/nbp-sdk-migration.md section 12).
type b1Seal struct{ *types.RootTrustBaseV2 }

func (s b1Seal) VerifyQuorumSignatures(data []byte, signatures map[string]hex.Bytes) error {
	ids := make([]string, 0, len(signatures))
	for id := range signatures {
		ids = append(ids, id)
	}
	sort.Strings(ids) // a deterministic error for a seal with several bad signatures
	var tally quorumweight.Tally
	for _, id := range ids {
		i := slices.IndexFunc(s.RootNodes, func(n *types.NodeInfo) bool { return n != nil && n.NodeID == id })
		if i < 0 {
			return fmt.Errorf("%w: %q", quorumweight.ErrUnknownSigner, id)
		}
		ver, err := s.RootNodes[i].SigVerifier()
		if err != nil {
			return fmt.Errorf("%w: %q: %v", quorumweight.ErrInvalidSignature, id, err)
		}
		if err := b1ref.CheckSealSignature(ver, signatures[id], data); err != nil {
			return fmt.Errorf("%w: %q: %w", quorumweight.ErrInvalidSignature, id, err)
		}
		if err := tally.Add(id, s.RootNodes[i].Stake); err != nil {
			return err
		}
	}
	if !tally.Reached(s.QuorumThreshold) {
		return fmt.Errorf("%w: signed weight %d, threshold %d", quorumweight.ErrQuorumNotReached, tally.Weight(), s.QuorumThreshold)
	}
	return nil
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
