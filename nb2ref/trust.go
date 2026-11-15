package nb2ref

import (
	"bytes"
	stdcrypto "crypto"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
)

// Historical authority (section 11.3), from bridgeprofile/authority.go and certscan.go. The trust input is the network's
// Unicity Trust Base history: a release bundle (tag 39015) of the genesis entry and every later entry, each witnessed by its
// predecessor's committee, pinned by the genesis EntryID (Γ.rootGenesis32). Every UC is judged under the entry of its own
// seal epoch by the upstream seal rule: each signature alone, an exact canonical 65-byte recoverable signature of a member
// counts its weight, anything else counts zero, and the weights reach floor(2W/3)+1 of that entry.

// TrustInput is an installed trust-base history.
type TrustInput struct {
	Bundle  []byte
	Entries []*types.RootTrustBaseV2 // ascending from the genesis
	id      [32]byte
}

// ID is the genesis EntryID.
func (t *TrustInput) ID() [32]byte { return t.id }

// Network is the history's network.
func (t *TrustInput) Network() types.NetworkID { return t.Entries[0].NetworkID }

var trustBundleLimits = types.TrustBaseLimits{MaxBytes: 1 << 20, MaxEntries: 1 << 16}

// LoadTrustInput installs a release bundle under its pinned genesis EntryID.
func LoadTrustInput(bundle []byte, pin [32]byte) (*TrustInput, error) {
	b, err := types.DecodeTrustBaseBundle(bundle, trustBundleLimits)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrustInput, err)
	}
	if id, err := b.Entries[0].EntryID(); err != nil || id != pin {
		return nil, fmt.Errorf("%w: genesis EntryID", ErrTrustInput)
	}
	if err := types.VerifyTrustBaseBundle(b, pin); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrustInput, err)
	}
	return &TrustInput{Bundle: bytes.Clone(bundle), Entries: b.Entries, id: pin}, nil
}

// TrustBundle encodes entries (a genesis first) as a release bundle.
func TrustBundle(entries ...*types.RootTrustBaseV2) ([]byte, error) {
	var raw [][]byte
	for _, e := range entries {
		b, err := types.Cbor.Marshal(e)
		if err != nil {
			return nil, err
		}
		raw = append(raw, b)
	}
	return types.EncodeTrustBaseBundle(raw)
}

// bind requires the history to be the one Γ names.
func (t *TrustInput) bind(c *Config) error {
	if t == nil || len(t.Entries) == 0 || t.id != c.RootGenesis || uint16(t.Network()) != c.Network {
		return ErrTrustInput
	}
	return nil
}

// entryFor selects the entry of the seal's epoch: another network is SealNetwork; an epoch after the latest held entry is
// NoEntryForEpoch (retryable); an epoch before the genesis, or a root round outside the epoch's interval
// [start_e, start_{e+1}), is SealEpoch.
func (t *TrustInput) entryFor(seal *types.UnicitySeal) (*types.RootTrustBaseV2, error) {
	if seal == nil || seal.NetworkID != t.Network() {
		return nil, ErrSealNetwork
	}
	genesis, tip := t.Entries[0].Epoch, t.Entries[len(t.Entries)-1].Epoch
	switch {
	case seal.Epoch > tip:
		return nil, ErrNoEntryForEpoch
	case seal.Epoch < genesis:
		return nil, ErrSealEpoch
	}
	i := seal.Epoch - genesis
	e := t.Entries[i]
	if seal.RootChainRoundNumber < e.EpochStart || (i+1 < uint64(len(t.Entries)) && seal.RootChainRoundNumber >= t.Entries[i+1].EpochStart) {
		if err := fail(ErrSealEpoch); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// decodeUC is the bounded certificate scan (the native shape scan intersected with the SDK codec subset, before any
// allocation proportional to its contents or cryptography) and the canonical decode. Every failure is
// UnsupportedCertificateEncoding.
func decodeUC(raw []byte) (*types.UnicityCertificate, error) {
	if err := scanCertificate(raw); err != nil {
		return nil, wrap(ErrUnsupportedCertificateEncoding, err)
	}
	var uc types.UnicityCertificate
	if err := types.Cbor.Unmarshal(raw, &uc); err != nil {
		return nil, wrap(ErrUnsupportedCertificateEncoding, err)
	}
	again, err := types.Cbor.Marshal(&uc)
	if err != nil || !bytes.Equal(again, raw) || uc.InputRecord == nil || uc.UnicitySeal == nil {
		return nil, detail(ErrUnsupportedCertificateEncoding, "noncanonical or incomplete")
	}
	return &uc, nil
}

// ucCheck is one UC verification: the entry of its seal epoch, its structure for the expected partition and shard
// (CertStructure), the shard and unicity tree folds to the seal hash (SealRoot) and the seal quorum under that entry
// (QuorumNotMet).
func (t *TrustInput) ucCheck(uc *types.UnicityCertificate, partition types.PartitionID, shard types.ShardID) error {
	entry, err := t.entryFor(uc.UnicitySeal)
	if err != nil {
		return err
	}
	// No expected configuration hash is supplied (nil), but the UC's own 32-byte ShardConfHash stays inside the authenticated
	// shard-tree leaf below, with its InputRecord and TRHash.
	if err := uc.IsValid(partition, shard, nil); err != nil || len(uc.ShardConfHash) != 32 {
		if e := failf(ErrCertStructure, "%v", err); e != nil {
			return e
		}
	}
	str, err := uc.ShardTreeCertificate.ComputeCertificateHash(uc.InputRecord, uc.TRHash, uc.ShardConfHash, stdcrypto.SHA256)
	if err != nil {
		return failf(ErrCertStructure, "%v", err)
	}
	utr, err := uc.UnicityTreeCertificate.EvalAuthPath(str, stdcrypto.SHA256)
	if err != nil {
		return failf(ErrCertStructure, "%v", err)
	}
	if !bytes.Equal(utr, uc.UnicitySeal.Hash) {
		if err := fail(ErrSealRoot); err != nil {
			return err
		}
	}
	if err := uc.UnicitySeal.Verify(quorumweight.Checked(entry)); err != nil {
		return failf(ErrQuorumNotMet, "%v", err)
	}
	return nil
}

// VerifyEVMUC verifies a deposit or seal receipt's EVM certificate for exactly (evmPartition, evmShard), with no expected
// configuration hash. Every failure is DepositUC (encoding, network, epoch interval, structure, partition, shard, folds,
// quorum) except NoEntryForEpoch, which keeps its retryable name.
func (t *TrustInput) VerifyEVMUC(raw []byte, c *Config) (*types.UnicityCertificate, error) {
	uc, err := decodeUC(raw)
	if err != nil {
		return nil, wrap(ErrDepositUC, err)
	}
	var shard types.ShardID
	if err := shard.UnmarshalText([]byte(fmt.Sprintf("0x%x", c.EVMShard))); err != nil || !bytes.Equal(shard.Bytes(), c.EVMShard) {
		return nil, ErrDepositUC
	}
	if err := t.ucCheck(uc, types.PartitionID(c.EVMPartition), shard); err != nil {
		if RuleOf(err) == ErrNoEntryForEpoch {
			return nil, err
		}
		if e := fail(ErrDepositUC); e != nil {
			return nil, wrap(ErrDepositUC, err)
		}
	}
	return uc, nil
}

// scanCertificate is bridgeprofile's bounded certificate scan: the SDK subset (field majors, seal network 1..65535, byte-string
// signatures of any width) and then the native scan b1ref.ScanUC.
func scanCertificate(raw []byte) error {
	if len(raw) > b1ref.MaxUCBytes {
		return b1ref.ErrUCTooLarge
	}
	root, err := scanNative(raw)
	if err != nil {
		return err
	}
	uc, err := root.tagContent(types.UnicityCertificateTag)
	if err != nil {
		return err
	}
	if err := uc.array(7); err != nil {
		return err
	}
	for _, field := range []struct {
		index, arity, required int
		tag                    uint64
		major                  byte
	}{
		{1, 10, 5, types.InputRecordTag, majBytes},
		{4, 3, 2, types.ShardTreeCertificateTag, majArray},
		{5, 3, 2, types.UnicityTreeCertificateTag, majArray},
		{6, 8, 7, types.UnicitySealTag, majMap},
	} {
		body, err := uc.kids[field.index].tagContent(field.tag)
		if err != nil || body.array(field.arity) != nil || body.kids[field.required].major != field.major {
			return fmt.Errorf("SDK field %d requires CBOR major %d", field.index, field.major)
		}
	}
	seal := uc.kids[6].kids[0].kids
	if !seal[1].isUint() || seal[1].arg == 0 || seal[1].arg > 65535 {
		return fmt.Errorf("SDK seal network outside 1..65535")
	}
	for i := 1; i < len(seal[7].kids); i += 2 {
		if !seal[7].kids[i].isBytes() {
			return fmt.Errorf("seal signature is not a byte string")
		}
	}
	_, err = b1ref.ScanUC(raw)
	return err
}
