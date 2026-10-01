package mintproof

import (
	"bytes"
	stdcrypto "crypto"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-go-base/types"
)

// BundleVersion2 is the PDR-carrying bundle schema. Version 1 bundles stay valid only under their
// explicit original configuration pin: a missing PDR is never read as the latest assignment.
const BundleVersion2 uint64 = 2

// MaxConfigPDRBytes bounds the carried configuration preimage.
const MaxConfigPDRBytes = 256 * 1024

// MintReasonBundleV2 carries the full canonical PartitionDescriptionRecord of its subject UC's
// configuration, including the shard epoch. The root signature over the UC commits to the PDR through
// its hash, so the bundle is offline proof authority for that assignment with no handoff-proof chain.
type MintReasonBundleV2 struct {
	MintReasonBundleV1
	ConfigPDR []byte
}

func (b MintReasonBundleV2) valid() bool {
	return b.MintReasonBundleV1.valid() && len(b.ConfigPDR) != 0 && len(b.ConfigPDR) <= MaxConfigPDRBytes
}

func (b MintReasonBundleV2) MarshalCBOR() ([]byte, error) {
	if !b.valid() {
		return nil, ErrInvalid
	}
	v, _ := b.value()
	v[0] = BundleVersion2
	v = append(v, b.ConfigPDR)
	raw, err := canonicalEnc.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(raw) > DefaultLimits().MaxBytes {
		return nil, ErrTooLarge
	}
	return raw, nil
}

// bundleVersion reads the leading schema version without trusting anything else.
func bundleVersion(raw []byte) (uint64, error) {
	var root []any
	if err := strictDec.Unmarshal(raw, &root); err != nil || len(root) == 0 {
		return 0, fmt.Errorf("%w: CBOR", ErrInvalid)
	}
	v, ok := root[0].(uint64)
	if !ok {
		return 0, ErrInvalid
	}
	return v, nil
}

// DecodeBundleV2 accepts exactly one canonical encoding of a version 2 bundle.
func DecodeBundleV2(raw []byte, limits Limits) (MintReasonBundleV2, error) {
	if !limits.valid() || len(raw) > limits.MaxBytes {
		return MintReasonBundleV2{}, ErrTooLarge
	}
	var root []any
	if err := strictDec.Unmarshal(raw, &root); err != nil || len(root) != 6 || asUint(root[0]) != BundleVersion2 {
		return MintReasonBundleV2{}, ErrInvalid
	}
	pdr, ok := root[5].([]byte)
	if !ok {
		return MintReasonBundleV2{}, ErrInvalid
	}
	// Re-encode the first five elements as a version 1 body to reuse its field decoding.
	head := append([]any{uint64(1)}, root[1:5]...)
	headRaw, err := canonicalEnc.Marshal(head)
	if err != nil {
		return MintReasonBundleV2{}, ErrInvalid
	}
	v1, err := DecodeBundle(headRaw, limits)
	if err != nil {
		return MintReasonBundleV2{}, err
	}
	b := MintReasonBundleV2{MintReasonBundleV1: v1, ConfigPDR: bytes.Clone(pdr)}
	canonical, err := b.MarshalCBOR()
	if err != nil || !bytes.Equal(canonical, raw) {
		return MintReasonBundleV2{}, ErrInvalid
	}
	return b, nil
}

// GenesisPin is the immutable deployment expectation a version 2 bundle is checked against: the
// genesis full configuration the deployment was started from. Every non-membership setting of the
// bundle's PDR, including the seal_registry_genesis commitment of G and all execution, fee and fork
// parameters, must equal it; only the validator set, shard epoch and activation round may differ.
type GenesisPin struct {
	Genesis *types.PartitionDescriptionRecord
}

func (g GenesisPin) valid() bool { return g.Genesis != nil }

// verifyConfigPDR checks a bundle's PDR and returns it. The root-authenticated UC carries the
// configuration hash, so no other evidence of the assignment is needed offline.
func verifyConfigPDR(b MintReasonBundleV2, uc *types.UnicityCertificate, expected ExpectedClaim) (*types.PartitionDescriptionRecord, error) {
	if !expected.Pin.valid() {
		return nil, fmt.Errorf("%w: no genesis pin for a PDR-carrying bundle", ErrInvalid)
	}
	var pdr types.PartitionDescriptionRecord
	if err := types.Cbor.Unmarshal(b.ConfigPDR, &pdr); err != nil {
		return nil, fmt.Errorf("%w: configuration PDR: %v", ErrInvalid, err)
	}
	canonical, err := types.Cbor.Marshal(&pdr)
	if err != nil || !bytes.Equal(canonical, b.ConfigPDR) {
		return nil, fmt.Errorf("%w: configuration PDR is not canonical", ErrInvalid)
	}
	hash, err := pdr.Hash(stdcrypto.SHA256)
	if err != nil || !bytes.Equal(hash, b.Context.ShardConf[:]) || !bytes.Equal(hash, uc.ShardConfHash) {
		return nil, fmt.Errorf("%w: configuration PDR does not hash to the certificate's configuration", ErrInvalid)
	}
	if expected.ShardConf != ([32]byte{}) && expected.ShardConf != b.Context.ShardConf {
		return nil, fmt.Errorf("%w: configuration differs from the exact historical pin", ErrInvalid)
	}
	if pdr.NetworkID != b.Context.Network || pdr.PartitionID != b.Context.Partition || !bytes.Equal(pdr.ShardID.Bytes(), b.Context.Shard) {
		return nil, fmt.Errorf("%w: configuration PDR names another network, partition or shard", ErrInvalid)
	}
	g := expected.Pin.Genesis
	if g.NetworkID != pdr.NetworkID || g.PartitionID != pdr.PartitionID || !g.ShardID.Equal(pdr.ShardID) {
		return nil, fmt.Errorf("%w: configuration PDR is not of the pinned deployment", ErrInvalid)
	}
	want, err := evmassign.ConfigHash(g)
	if err != nil {
		return nil, ErrInvalid
	}
	got, err := evmassign.ConfigHash(&pdr)
	if err != nil || got != want {
		return nil, fmt.Errorf("%w: configuration PDR changes a non-membership setting of the genesis pin", ErrInvalid)
	}
	// Every non-membership field is pinned above by the genesis configuration hash, so only the
	// validator set carries assignment schema to validate here.
	if err := evmassign.ValidateSet(pdr.Validators); err != nil {
		return nil, fmt.Errorf("%w: configuration PDR validators: %v", ErrInvalid, err)
	}
	// The certified input record's epoch is signed by the root; the PDR it commits to must be that
	// assignment's, so a certificate of one epoch cannot be explained by another epoch's configuration.
	if uc.InputRecord == nil || uc.InputRecord.Epoch != pdr.Epoch {
		return nil, fmt.Errorf("%w: certified shard epoch %d, configuration PDR epoch %d", ErrInvalid, epochOf(uc), pdr.Epoch)
	}
	return &pdr, nil
}

func epochOf(uc *types.UnicityCertificate) uint64 {
	if uc == nil || uc.InputRecord == nil {
		return 0
	}
	return uc.InputRecord.Epoch
}
