package bridgeprofile

import (
	"bytes"
	stdcrypto "crypto"
	"encoding/json"

	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
)

// This file isolates the trust-authority decisions that the native-bridge
// design still has open, so each changes in exactly one place. Trust-base
// evolution (epochs, appended records, fetching newer bases, arbitrary
// weights) is common SDK functionality for later: this profile verifies against
// one SDK trust base supplied by the caller and builds no bridge-private epoch
// bundle and no bridge-owned weighted verifier.

// verifyNativeUC is the Go SDK's own UC verification, used as is. The repository
// routes every production UC verification through quorumweight.Checked, which
// only guards stake overflow; it adds no weighted-authority logic.
func verifyNativeUC(tb types.RootTrustBase, uc *types.UnicityCertificate, partition types.PartitionID, shard types.ShardID, conf []byte) error {
	return uc.Verify(quorumweight.Checked(tb), stdcrypto.SHA256, partition, shard, conf)
}

// TrustInput is the one pinned SDK RootTrustBase document of the supported
// profile: the exact installed bytes B (the SDK's JSON representation,
// published once and pinned by the manifest) and the base parsed from them.
// trustBaseId = SHA256(B) identifies those exact bytes; it is an integrity
// binding, not authentication of the base, which stays the application's
// provisioning decision. Verification hashes the installed B, never a
// reconstructed object.
type TrustInput struct {
	JSON []byte
	Base types.RootTrustBase
}

// ID is trustBaseId = SHA256(B).
func (t *TrustInput) ID() [32]byte { return H(t.JSON) }

// trustDoc fixes the SDK's emitted top-level order (changeRecordHash, epoch,
// epochStartRound, networkId, previousEntryHash, quorumThreshold, rootNodes,
// signatures, stateHash, version); each node emits nodeId, sigKey, stake. The
// oracle's own rendering is a CANDIDATE: the authoritative B is the one the
// pinned JS SDK 3.0.1 emits, published by native-bridge-plugins; the oracle
// consumes B as opaque bytes.
type trustDoc struct {
	ChangeRecordHash  hex.Bytes            `json:"changeRecordHash"`
	Epoch             uint64               `json:"epoch"`
	EpochStart        uint64               `json:"epochStartRound"`
	NetworkID         types.NetworkID      `json:"networkId"`
	PreviousEntryHash hex.Bytes            `json:"previousEntryHash"`
	QuorumThreshold   uint64               `json:"quorumThreshold"`
	RootNodes         []*types.NodeInfo    `json:"rootNodes"`
	Signatures        map[string]hex.Bytes `json:"signatures"`
	StateHash         hex.Bytes            `json:"stateHash"`
	Version           types.Version        `json:"version"`
}

// RenderTrustBaseJSON renders tb in the SDK's documented field order.
func RenderTrustBaseJSON(tb *types.RootTrustBaseV1) ([]byte, error) {
	return json.Marshal(trustDoc{ChangeRecordHash: tb.ChangeRecordHash, Epoch: tb.Epoch, EpochStart: tb.EpochStart, NetworkID: tb.NetworkID,
		PreviousEntryHash: tb.PreviousEntryHash, QuorumThreshold: tb.QuorumThreshold, RootNodes: tb.RootNodes,
		Signatures: tb.Signatures, StateHash: tb.StateHash, Version: tb.Version})
}

// LoadTrustInput parses the installed bytes B and checks the fixed profile at
// installation: version 1, an epoch, N distinct validators each of weight 1 and
// quorumThreshold = N - (N-1)/3. Anything else is unsupported (never flattened
// into unit weights): trust-base evolution and arbitrary weights are common SDK
// work for later.
func LoadTrustInput(b []byte) (*TrustInput, error) {
	var tb types.RootTrustBaseV1
	if err := json.Unmarshal(b, &tb); err != nil {
		return nil, ErrTrustConfig
	}
	n := uint64(len(tb.RootNodes))
	if tb.Version != 1 || tb.Epoch == 0 || n == 0 || tb.QuorumThreshold != n-(n-1)/3 {
		return nil, ErrTrustConfig
	}
	seen := map[string]bool{}
	for _, v := range tb.RootNodes {
		if v == nil || v.Stake != 1 || seen[v.NodeID] {
			return nil, ErrTrustConfig
		}
		seen[v.NodeID] = true
	}
	return &TrustInput{JSON: bytes.Clone(b), Base: &tb}, nil
}

// checkFixedProfile guards use outside the one pinned base (it implements no
// epoch evolution): the proof names exactly this document, and the seal's
// network and root epoch equal the base's with a root round at or after the
// base's epoch start.
func checkFixedProfile(p *LockProof, t *TrustInput, uc *types.UnicityCertificate) error {
	if t == nil || t.Base == nil || p.TrustBaseID != t.ID() {
		return ErrTrustBaseDigest
	}
	if uc.UnicitySeal.NetworkID != t.Base.GetNetworkID() || uc.GetRootEpoch() != t.Base.GetEpoch() ||
		uc.UnicitySeal.RootChainRoundNumber < t.Base.GetEpochStart() {
		return ErrEpochMismatch
	}
	return nil
}
