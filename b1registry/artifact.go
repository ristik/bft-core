// Package b1registry pins the fresh B1 registry. Historical registry artifacts
// are never accepted by this deployment. B1 remains inactive until PR4.
package b1registry

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-core/b1state"
)

const Source = "ristik/unicity-pos-contracts@0c1e43df954c2a60e01dc668b06415fcbf22d043:artifacts/seal-registry.json"
const CodeHashHex = "0x8c5b57fd322b9ca1370fca310564a1fba8e80b6ad29a78ceb23aa9ae4113cfe4"

// MaxMeasuredEpochs is the most epochs per update the runtime's G_rest was measured for (contracts B1GenesisBuilder: UnmeasuredB above 2).
const MaxMeasuredEpochs uint64 = b1state.MinEpochsPerUpdate

var ErrArtifact = errors.New("b1registry: registry artifact or profile differs from pin")

//go:embed seal-registry.json
var artifact []byte

// CompilerHash commits the exact compiler object in the immutable artifact.
func CompilerHash() [32]byte {
	return sha256.Sum256([]byte(`{"solc":"0.8.37","evm_version":"cancun","optimizer":true,"optimizer_runs":200,"via_ir":true,"bytecode_hash":"none","cbor_metadata":false}`))
}
func Runtime() ([]byte, error) {
	sum := sha256.Sum256(artifact)
	if hex.EncodeToString(sum[:]) != "c575023a1038a34cc92b802ad393a2722b0f5eacefccd82f4c90469347711ee7" {
		return nil, ErrArtifact
	}
	var a struct {
		Profile         string
		RuntimeBytecode hexutil.Bytes
		CodeHash        common.Hash
		OpenSelector    string
		SlotKeys        []struct {
			Name string
			Key  common.Hash
		}
	}
	if json.Unmarshal(artifact, &a) != nil || a.Profile != "sealRegistry" || a.CodeHash != common.HexToHash(CodeHashHex) || crypto.Keccak256Hash(a.RuntimeBytecode) != a.CodeHash || a.OpenSelector != "0x724236c0" {
		return nil, ErrArtifact
	}
	names := append(append(b1state.OperationalSlots(), b1state.RecordSlots()...), "b1.network", "b1.format", "b1.profileHash", "b1.initialized", "b1.genesisEpoch", "b1.importedTipEpoch", "b1.originReady")
	if len(names) != len(a.SlotKeys) {
		return nil, ErrArtifact
	}
	for i, n := range names {
		if a.SlotKeys[i].Name != n || a.SlotKeys[i].Key != common.Hash(b1state.FixedSlot(n)) {
			return nil, ErrArtifact
		}
	}
	return append([]byte(nil), a.RuntimeBytecode...), nil
}

// MinRestGas is the frozen G_rest allowance the profile must reserve for an update of b epochs: the measured base plus the per-epoch term.
// Measured on the permanent-layout runtime under forge's EVM with 16-member entries (briefs/registry-permanent-layout-for-dev-dev3.md): ureth re-measures
// under the real client.
func MinRestGas(b uint64) uint64 { return 1_150_000 + 250_000*b }

// ValidateProfile enforces the measured envelope, independently of caller-supplied pins.
func ValidateProfile(p b1state.Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	k, _, _, _ := p.Bounds()
	if k > MaxMeasuredEpochs || p.RuntimeHash != [32]byte(common.HexToHash(CodeHashHex)) || p.CompilerHash != CompilerHash() || p.RestGas < MinRestGas(p.MaxEpochsPerUpdate) {
		return ErrArtifact
	}
	_, err := Runtime()
	return err
}
