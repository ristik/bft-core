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

const Source = "ristik/unicity-pos-contracts@30bc153a5cbbc42622dda13ab9603cfe08978853:artifacts/seal-registry.json"
const CodeHashHex = "0x1c660647c1dc27aff97d9e9d5315e2ff60208ea8446253164d831c3ae0cd2611"
const MaxMeasuredK uint64 = 16

var ErrArtifact = errors.New("b1registry: registry artifact or profile differs from pin")

//go:embed seal-registry.json
var artifact []byte

// CompilerHash commits the exact compiler object in the immutable artifact.
func CompilerHash() [32]byte {
	return sha256.Sum256([]byte(`{"solc":"0.8.37","evm_version":"cancun","optimizer":true,"optimizer_runs":200,"via_ir":true,"bytecode_hash":"none","cbor_metadata":false}`))
}
func Runtime() ([]byte, error) {
	sum := sha256.Sum256(artifact)
	if hex.EncodeToString(sum[:]) != "f4ed5be6bff995082909f425df7f9200fd65f59b0816cea2d1617b1afb2b11d4" {
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
	names := append(append(b1state.OperationalSlots(), b1state.RecordSlots()...), "b1.network", "b1.wCert", "b1.profileHash", "b1.initialized", "b1.head", "b1.count")
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

// ValidateProfile enforces the measured envelope, independently of caller-supplied pins.
func ValidateProfile(p b1state.Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	k, _, _, _ := p.Bounds()
	if k > MaxMeasuredK || p.RuntimeHash != [32]byte(common.HexToHash(CodeHashHex)) || p.CompilerHash != CompilerHash() || p.RestGas < 1136500+1147500*k {
		return ErrArtifact
	}
	_, err := Runtime()
	return err
}
