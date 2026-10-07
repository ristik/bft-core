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

const Source = "ristik/unicity-pos-contracts@71eb6325bafe296bb58ceb93f7c4df775409f764:artifacts/seal-registry.json"
const CodeHashHex = "0x28ebc47d5beeb45307cb92ff1521be6a5623d4e4fa1721bc13a6f755cdf0781c"
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
	if hex.EncodeToString(sum[:]) != "c094a1a6d56236474e68e5fda665f3d6fcc2c789743ede6e671c7f4f89279bcb" {
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
	names := append(b1state.OperationalSlots(), "b1.network", "b1.wCert", "b1.profileHash", "b1.initialized", "b1.head", "b1.count")
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
	if k > MaxMeasuredK || p.RuntimeHash != [32]byte(common.HexToHash(CodeHashHex)) || p.CompilerHash != CompilerHash() || p.RestGas < 1096500+1141500*k {
		return ErrArtifact
	}
	_, err := Runtime()
	return err
}
