package registrygenesis

import (
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-core/registryproof"
)

// ArtifactSource names the embedded file exactly: the merged SealRegistry artifact (#12, contracts PR #1).
const ArtifactSource = "ristik/unicity-pos-contracts artifacts/seal-registry-v1.json at 7dc63acd64606f0ef0bec68cc1e8f2caa1a32684"

//go:embed seal-registry-v1.json
var pinnedArtifactJSON []byte

// Artifact is the registry runtime code and its Keccak-256 code hash, as the genesis allocation places it.
type Artifact struct {
	RuntimeCode []byte
	CodeHash    common.Hash
}

func (a Artifact) check() error {
	if len(a.RuntimeCode) == 0 {
		return fmt.Errorf("%w: runtime code is empty", ErrArtifact)
	}
	if got := crypto.Keccak256Hash(a.RuntimeCode); got != a.CodeHash {
		return fmt.Errorf("%w: runtime code hashes to %s, artifact names %s", ErrArtifact, got, a.CodeHash)
	}
	return nil
}

type artifactFile struct {
	Profile         string        `json:"profile"`
	Compiler        compilerPin   `json:"compiler"`
	RuntimeBytecode hexutil.Bytes `json:"runtimeBytecode"`
	CodeHash        common.Hash   `json:"codeHash"`
	SystemCaller    string        `json:"systemCaller"`
	SlotKeys        []struct {
		Name string      `json:"name"`
		Key  common.Hash `json:"key"`
	} `json:"slotKeys"`
}

type compilerPin struct {
	Solc          string `json:"solc"`
	EVMVersion    string `json:"evm_version"`
	Optimizer     bool   `json:"optimizer"`
	OptimizerRuns int    `json:"optimizer_runs"`
	ViaIR         bool   `json:"via_ir"`
	BytecodeHash  string `json:"bytecode_hash"`
	CBORMetadata  bool   `json:"cbor_metadata"`
}

// pinnedCompiler is the #153 §11 amendment (#155).
var pinnedCompiler = compilerPin{Solc: "0.8.37", EVMVersion: "cancun", Optimizer: true, OptimizerRuns: 200, ViaIR: true, BytecodeHash: "none", CBORMetadata: false}

// PinnedArtifact parses the embedded artifact and checks it against #153 before returning it: profile,
// compiler settings, system caller, every slot key against registryproof's constants, and the code hash
// against the runtime code.
func PinnedArtifact() (Artifact, error) { return parseArtifact(pinnedArtifactJSON) }

func parseArtifact(raw []byte) (Artifact, error) {
	var f artifactFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return Artifact{}, fmt.Errorf("%w: %v", ErrArtifact, err)
	}
	if f.Profile != "sealRegistry/v1" {
		return Artifact{}, fmt.Errorf("%w: profile %q", ErrArtifact, f.Profile)
	}
	if f.Compiler != pinnedCompiler {
		return Artifact{}, fmt.Errorf("%w: compiler settings %+v are not the #153 pin %+v", ErrArtifact, f.Compiler, pinnedCompiler)
	}
	if !common.IsHexAddress(f.SystemCaller) || common.HexToAddress(f.SystemCaller) != SystemAddress {
		return Artifact{}, fmt.Errorf("%w: system caller %s is not a_sys %s", ErrArtifact, f.SystemCaller, SystemAddress)
	}
	if len(f.SlotKeys) != registryproof.FieldCount {
		return Artifact{}, fmt.Errorf("%w: %d slot keys, want %d", ErrArtifact, len(f.SlotKeys), registryproof.FieldCount)
	}
	for i, k := range f.SlotKeys {
		if k.Name != registryproof.SlotNames[i] || k.Key != registryproof.SlotKey(i) {
			return Artifact{}, fmt.Errorf("%w: slot key %d is %s %s, want %s %s", ErrArtifact, i, k.Name, k.Key, registryproof.SlotNames[i], registryproof.SlotKey(i))
		}
	}
	a := Artifact{RuntimeCode: f.RuntimeBytecode, CodeHash: f.CodeHash}
	if err := a.check(); err != nil {
		return Artifact{}, err
	}
	return a, nil
}
