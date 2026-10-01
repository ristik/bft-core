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

// ArtifactSource names the embedded file exactly: the merged SealRegistry artifact (contracts PR #2).
const ArtifactSource = "ristik/unicity-pos-contracts artifacts/seal-registry-v1.json at 6b4e221737c13a645400b9e19dd5259d02e5cc5c"

// ArtifactSourceV2 names the assignment-aware SealRegistry (contracts PR 5, h3/contracts-assignment).
const ArtifactSourceV2 = "ristik/unicity-pos-contracts artifacts/seal-registry-v2.json at 8b30801afaa887db0d7aa2e4957ecae2c01293e4"

// PinnedCodeHashV2 is the runtime code hash of the pinned v2 artifact, an independent pin: the artifact
// file is checked against it, so replacing the file alone cannot change the deployment's code.
var PinnedCodeHashV2 = common.HexToHash("0x7787f3166565c8e5ebd73801bf71cbacf0cf69f6bcfb8dea8bedbef8198caf38")

//go:embed seal-registry-v1.json
var pinnedArtifactJSON []byte

//go:embed seal-registry-v2.json
var pinnedArtifactV2JSON []byte

// Artifact is the registry runtime code and its Keccak-256 code hash, as the genesis allocation places it.
type Artifact struct {
	RuntimeCode []byte
	CodeHash    common.Hash
	// Layout is the registry layout the code implements: 1 (the historical v1) or 2 (assignment-aware).
	// Zero is read as 1.
	Layout uint64
}

func (a Artifact) layout() uint64 {
	if a.Layout == 0 {
		return 1
	}
	return a.Layout
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
func PinnedArtifact() (Artifact, error) { return parseArtifact(pinnedArtifactJSON, 1) }

// PinnedArtifactV2 parses the embedded assignment-aware artifact and checks it the same way, and against
// the independently pinned code hash.
func PinnedArtifactV2() (Artifact, error) {
	a, err := parseArtifact(pinnedArtifactV2JSON, 2)
	if err != nil {
		return Artifact{}, err
	}
	if a.CodeHash != PinnedCodeHashV2 {
		return Artifact{}, fmt.Errorf("%w: v2 code hash %s is not the pinned %s", ErrArtifact, a.CodeHash, PinnedCodeHashV2)
	}
	return a, nil
}

// PinnedArtifactForLayout selects the pinned artifact: layout 0 or 1 is the historical sealRegistry/v1, 2 the
// assignment-aware sealRegistry/v2 an M3 launch genesis must use. Any other layout is refused.
func PinnedArtifactForLayout(layout uint64) (Artifact, error) {
	switch layout {
	case 0, 1:
		return PinnedArtifact()
	case 2:
		return PinnedArtifactV2()
	}
	return Artifact{}, fmt.Errorf("%w: registry layout %d", ErrArtifact, layout)
}

func parseArtifact(raw []byte, layout uint64) (Artifact, error) {
	var f artifactFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return Artifact{}, fmt.Errorf("%w: %v", ErrArtifact, err)
	}
	if f.Profile != fmt.Sprintf("sealRegistry/v%d", layout) {
		return Artifact{}, fmt.Errorf("%w: profile %q", ErrArtifact, f.Profile)
	}
	names, err := registryproof.SlotNamesFor(layout)
	if err != nil {
		return Artifact{}, err
	}
	if f.Compiler != pinnedCompiler {
		return Artifact{}, fmt.Errorf("%w: compiler settings %+v are not the #153 pin %+v", ErrArtifact, f.Compiler, pinnedCompiler)
	}
	if !common.IsHexAddress(f.SystemCaller) || common.HexToAddress(f.SystemCaller) != SystemAddress {
		return Artifact{}, fmt.Errorf("%w: system caller %s is not a_sys %s", ErrArtifact, f.SystemCaller, SystemAddress)
	}
	if len(f.SlotKeys) != len(names) {
		return Artifact{}, fmt.Errorf("%w: %d slot keys, want %d", ErrArtifact, len(f.SlotKeys), len(names))
	}
	for i, k := range f.SlotKeys {
		want, err := registryproof.SlotKeyFor(layout, i)
		if err != nil || k.Name != names[i] || k.Key != want {
			return Artifact{}, fmt.Errorf("%w: slot key %d is %s %s, want %s %s", ErrArtifact, i, k.Name, k.Key, names[i], want)
		}
	}
	a := Artifact{RuntimeCode: f.RuntimeBytecode, CodeHash: f.CodeHash, Layout: layout}
	if err := a.check(); err != nil {
		return Artifact{}, err
	}
	return a, nil
}
