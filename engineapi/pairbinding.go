package engineapi

// The paired-execution binding (ureth#52, crates/unicity/execution/src/pairing.rs): what this node's own Go verification vouches for, handed to
// the co-hosted execution client with every build job and every imported block. This file is the ONLY place that knows the binding's wire form,
// its identities and its JSON field and sealConfigV1 key names; a change to ureth#52 during review touches this file and its vector test
// (pairbinding_test.go, testdata/pair-binding-vectors.json), and nothing else in the adapter.
//
// The binding is not a certificate. The Rust side signs and verifies nothing here; it compares every field with what it can see for itself (its
// pins, its genesis, its parent header, the decoded root input, the exact build job or block). The Go side states what its derivation depended
// on, so a substituted input, parent, configuration or block cannot be presented under a binding that names another.

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	pairBindingDomain  = "UNICITY_PAIR_BINDING"
	pairBindingVersion = uint64(1)
	pairJobDomain      = "UNICITY_PAIR_JOB"
	pairNoActivation   = "UNICITY_PAIR_NO_ACTIVATION"
	pairSubjectBuild   = uint64(1)
	pairSubjectImport  = uint64(2)

	// MaxPairBindingBytes is the largest encoding the Rust gate accepts; the fixed shape is under 400 bytes.
	MaxPairBindingBytes = 512
)

var (
	// ErrPairBinding is returned for a binding this adapter cannot produce or decode.
	ErrPairBinding = errors.New("engineapi: invalid pair binding")
	// ErrPairPins is returned when the execution client's reported pins differ from this node's own.
	ErrPairPins = errors.New("engineapi: execution client is pinned to another network or root genesis")
)

// PairPins are this node's own network and root-genesis identities. The execution client reports the pins it was started with
// (sealConfigV1) and the adapter refuses to build until they equal these.
type PairPins struct {
	NetworkID     uint64
	RootGenesisID [32]byte
}

// PairConfig enables the binding for an adapter. A nil PairConfig sends none, which is what an execution client without ureth#52 expects.
type PairConfig struct {
	Pins PairPins
	// ExecutionGenesis is the hash of the configured execution genesis block.
	ExecutionGenesis [32]byte
	// ActivationID, when set, names the verified activation of a root epoch (the history's ActivationCommitID). It is used only for an input
	// that carries no transition, where the Rust gate carries the field without comparing it; with a transition the acknowledged
	// transition's commit id is used and this is not consulted.
	ActivationID func(rootEpoch uint64) ([32]byte, bool)
}

// PairSubjectKind names what a binding is about.
type PairSubjectKind uint64

const (
	// PairBuild is a block this node is about to build: the subject is the digest of the exact attributes.
	PairBuild PairSubjectKind = PairSubjectKind(pairSubjectBuild)
	// PairImport is a block this node is about to import: the subject is the block hash.
	PairImport PairSubjectKind = PairSubjectKind(pairSubjectImport)
)

// PairBinding is the decoded binding. Field names follow the wire form.
type PairBinding struct {
	NetworkID            uint64
	RootGenesisID        [32]byte
	ExecutionGenesisHash [32]byte
	ParentHash           [32]byte
	ParentNumber         uint64
	OriginRootEpoch      uint64
	OriginRootRound      uint64
	ConfigurationID      [32]byte
	ActivationID         [32]byte
	RootInputHash        [32]byte
	TransitionsHash      [32]byte
	Kind                 PairSubjectKind
	SubjectID            [32]byte
}

// checkNonZero refuses an all-zero identity, as the Rust decoder does.
func (b PairBinding) checkNonZero() error {
	for name, id := range map[string][32]byte{"rootGenesisId": b.RootGenesisID, "executionGenesisHash": b.ExecutionGenesisHash, "parentHash": b.ParentHash,
		"configurationId": b.ConfigurationID, "activationId": b.ActivationID, "rootInputHash": b.RootInputHash, "transitionsHash": b.TransitionsHash,
		"subjectId": b.SubjectID} {
		if id == ([32]byte{}) {
			return fmt.Errorf("%w: %s is all zero", ErrPairBinding, name)
		}
	}
	return nil
}

// Encode is the canonical binding: one fixed array, no optional fields.
func (b PairBinding) Encode() ([]byte, error) {
	raw, err := types.Cbor.Marshal([]any{pairBindingDomain, pairBindingVersion,
		b.NetworkID, b.RootGenesisID[:], b.ExecutionGenesisHash[:],
		b.ParentHash[:], b.ParentNumber, b.OriginRootEpoch, b.OriginRootRound,
		b.ConfigurationID[:], b.ActivationID[:], b.RootInputHash[:], b.TransitionsHash[:],
		uint64(b.Kind), b.SubjectID[:]})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPairBinding, err)
	}
	if len(raw) > MaxPairBindingBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrPairBinding, len(raw))
	}
	return raw, nil
}

// DecodePairBinding accepts exactly one canonical encoding (the control tooling and the tests use it; the node never authenticates with it).
func DecodePairBinding(raw []byte) (PairBinding, error) {
	var b PairBinding
	if len(raw) == 0 || len(raw) > MaxPairBindingBytes {
		return b, fmt.Errorf("%w: %d bytes", ErrPairBinding, len(raw))
	}
	var v []any
	if err := types.Cbor.Unmarshal(raw, &v); err != nil || len(v) != 15 {
		return b, fmt.Errorf("%w: not a 15-element array", ErrPairBinding)
	}
	if d, ok := v[0].(string); !ok || d != pairBindingDomain {
		return b, fmt.Errorf("%w: domain", ErrPairBinding)
	}
	u := func(i int) (uint64, bool) { x, ok := v[i].(uint64); return x, ok }
	w := func(i int) ([32]byte, bool) {
		x, ok := v[i].([]byte)
		var out [32]byte
		if !ok || len(x) != 32 {
			return out, false
		}
		copy(out[:], x)
		return out, true
	}
	ok := true
	step := func(good bool) { ok = ok && good }
	var version, kind uint64
	var good bool
	version, good = u(1)
	step(good && version == pairBindingVersion)
	b.NetworkID, good = u(2)
	step(good)
	b.RootGenesisID, good = w(3)
	step(good)
	b.ExecutionGenesisHash, good = w(4)
	step(good)
	b.ParentHash, good = w(5)
	step(good)
	b.ParentNumber, good = u(6)
	step(good)
	b.OriginRootEpoch, good = u(7)
	step(good)
	b.OriginRootRound, good = u(8)
	step(good)
	b.ConfigurationID, good = w(9)
	step(good)
	b.ActivationID, good = w(10)
	step(good)
	b.RootInputHash, good = w(11)
	step(good)
	b.TransitionsHash, good = w(12)
	step(good)
	kind, good = u(13)
	step(good && (kind == pairSubjectBuild || kind == pairSubjectImport))
	b.Kind = PairSubjectKind(kind)
	b.SubjectID, good = w(14)
	step(good)
	if !ok {
		return PairBinding{}, fmt.Errorf("%w: field shape", ErrPairBinding)
	}
	if err := b.checkNonZero(); err != nil {
		return PairBinding{}, err
	}
	if again, err := b.Encode(); err != nil || string(again) != string(raw) {
		return PairBinding{}, fmt.Errorf("%w: not canonical", ErrPairBinding)
	}
	return b, nil
}

// TransitionsHash is the SHA-256 of the canonical array of the transition byte strings, exactly the D[] encoding inside the root input.
func TransitionsHash(transitions [][]byte) ([32]byte, error) {
	items := make([]any, len(transitions))
	for i, t := range transitions {
		items[i] = t
	}
	raw, err := types.Cbor.Marshal(items)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrPairBinding, err)
	}
	return sha256.Sum256(raw), nil
}

// AttributesDigest names one build job: SHA-256 of ["UNICITY_PAIR_JOB", 1, timestamp, prevRandao, suggestedFeeRecipient, parentBeaconBlockRoot].
func AttributesDigest(timestamp uint64, prevRandao [32]byte, feeRecipient [20]byte, beaconRoot [32]byte) ([32]byte, error) {
	raw, err := types.Cbor.Marshal([]any{pairJobDomain, uint64(1), timestamp, prevRandao[:], feeRecipient[:], beaconRoot[:]})
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrPairBinding, err)
	}
	return sha256.Sum256(raw), nil
}

// pairParent is the execution parent a binding is derived for, as this node's own eth endpoint reports it.
type pairParent struct {
	Hash   [32]byte
	Number uint64
}

// newPairBinding derives the binding from this node's own authenticated derivation of the root input.
func (c *PairConfig) newPairBinding(derived rootinput.ResultV2, parent pairParent, kind PairSubjectKind, subject [32]byte) (PairBinding, error) {
	if c == nil {
		return PairBinding{}, fmt.Errorf("%w: pair binding is not configured", ErrPairBinding)
	}
	origin := derived.Input.Origin
	conf := [32]byte{}
	if len(origin.ShardConfHash) != 32 {
		return PairBinding{}, fmt.Errorf("%w: origin configuration identity is %d bytes", ErrPairBinding, len(origin.ShardConfHash))
	}
	copy(conf[:], origin.ShardConfHash)
	th, err := TransitionsHash(derived.Input.Transitions)
	if err != nil {
		return PairBinding{}, err
	}
	activation, err := c.activationID(derived, conf)
	if err != nil {
		return PairBinding{}, err
	}
	b := PairBinding{
		NetworkID: c.Pins.NetworkID, RootGenesisID: c.Pins.RootGenesisID, ExecutionGenesisHash: c.ExecutionGenesis,
		ParentHash: parent.Hash, ParentNumber: parent.Number,
		OriginRootEpoch: origin.RootEpoch, OriginRootRound: origin.RootRound,
		ConfigurationID: conf, ActivationID: activation,
		RootInputHash: derived.Commitment, TransitionsHash: th,
		Kind: kind, SubjectID: subject,
	}
	if err := b.checkNonZero(); err != nil {
		return PairBinding{}, err
	}
	return b, nil
}

// activationID is the acknowledged transition's commit id when the input carries one; otherwise the verified activation of the origin's root
// epoch when the node's history supplies it, otherwise a fixed non-zero identity derived from the configuration (the Rust gate carries the
// field without comparing it in that case, and refuses only an all-zero value).
func (c *PairConfig) activationID(derived rootinput.ResultV2, conf [32]byte) ([32]byte, error) {
	if len(derived.Input.Transitions) > 0 {
		t, err := handoff.DecodeEVMTransition(derived.Input.Transitions[0])
		if err != nil {
			return [32]byte{}, fmt.Errorf("%w: transition: %v", ErrPairBinding, err)
		}
		return t.Ack.CommitID, nil
	}
	if c.ActivationID != nil {
		if id, ok := c.ActivationID(derived.Input.Origin.RootEpoch); ok && id != ([32]byte{}) {
			return id, nil
		}
	}
	raw, err := types.Cbor.Marshal([]any{pairNoActivation, derived.Input.Origin.RootEpoch, conf[:]})
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrPairBinding, err)
	}
	return sha256.Sum256(raw), nil
}

// pairWire is the JSON field the binding travels in, on the build input and on the seal companion. It is embedded in both request types so the
// key name exists nowhere else; omitted when empty, which keeps every request to a client without ureth#52 byte-identical to what it was.
type pairWire struct {
	PairBinding data `json:"pairBinding,omitempty"`
}

// pairConfigWire are the pins the execution client echoes in sealConfigV1.
type pairConfigWire struct {
	NetworkID     *uint64 `json:"networkId,omitempty"`
	RootGenesisID *data32 `json:"rootGenesisId,omitempty"`
}

// checkPins compares the pins an execution client reports with this node's own. A client that reports none is refused when the binding is
// enabled: it would fail every build on the missing binding anyway, and the refusal here names the cause.
func (c *PairConfig) checkPins(got pairConfigWire) error {
	if c == nil {
		return nil
	}
	if got.NetworkID == nil || got.RootGenesisID == nil {
		return fmt.Errorf("%w: sealConfigV1 reports no pins", ErrPairPins)
	}
	if *got.NetworkID != c.Pins.NetworkID {
		return fmt.Errorf("%w: network %d, expected %d", ErrPairPins, *got.NetworkID, c.Pins.NetworkID)
	}
	if [32]byte(*got.RootGenesisID) != c.Pins.RootGenesisID {
		return fmt.Errorf("%w: root genesis %x, expected %x", ErrPairPins, [32]byte(*got.RootGenesisID), c.Pins.RootGenesisID)
	}
	return nil
}

// pairBuildBinding is the canonical binding for the build job this adapter is about to submit, or nil when no binding is configured.
func (a *Adapter) pairBuildBinding(ctx context.Context, derived rootinput.ResultV2, parent blockHeaderJSON, attrs PayloadAttributesV3) ([]byte, error) {
	if a.pair == nil {
		return nil, nil
	}
	if err := a.ensurePairPins(ctx); err != nil {
		return nil, err
	}
	digest, err := AttributesDigest(uint64(attrs.Timestamp), attrs.PrevRandao, attrs.SuggestedFeeRecipient, attrs.ParentBeaconBlockRoot)
	if err != nil {
		return nil, err
	}
	return a.encodePair(derived, parent, PairBuild, digest)
}

// pairImportBinding is the canonical binding for the exact block this adapter is about to hand the execution client, derived from this node's
// own authenticated derivation, never from the leader's companion.
func (a *Adapter) pairImportBinding(ctx context.Context, derived rootinput.ResultV2, parent blockHeaderJSON, block data32) ([]byte, error) {
	if a.pair == nil {
		return nil, nil
	}
	if err := a.ensurePairPins(ctx); err != nil {
		return nil, err
	}
	return a.encodePair(derived, parent, PairImport, block)
}

func (a *Adapter) encodePair(derived rootinput.ResultV2, parent blockHeaderJSON, kind PairSubjectKind, subject [32]byte) ([]byte, error) {
	b, err := a.pair.newPairBinding(derived, pairParent{Hash: parent.Hash, Number: uint64(parent.Number)}, kind, subject)
	if err != nil {
		return nil, err
	}
	return b.Encode()
}

// ensurePairPins reads the pins the execution client was started with (sealConfigV1) and compares them with this node's own, once per process.
func (a *Adapter) ensurePairPins(ctx context.Context) error {
	if a.pair == nil || a.pairPinsOK.Load() {
		return nil
	}
	var got sealConfigWire
	if err := a.engine.call(ctx, "engine_sealConfigV1", []any{}, &got); err != nil {
		return fmt.Errorf("%w: %v", ErrSealConfigUnavailable, err)
	}
	if err := a.pair.checkPins(got.pairConfigWire); err != nil {
		return err
	}
	a.pairPinsOK.Store(true)
	return nil
}

// AdmitRecoveredHead is the restart admission of the execution client's canonical head (ureth#52, engine_admitParentV1). After a restart the
// client holds only cached accounting, which resolves nothing until this node's own Go verification has reauthenticated the head's named parent
// context from the verified history and presented it. The caller passes that derivation (the head's root input, re-derived and authenticated), the
// head's parent and the head's hash; the adapter builds the import binding and the client re-checks it against its retained evidence. Until this
// returns nil, builds and imports on the restarted head answer SYNCING. A refusal carries the client's typed cause in the error text.
func (a *Adapter) AdmitRecoveredHead(ctx context.Context, derived rootinput.ResultV2, parentHash [32]byte, parentNumber uint64, head [32]byte) error {
	if a.pair == nil {
		return fmt.Errorf("%w: pair binding is not configured", ErrPairBinding)
	}
	if err := a.ensurePairPins(ctx); err != nil {
		return err
	}
	b, err := a.pair.newPairBinding(derived, pairParent{Hash: parentHash, Number: parentNumber}, PairImport, head)
	if err != nil {
		return err
	}
	raw, err := b.Encode()
	if err != nil {
		return err
	}
	if err := a.engine.call(ctx, "engine_admitParentV1", []any{data(raw)}, nil); err != nil {
		return fmt.Errorf("engineapi: recovery admission refused: %w", err)
	}
	return nil
}
