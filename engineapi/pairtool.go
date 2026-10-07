package engineapi

// Operator tooling for the paired-execution binding (ureth#52), used by the Q3 acceptance lane's `ubft q3 pair-*` commands. It talks to one
// execution client over its plain and Engine endpoints and to nothing else, so a lane can read what a pair retained, present a tampered
// binding to see the exact refusal, and exercise the restart admission. It is not part of the node: the node's own derivation of a binding
// is pairbinding.go's, and nothing here supplies a trust decision.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/unicitynetwork/bft-go-base/types"
)

// PairExport is what one pair retained for a block: the canonical root input its execution rests on, the transition bytes inside it, the
// binding retained with the companion and the block's execution state.
type PairExport struct {
	Number      uint64
	Head        [32]byte
	Parent      [32]byte
	StateRoot   [32]byte
	RootInput   []byte
	Transitions []byte // the canonical array of the transition byte strings, as the binding hashes it
	Binding     []byte
}

type pairHeader struct {
	Number                string            `json:"number"`
	Hash                  string            `json:"hash"`
	ParentHash            string            `json:"parentHash"`
	StateRoot             string            `json:"stateRoot"`
	MixHash               string            `json:"mixHash"`
	Miner                 string            `json:"miner"`
	Timestamp             string            `json:"timestamp"`
	ExtraData             string            `json:"extraData"`
	ParentBeaconBlockRoot string            `json:"parentBeaconBlockRoot"`
	Withdrawals           []json.RawMessage `json:"withdrawals"`
}

func hexBytes(s string, size int) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || (size >= 0 && len(raw) != size) {
		return nil, fmt.Errorf("engineapi: %q is not a %d-byte hex value", s, size)
	}
	return raw, nil
}

func hexUint(s string) (uint64, error) { return strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64) }

func (c *EthClient) header(ctx context.Context, tag string) (pairHeader, error) {
	var h pairHeader
	var raw json.RawMessage
	if err := c.call(ctx, "eth_getBlockByNumber", []any{tag, false}, &raw); err != nil {
		return h, err
	}
	if isJSONNull(raw) {
		return h, fmt.Errorf("engineapi: the execution client has no block %s", tag)
	}
	return h, json.Unmarshal(raw, &h)
}

type pairCompanionLookup struct {
	Status    string `json:"status"`
	Companion struct {
		RootInput   string `json:"rootInput"`
		PairBinding string `json:"pairBinding"`
	} `json:"companion"`
}

// ErrPairCompanion is returned when the execution client holds no companion for a block.
var ErrPairCompanion = errors.New("engineapi: the execution client retains no companion for the block")

func (c *EthClient) companion(ctx context.Context, hash string) (rootInput, binding []byte, err error) {
	var l pairCompanionLookup
	if err := c.call(ctx, "unicity_getSealCompanionV1", []any{hash}, &l); err != nil {
		return nil, nil, err
	}
	if l.Status != "found" {
		return nil, nil, fmt.Errorf("%w: %s (%s)", ErrPairCompanion, hash, l.Status)
	}
	if rootInput, err = hexBytes(l.Companion.RootInput, -1); err != nil {
		return nil, nil, err
	}
	if binding, err = hexBytes(l.Companion.PairBinding, -1); err != nil {
		return nil, nil, err
	}
	return rootInput, binding, nil
}

// rootInputTransitions is the canonical array of the transition byte strings inside a canonical root input: its last field.
func rootInputTransitions(rootInput []byte) ([]byte, error) {
	var v []any
	if err := types.Cbor.Unmarshal(rootInput, &v); err != nil || len(v) == 0 {
		return nil, errors.New("engineapi: the root input is not a CBOR array")
	}
	d, ok := v[len(v)-1].([]any)
	if !ok {
		return nil, errors.New("engineapi: the root input's last field is not the transition array")
	}
	items := make([]any, len(d))
	for i, t := range d {
		b, ok := t.([]byte)
		if !ok {
			return nil, errors.New("engineapi: a transition is not a byte string")
		}
		items[i] = b
	}
	return types.Cbor.Marshal(items)
}

// ExportPairBlock reads what the pair at ethURL retained for the block of the given number (the latest when latest is set).
func ExportPairBlock(ctx context.Context, ethURL string, number uint64, latest bool) (PairExport, error) {
	var out PairExport
	eth := NewEthClient(ethURL)
	tag := "0x" + strconv.FormatUint(number, 16)
	if latest {
		tag = "latest"
	}
	h, err := eth.header(ctx, tag)
	if err != nil {
		return out, err
	}
	if out.Number, err = hexUint(h.Number); err != nil {
		return out, err
	}
	for dst, src := range map[*[32]byte]string{&out.Head: h.Hash, &out.Parent: h.ParentHash, &out.StateRoot: h.StateRoot} {
		raw, err := hexBytes(src, 32)
		if err != nil {
			return out, err
		}
		copy(dst[:], raw)
	}
	if out.RootInput, out.Binding, err = eth.companion(ctx, h.Hash); err != nil {
		return out, err
	}
	if out.Transitions, err = rootInputTransitions(out.RootInput); err != nil {
		return out, err
	}
	return out, nil
}

// PairControl names a refusal control on the build path.
type PairControl string

const (
	// ControlAccept re-presents the block's own build binding: the control that must be accepted.
	ControlAccept PairControl = "accept"
	// ControlWrongParent names another parent hash than the one the build is on.
	ControlWrongParent PairControl = "wrong-parent"
	// ControlWrongJob names the digest of other build attributes than the ones submitted.
	ControlWrongJob PairControl = "wrong-job"
	// ControlSubstitutedInput names another root input than the one submitted.
	ControlSubstitutedInput PairControl = "substituted-input"
	// ControlMissingEvidence submits no binding at all.
	ControlMissingEvidence PairControl = "missing-evidence"
)

// PairControlOutcome is the execution client's answer to one control.
type PairControlOutcome struct {
	Accepted bool
	Detail   string // the refusal text of a refused control, which carries the typed cause
}

// RunPairControl submits one build job to the pair's execution client: the job that would rebuild its latest block on that block's parent,
// from the root input and binding it retained, with exactly one thing changed according to the control. The control that changes nothing
// must be accepted; every other must be refused with its own cause. A job that is accepted starts a payload build the node never collects.
func RunPairControl(ctx context.Context, engineURL string, secret Secret, ethURL string, kind PairControl) (PairControlOutcome, error) {
	var out PairControlOutcome
	eth := NewEthClient(ethURL)
	h, err := eth.header(ctx, "latest")
	if err != nil {
		return out, err
	}
	if len(h.Withdrawals) != 0 {
		return out, errors.New("engineapi: a block with withdrawals is not a block this control can rebuild")
	}
	rootInput, retained, err := eth.companion(ctx, h.Hash)
	if err != nil {
		return out, err
	}
	b, err := DecodePairBinding(retained)
	if err != nil {
		return out, fmt.Errorf("engineapi: the retained binding does not decode: %w", err)
	}
	transitions, err := rootInputTransitionList(rootInput)
	if err != nil {
		return out, err
	}
	timestamp, err := hexUint(h.Timestamp)
	if err != nil {
		return out, err
	}
	var randao, beacon [32]byte
	var recipient [20]byte
	mix, err := hexBytes(h.MixHash, 32)
	if err != nil {
		return out, err
	}
	copy(randao[:], mix)
	fee, err := hexBytes(h.Miner, 20)
	if err != nil {
		return out, err
	}
	copy(recipient[:], fee)
	root, err := hexBytes(h.ParentBeaconBlockRoot, 32)
	if err != nil {
		return out, err
	}
	copy(beacon[:], root)
	parent, err := hexBytes(h.ParentHash, 32)
	if err != nil {
		return out, err
	}
	extra, err := hexBytes(h.ExtraData, 32)
	if err != nil {
		return out, err
	}

	// the binding of the build of this block, then the one thing the control changes
	digest, err := AttributesDigest(timestamp, randao, recipient, beacon)
	if err != nil {
		return out, err
	}
	b.Kind, b.SubjectID = PairBuild, digest
	var evidence []byte
	switch kind {
	case ControlAccept:
	case ControlWrongParent:
		b.ParentHash[0] ^= 0xff
	case ControlWrongJob:
		if b.SubjectID, err = AttributesDigest(timestamp+1, randao, recipient, beacon); err != nil {
			return out, err
		}
	case ControlSubstitutedInput:
		b.RootInputHash[0] ^= 0xff
	case ControlMissingEvidence:
		b = PairBinding{}
	default:
		return out, fmt.Errorf("engineapi: unknown pair control %q", kind)
	}
	if kind != ControlMissingEvidence {
		if evidence, err = b.Encode(); err != nil {
			return out, err
		}
	}

	var parentHash data32
	copy(parentHash[:], parent)
	attrs := UnicityPayloadAttributes{PayloadAttributesV3: PayloadAttributesV3{Timestamp: quantity(timestamp), PrevRandao: randao,
		SuggestedFeeRecipient: recipient, Withdrawals: []WithdrawalV1{}, ParentBeaconBlockRoot: beacon}}
	copy(attrs.Commitment[:], extra)
	input := SealBuildInput{RootInput: rootInput, Transitions: transitions, Pair: evidence}
	engine := NewClient(engineURL, secret)
	resp, err := engine.ForkchoiceUpdatedWithSealV1(ctx, ForkchoiceStateV1{HeadBlockHash: parentHash, SafeBlockHash: parentHash, FinalizedBlockHash: parentHash}, &attrs, input)
	switch {
	case err != nil:
		out.Detail = err.Error()
	case resp.PayloadStatus.Status == PayloadStatusValid && resp.PayloadID != nil:
		out.Accepted = true
	default:
		out.Detail = fmt.Sprintf("status %s: %s", resp.PayloadStatus.Status, errString(resp.PayloadStatus.ValidationError))
	}
	return out, nil
}

// rootInputTransitionList is the transition byte strings of a canonical root input, one per entry.
func rootInputTransitionList(rootInput []byte) ([]data, error) {
	var v []any
	if err := types.Cbor.Unmarshal(rootInput, &v); err != nil || len(v) == 0 {
		return nil, errors.New("engineapi: the root input is not a CBOR array")
	}
	d, ok := v[len(v)-1].([]any)
	if !ok {
		return nil, errors.New("engineapi: the root input's last field is not the transition array")
	}
	out := make([]data, len(d))
	for i, t := range d {
		b, ok := t.([]byte)
		if !ok {
			return nil, errors.New("engineapi: a transition is not a byte string")
		}
		out[i] = data(b)
	}
	return out, nil
}

// AdmitHeadFromRetained presents the pair's latest block's retained binding, as an import binding of that block, to its restart admission
// (engine_admitParentV1). It is the OPERATOR presenting what the client retained: it exercises the client's gate, and it is not the node's
// own reauthentication of the head from its verified history (Adapter.AdmitRecoveredHead), which is what a real restart must supply.
func AdmitHeadFromRetained(ctx context.Context, engineURL string, secret Secret, ethURL string) error {
	eth := NewEthClient(ethURL)
	h, err := eth.header(ctx, "latest")
	if err != nil {
		return err
	}
	_, retained, err := eth.companion(ctx, h.Hash)
	if err != nil {
		return err
	}
	b, err := DecodePairBinding(retained)
	if err != nil {
		return err
	}
	hash, err := hexBytes(h.Hash, 32)
	if err != nil {
		return err
	}
	b.Kind = PairImport
	copy(b.SubjectID[:], hash)
	presented, err := b.Encode()
	if err != nil {
		return err
	}
	return NewClient(engineURL, secret).call(ctx, "engine_admitParentV1", []any{data(presented)}, nil)
}
