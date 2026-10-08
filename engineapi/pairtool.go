package engineapi

// Operator tooling for the paired-execution binding (ureth#52), used by the Q3 acceptance lane's `ubft q3 pair-*` commands. It talks to one
// execution client over its plain and Engine endpoints and to nothing else, so a lane can read what a pair retained, present a tampered
// binding to see the exact refusal, and exercise the restart admission. It is not part of the node: the node's own derivation of a binding
// is pairbinding.go's, and nothing here supplies a trust decision.

import (
	"context"
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

// rootInputTransitions is the canonical array of the transition byte strings inside a canonical root input: its 11th field (see
// rootInputTransitionsField), whatever follows it.
func rootInputTransitions(rootInput []byte) ([]byte, error) {
	var v []any
	if err := types.Cbor.Unmarshal(rootInput, &v); err != nil || len(v) <= rootInputTransitionsField {
		return nil, errors.New("engineapi: the root input is not a CBOR array with a transition field")
	}
	d, ok := v[rootInputTransitionsField].([]any)
	if !ok {
		return nil, errors.New("engineapi: the root input's transition field is not an array")
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

// rootInputTransitionsField is the position of the transition array in a canonical root input: the 11th field of every tuple (the legacy 11-field
// tuple ends with it; the B1 tuples append the B1 update hash and the root-records hash after it).
const rootInputTransitionsField = 10

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
	// GateOnly: the pair gate accepted the job and the engine then refused the build below its finalized block (see RunPairControl).
	GateOnly bool
	Detail   string // the refusal text of a refused control, which carries the typed cause
}

// RunPairControl submits one build job to the pair's execution client: the job that would rebuild its latest block on that block's parent,
// from the root input and binding it retained, with exactly one thing changed according to the control. The control that changes nothing
// must be accepted; every other must be refused with its own cause. A job that is accepted starts a payload build the node never collects.
//
// The rebuild is on the latest block's parent. In steady state the latest block is the latest certified one, which the node told its execution
// client is finalized, and the client refuses a build below its finalized block ("Too deep reorg") AFTER the pair gate has accepted the job
// (ureth checks the binding before the build is forwarded to the engine). For the control that changes nothing that answer is therefore the
// gate's acceptance, reported as Accepted with GateOnly set; for every other control it is a failure to be refused by the gate, so it stays a
// refusal and the lane finds no typed cause.
func RunPairControl(ctx context.Context, engineURL string, secret Secret, ethURL string, kind PairControl) (PairControlOutcome, error) {
	out, err := runPairControlOnce(ctx, engineURL, secret, ethURL, kind)
	if err == nil && kind == ControlAccept && !out.Accepted && strings.Contains(out.Detail, tooDeepReorg) {
		out.Accepted, out.GateOnly = true, true
	}
	return out, err
}

// tooDeepReorg is the execution client's refusal of a build below its finalized block.
const tooDeepReorg = "Too deep reorg"

func runPairControlOnce(ctx context.Context, engineURL string, secret Secret, ethURL string, kind PairControl) (PairControlOutcome, error) {
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
	input := SealBuildInput{RootInput: rootInput, Transitions: transitions, Pair: evidence, PairEmpty: kind == ControlMissingEvidence}
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
	if err := types.Cbor.Unmarshal(rootInput, &v); err != nil || len(v) <= rootInputTransitionsField {
		return nil, errors.New("engineapi: the root input is not a CBOR array with a transition field")
	}
	d, ok := v[rootInputTransitionsField].([]any)
	if !ok {
		return nil, errors.New("engineapi: the root input's transition field is not an array")
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
