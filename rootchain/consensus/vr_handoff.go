package consensus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/vrschedule"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The root side of the validator-registry (VR) handoff, first stage (VT-05b PR A, ristik/bft-core#1159): the roots observe VR's outputs at
// the EVM blocks their committed chain certifies (stage 0), derive the intent the executor judges against (vrschedule.Intents), and a
// leader orders the Prepare, the Freeze v5 and the H for a complete verified view certificate it holds. In this stage the certificate is
// delivered by an operator path (SubmitVRCertificate); the staged protocol that assembles it among the roots and the successors is PR B.

// ErrVRHandoff reports a VR handoff operation this root refuses.
var ErrVRHandoff = errors.New("VR handoff")

// VRHandoffConfig wires the VR handoff root side: the intent provider (with its sources and output cache), the VR reader the observer
// fetches through, the designated EVM shard, and the Freeze v5 witness builder at the frozen parent.
type VRHandoffConfig struct {
	Intents *vrschedule.Intents
	Reader  vrschedule.Reader
	EVM     types.PartitionShardID
	// Witness builds the Freeze v5 witness over VR at a certified EVM block (the frozen parent P) for result.
	Witness func(ctx context.Context, blockHash, stateRoot [32]byte, result vrschema.Word) ([]byte, error)
	Log     *slog.Logger
}

// vrHeld is the complete verified certificate this root holds for one intent (the I-RET slot): the first one it verified, kept until the
// intent dies.
type vrHeld struct {
	epoch, attempt uint64
	predecessor    []byte
	intent         [32]byte
	cert           vrschema.ViewCertificate
	body           q3format.BodyV3
	result         vrschema.Word
	witness        []byte // the Freeze witness at witnessAt
	witnessAt      [32]byte
}

type vrHandoff struct {
	cfg      VRHandoffConfig
	observer *vrschedule.Observer
	queue    chan []vrschedule.CertifiedEVM
	mu       sync.Mutex
	held     *vrHeld
}

// EnableVRHandoff installs the VR handoff root side on a VR-mode manager: the intent provider into the executor's VR services, the commit
// observer, and its worker (stopped with ctx). It must be called before the manager starts.
func (x *ConsensusManager) EnableVRHandoff(ctx context.Context, cfg VRHandoffConfig) error {
	svc := x.blockStore.PosServices()
	if svc == nil || svc.Registry == nil || cfg.Intents == nil || cfg.Reader == nil || cfg.Witness == nil {
		return fmt.Errorf("%w: the VR services, the intent provider, the VR reader and the witness builder are required", ErrVRHandoff)
	}
	if x.q3 == nil {
		return fmt.Errorf("%w: a VR handoff needs the verified Q3 history", ErrVRHandoff)
	}
	if cfg.Intents.Outputs == nil {
		cfg.Intents.Outputs = vrschedule.NewOutputs()
	}
	if cfg.Log == nil {
		cfg.Log = x.log
	}
	cfg.Intents.Config = x.q3.ProtocolConfig
	svc.Registry.Intents = cfg.Intents
	x.vr = &vrHandoff{cfg: cfg, queue: make(chan []vrschedule.CertifiedEVM, 1024),
		observer: &vrschedule.Observer{Reader: cfg.Reader, Sources: cfg.Intents.Sources, Outputs: cfg.Intents.Outputs, Log: cfg.Log}}
	x.blockStore.SetCommitObserver(x.vr.onCommit)
	go x.vr.run(ctx)
	return nil
}

// onCommit hands the certified EVM blocks of the committed blocks, oldest first, to the observer's worker (never blocking consensus).
func (v *vrHandoff) onCommit(blocks []*storage.ExecutedBlock) {
	var out []vrschedule.CertifiedEVM
	for _, b := range blocks {
		if b == nil || b.BlockData == nil {
			continue
		}
		si := b.ShardState.States[v.cfg.EVM]
		if si == nil || si.IR == nil || len(si.IR.BlockHash) != 32 || len(si.IR.Hash) != 32 {
			continue
		}
		out = append(out, vrschedule.CertifiedEVM{RootRound: b.GetRound(), RootUCTime: b.BlockData.Timestamp, BlockHash: [32]byte(si.IR.BlockHash),
			StateRoot: [32]byte(si.IR.Hash), BlockNumber: si.IR.RoundNumber})
	}
	if len(out) == 0 {
		return
	}
	select {
	case v.queue <- out:
	default:
		v.cfg.Log.Warn("VR handoff: the source observer is behind; a committed EVM certification was not observed")
	}
}

func (v *vrHandoff) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case cs := <-v.queue:
			for _, c := range cs {
				for try := 0; ; try++ {
					err := v.observer.Observe(ctx, c)
					if err == nil {
						break
					}
					if try >= 20 || ctx.Err() != nil {
						v.cfg.Log.Warn("VR handoff: observing a certified EVM block failed", "evmBlock", c.BlockNumber, "rootRound", c.RootRound, "error", err)
						break
					}
					select {
					case <-ctx.Done():
						return
					case <-time.After(500 * time.Millisecond):
					}
				}
			}
		}
	}
}

// VRIntentView is the intent this root derives over its committed state, for the operator: the intent, its digest, the root epoch it
// succeeds, the incumbents (the assembler order's input) and the assembler of view 0.
type VRIntentView struct {
	Intent     vrhandoff.Intent
	Digest     [32]byte
	RootEpoch  uint64
	Incumbents []string
	Assembler  string
}

func (x *ConsensusManager) vrDerived() (vrschedule.Derived, map[string][]byte, error) {
	if x.vr == nil {
		return vrschedule.Derived{}, nil, fmt.Errorf("%w: not enabled", ErrVRHandoff)
	}
	q, on, err := x.blockStore.CommittedVRQuery()
	if err != nil || !on {
		return vrschedule.Derived{}, nil, errors.Join(ErrVRHandoff, errors.New("no committed VR state"), err)
	}
	d, ok, err := x.vr.cfg.Intents.Derive(q)
	if err != nil {
		return d, nil, errors.Join(ErrVRHandoff, err)
	}
	if !ok {
		return d, nil, fmt.Errorf("%w: no intent is derivable over the committed state", ErrVRHandoff)
	}
	keys := map[string][]byte{}
	if tb := x.trustBase.Load(); tb != nil {
		for _, n := range tb.RootNodes {
			keys[n.NodeID] = bytes.Clone(n.SigKey)
		}
	}
	return d, keys, nil
}

// VRIntent is the current intent over the committed state.
func (x *ConsensusManager) VRIntent() (VRIntentView, error) {
	d, keys, err := x.vrDerived()
	if err != nil {
		return VRIntentView{}, err
	}
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	view := uint64(0)
	if s, ok, _ := x.blockStore.CommittedVRState(); ok && bytes.Equal(s.Backoff.Intent, d.Digest[:]) {
		view = s.Backoff.LastView
	}
	order := vrhandoff.AssemblerOrder(d.Digest, ids)
	return VRIntentView{Intent: d.Intent, Digest: d.Digest, RootEpoch: d.RootEpoch, Incumbents: order, Assembler: vrschema.Assembler(order, view)}, nil
}

// VRBody is the successor body and the successor trust base an assembled candidate of the current intent determines (what each member's
// readiness signs). The candidate must be the intent's unsigned candidate with valid possession proofs.
func (x *ConsensusManager) VRBody(candidate []byte) (q3format.BodyV3, []byte, error) {
	d, _, err := x.vrDerived()
	if err != nil {
		return q3format.BodyV3{}, nil, err
	}
	if _, err := vrhandoff.VerifyAssembly(d.Intent, vrhandoff.Assembly{IntentDigest: d.Digest[:], Candidate: candidate}); err != nil {
		return q3format.BodyV3{}, nil, errors.Join(ErrVRHandoff, err)
	}
	body, err := vrhandoff.DeriveBody(d.Intent, d.RootEpoch, sha256.Sum256(candidate), d.Body)
	if err != nil {
		return body, nil, errors.Join(ErrVRHandoff, err)
	}
	_, tb, err := vrhandoff.TrustBase(d.Intent, d.RootEpoch)
	return body, tb, errors.Join(err)
}

// SubmitVRCertificate admits a complete view certificate of the current intent into the I-RET slot once it verifies in full, exactly as
// Freeze validity will judge it (design section 5.3.5): the assembly is the intent's candidate with valid PoPs, signed by its view's
// assembler, the view is committed, and every successor's readiness is valid over the derived body and trust base. The first complete
// certificate of an intent is kept; a later one is refused.
func (x *ConsensusManager) SubmitVRCertificate(c vrschema.ViewCertificate) error {
	d, keys, err := x.vrDerived()
	if err != nil {
		return err
	}
	cand, err := vrhandoff.VerifyAssembly(d.Intent, c.Assembly)
	if err != nil {
		return errors.Join(ErrVRHandoff, err)
	}
	body, err := vrhandoff.DeriveBody(d.Intent, d.RootEpoch, sha256.Sum256(c.Assembly.Candidate), d.Body)
	if err != nil {
		return errors.Join(ErrVRHandoff, err)
	}
	_, tb, err := vrhandoff.TrustBase(d.Intent, d.RootEpoch)
	if err != nil {
		return errors.Join(ErrVRHandoff, err)
	}
	committedView := uint64(0)
	if s, ok, _ := x.blockStore.CommittedVRState(); ok && bytes.Equal(s.Backoff.Intent, d.Digest[:]) {
		committedView = s.Backoff.LastView
	}
	if err := vradmit.VerifyCertificate(vradmit.CertificateInput{Certificate: c, IntentDigest: d.Digest, CommittedView: committedView, Incumbents: keys,
		CandidateBytes: c.Assembly.Candidate, Successors: cand.Identities, Body: body, Attempt: d.Intent.Attempt, TrustBaseBytes: tb}); err != nil {
		return errors.Join(ErrVRHandoff, err)
	}
	x.vr.mu.Lock()
	defer x.vr.mu.Unlock()
	if h := x.vr.held; h != nil && h.intent == d.Digest && h.epoch == d.RootEpoch {
		return nil // I-RET keeps the first complete certificate of the intent
	}
	x.vr.held = &vrHeld{epoch: d.RootEpoch, attempt: d.Intent.Attempt, predecessor: bytes.Clone(d.Intent.PredecessorBodyID), intent: d.Digest, cert: c, body: body,
		result: vrschema.Word(cand.SourceRef)}
	x.log.Info("VR handoff: a complete verified certificate is held", "intent", fmt.Sprintf("%x", d.Digest[:8]), "view", c.Assembly.Slot,
		"rootEpoch", d.RootEpoch, "attempt", d.Intent.Attempt)
	return nil
}

func (v *vrHandoff) current() *vrHeld {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.held
}

// vrRecordsForRound is the leader's handoff record of a VR chain for the round: the Prepare of the held certificate's attempt at a quiet
// control state whose stored attempt is that one (a due rejection first), then its Freeze v5 once the Prepare bound the frozen parent,
// then H. A certificate of another epoch, attempt or predecessor orders nothing (its intent died).
func (x *ConsensusManager) vrRecordsForRound(round uint64, parent *storage.ExecutedBlock, parentQC *rctypes.QuorumCert) ([][]byte, error) {
	control := parent.ShardState.Control
	h := x.vr.current()
	if h == nil || h.epoch != control.Epoch || !bytes.Equal(h.predecessor, control.PredecessorBodyID) {
		return nil, nil
	}
	lapsed := storage.PrepareLapsed(control, round)
	if lapsed && !storage.PrepareMayFollowLapse(control, round) {
		return nil, nil
	}
	bodyID := h.body.Identity()
	switch {
	case control.Phase == "idle" || control.Phase == "aborted" || lapsed:
		attempt, err := plannedAttempt(control, round)
		if err != nil || attempt != h.attempt {
			return nil, nil
		}
		// the attempt must be the stored backoff identity: a Prepare in the block whose end opens its attempt is refused
		if s, err := vradmit.DecodeRootState(control.VR); err != nil || s.Backoff.Epoch != control.Epoch || s.Backoff.Attempt != attempt {
			return nil, nil
		}
		if x.preferRejection(context.Background(), parentQC.GetRound(), round, parentQC) {
			return nil, nil
		}
		if round > ^uint64(0)-storage.PrepareActivationFloorRounds {
			return nil, ErrHandoffApproval
		}
		r := evmroot.OrderedHandoffRecord{Network: control.Network, Epoch: control.Epoch, Attempt: attempt, OrderedRound: round,
			ActivationRound: max(h.body.EarliestActivation, round+storage.PrepareActivationFloorRounds), PredecessorBodyID: bytes.Clone(control.PredecessorBodyID),
			NextBodyID: bodyID[:], Kind: "prepare", FrozenID: make([]byte, 32), SuccessorTRHash: make([]byte, 32)}
		x.log.Info("VR handoff: ordering the Prepare", "round", round, "attempt", attempt, "activation", r.ActivationRound)
		return [][]byte{r.Bytes()}, nil
	case control.Phase == "prepared":
		previous, err := storage.DecodeOrderedHandoffRecord(control.RecordBytes)
		if err != nil || previous.Attempt != h.attempt || !bytes.Equal(previous.NextBodyID, bodyID[:]) || len(control.FrozenParent) != 32 {
			return nil, nil
		}
		si := parent.ShardState.States[x.vr.cfg.EVM]
		if si == nil || si.IR == nil || !bytes.Equal(si.IR.BlockHash, control.FrozenParent) || len(si.IR.Hash) != 32 {
			return nil, nil
		}
		witness, err := x.vr.witnessAt([32]byte(control.FrozenParent), [32]byte(si.IR.Hash), h)
		if err != nil {
			x.log.Warn("VR handoff: the Freeze witness at the frozen parent is unavailable; Freeze not ordered", "attempt", h.attempt, "error", err)
			return nil, nil
		}
		cd := sha256.Sum256(h.cert.Assembly.Candidate)
		r := previous
		r.Kind, r.OrderedRound, r.SuccessorTRHash = "freeze", round, make([]byte, 32)
		r.FrozenID = evmroot.D4FrozenID(bodyID[:], h.body.StateSummary, control.FrozenParent, cd[:], h.attempt, control.PredecessorBodyID)
		companion, err := vrschema.FreezeV5{Candidate: h.cert.Assembly.Candidate, Certificate: h.cert, Witness: witness}.Encode()
		if err != nil {
			return nil, err
		}
		x.log.Info("VR handoff: ordering the Freeze v5", "round", round, "attempt", h.attempt, "view", h.cert.Assembly.Slot)
		return [][]byte{r.Bytes(), companion}, nil
	case control.Phase == "endorsed":
		previous, err := storage.DecodeOrderedHandoffRecord(control.RecordBytes)
		if err != nil || previous.Attempt != h.attempt || !bytes.Equal(previous.NextBodyID, bodyID[:]) {
			return nil, nil
		}
		activation, ok := storage.CommitActivationRound(previous.ActivationRound, round)
		if !ok {
			return nil, ErrHandoffApproval
		}
		key, err := x.blockStore.CertifiedEVMShardAt(parent.GetRound(), control.FrozenParent)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrHandoffApproval, err)
		}
		tr, err := storage.AssignmentSuccessorTRHash(parent.ShardState.States[key], h.cert.Assembly.Candidate, activation, x.params.HashAlgorithm)
		if err != nil {
			return nil, err
		}
		r := previous
		r.Kind, r.OrderedRound, r.ActivationRound, r.SuccessorTRHash = "commit", round, activation, tr
		x.log.Info("VR handoff: ordering H", "round", round, "attempt", h.attempt, "activation", activation)
		return [][]byte{r.Bytes()}, nil
	}
	return nil, nil
}

func (v *vrHandoff) witnessAt(p, root [32]byte, h *vrHeld) ([]byte, error) {
	v.mu.Lock()
	if h.witness != nil && h.witnessAt == p {
		w := h.witness
		v.mu.Unlock()
		return w, nil
	}
	v.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w, err := v.cfg.Witness(ctx, p, root, h.result)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	h.witness, h.witnessAt = w, p
	v.mu.Unlock()
	return w, nil
}
