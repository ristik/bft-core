// Package vrhandoff is the validator-registry (VR) handoff view protocol shared by the roots (VT-05b, ristik/bft-core#1159) and the
// successor nodes (VT-09, #1149): stage 0 (the source) and stage 1 (the deterministic intent with its unsigned candidate v6), the sticky
// possession proofs (stage 2), the assembly (stage 3), the readiness (stage 4) and the view certificate a Freeze v5 carries (design section
// 5.3, schema section 10).
//
// The message types and their signing targets are the frozen ones of vrschema (aliased here, never redefined); this package adds what the
// schema leaves to the implementations: the derivation of the intent, the successor body and the successor trust base from committed root
// state and VR, and the signing and verification of every stage over them. Every function is pure.
package vrhandoff

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrschema"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The protocol messages, exactly as frozen (schema section 10).
type (
	Source            = vrschema.Source
	Intent            = vrschema.Intent
	PoPOffer          = vrschema.PoPOffer
	Assembly          = vrschema.Assembly
	Readiness         = vrschema.Readiness
	ViewCertificate   = vrschema.ViewCertificate
	SupportCommitment = vrschema.SupportCommitment
)

var (
	// ErrIntent reports an intent that cannot be derived from the given state: R is not the Published open output, the served preimages
	// are not the ones VR committed, or the candidate they make fails the H3 shape checks.
	ErrIntent = errors.New("vrhandoff: intent")
	// ErrAssembly reports an assembly that is not the intent's unsigned candidate with one valid possession proof per successor validator.
	ErrAssembly = errors.New("vrhandoff: assembly")
	// ErrReadiness reports a readiness that cannot be signed or does not verify.
	ErrReadiness = errors.New("vrhandoff: readiness")
)

// RootContext is the committed root state an intent is derived over (design section 5.3.1 stage 1): the VR generation, the root's network
// and Q3 genesis identity, the root epoch and the predecessor body (the root's authority), the attempt with the committed round at which it
// became plannable, the installed configuration of the EVM shard, its lifecycle (K, the acknowledged committee, and its assignment hash)
// and the fold's input.
type RootContext struct {
	Deployment       vradmit.Deployment
	Genesis          [32]byte
	RootEpoch        uint64
	Predecessor      [32]byte
	Attempt          uint64
	AttemptOpenRound uint64
	Installed        *types.PartitionDescriptionRecord
	Lifecycle        evmassign.LifecycleContext
	Fold             vrschema.FoldInput
}

// Output is VR's output R at one certified EVM block: State is proven against that block's state root (rootchain/vrstate), Members and
// Changes are served by VR's views (the captured bindings' preimages and the bound change payloads) and are trusted only once they hash to
// the proven digests (schema FD-16). Changes carry no verdict: the roots fold them.
type Output struct {
	State   vradmit.OutputState
	Members []evmassign.Identity
	Changes []vrschema.RegistryChange
}

// RootView and OutputView are the read sides DeriveIntent takes (design section 5.3.6): committed root history, and VR at one certified
// EVM block verified against its state root.
type RootView interface {
	// CommittedSource is stage 0 of R: the first certified EVM block at which R is Published, from committed history.
	CommittedSource(resultID [32]byte) (Source, bool, error)
	// Context is the committed root state the intent is derived over.
	Context() (RootContext, error)
}

type OutputView interface {
	Output(resultID [32]byte) (Output, error)
}

// DeriveIntent is stages 0 and 1: R's committed source and the intent over the root's committed state and VR's output.
func DeriveIntent(r RootView, v OutputView, src Source) (Intent, [32]byte, error) {
	var none [32]byte
	if len(src.ResultID) != 32 {
		return Intent{}, none, fmt.Errorf("%w: source without a result id", ErrIntent)
	}
	rc, err := r.Context()
	if err != nil {
		return Intent{}, none, err
	}
	o, err := v.Output([32]byte(src.ResultID))
	if err != nil {
		return Intent{}, none, err
	}
	return NewIntent(rc, src, o)
}

// AnchorRound is max(source.certRootRound, attemptOpenRound).
func AnchorRound(src Source, attemptOpenRound uint64) uint64 {
	return vrschema.AnchorRound(src.CertRootRound, attemptOpenRound)
}

// NewIntent is stage 1 over an explicit root context and output: the unsigned candidate v6 (UnsignedCandidate), the source it rests on and
// the anchor max(source.certRootRound, attemptOpenRound). It returns the intent and its digest.
func NewIntent(rc RootContext, src Source, o Output) (Intent, [32]byte, error) {
	var none [32]byte
	c, err := UnsignedCandidate(rc, o)
	if err != nil {
		return Intent{}, none, err
	}
	r := o.State.ResultID
	if !bytes.Equal(src.ResultID, r[:]) || !bytes.Equal(src.OutputCommit, o.State.Output.OutputCommit[:]) || len(src.EVMBlockHash) != 32 {
		return Intent{}, none, fmt.Errorf("%w: the source is not R's published output", ErrIntent)
	}
	raw, err := c.Encode()
	if err != nil {
		return Intent{}, none, errors.Join(ErrIntent, err)
	}
	in := Intent{Version: vrschema.IntentVersion, Network: rc.Deployment.RootNetwork, Genesis: bytes.Clone(rc.Genesis[:]),
		PredecessorBodyID: bytes.Clone(rc.Predecessor[:]), Attempt: rc.Attempt, AnchorRound: AnchorRound(src, rc.AttemptOpenRound),
		Source: Source{ResultID: bytes.Clone(src.ResultID), EVMBlockHash: bytes.Clone(src.EVMBlockHash), EVMBlockNumber: src.EVMBlockNumber,
			CertRootRound: src.CertRootRound, OutputCommit: bytes.Clone(src.OutputCommit)}, Candidate: raw}
	d, err := in.Digest()
	if err != nil {
		return Intent{}, none, errors.Join(ErrIntent, err)
	}
	return in, d, nil
}

// UnsignedCandidate is the intent's candidate v6 (PoPs empty, verdicts set): exactly what VR's output R and the committed root state
// determine, so every root and every successor derives the same bytes.
//   - R is the open, Published output over the acknowledged result, and every served preimage hashes to what VR committed: the members to
//     membersDigest, K (the acknowledged committee) to kDigest, the changes to changesDigest, all of it to outputCommit;
//   - the successor assignment is the installed configuration with J's EVM validators (weight = the quantized weight), the root members and
//     bindings are J's, the authorization is K's with R's snapshot and policy digests;
//   - the verdicts are FoldVerdicts over the committed fold input;
//   - the candidate passes the H3 shape checks (successor, coupling, identities) and the lifecycle (K, continuity, no pending primary).
func UnsignedCandidate(rc RootContext, o Output) (vrschema.CandidateV6, error) {
	var c vrschema.CandidateV6
	s, out, d := o.State, o.State.Output, rc.Deployment
	r := s.ResultID
	switch {
	case rc.Installed == nil:
		return c, fmt.Errorf("%w: no installed EVM configuration", ErrIntent)
	case s.Network != d.NetworkWord:
		return c, fmt.Errorf("%w: VR's network word is not the deployment's", ErrIntent)
	case r == (vrschema.Word{}) || s.OpenOutput != r || out.State != vrschema.OutPublished:
		return c, fmt.Errorf("%w: R is not the open Published output", ErrIntent)
	case s.PendingPair != (vrschema.Word{}) || rc.Lifecycle.Pending != 0:
		return c, fmt.Errorf("%w: an assignment awaits its acknowledgement", ErrIntent)
	}
	j := append([]evmassign.Identity(nil), o.Members...)
	sort.Slice(j, func(a, b int) bool { return bytes.Compare(j[a].StakingID, j[b].StakingID) < 0 })
	if len(j) == 0 || len(j) > vrschema.MaxCommittee {
		return c, fmt.Errorf("%w: %d members", ErrIntent, len(j))
	}
	if err := vradmit.VerifyMembers(j, out.MembersDigest); err != nil {
		return c, errors.Join(ErrIntent, err)
	}
	k := rc.Lifecycle.Incumbent
	kd, err := vradmit.MembersDigestOf(k)
	if err != nil || kd != out.KDigest {
		return c, errors.Join(ErrIntent, errors.New("K is not the acknowledged committee VR captured"), err)
	}
	changes := append([]vrschema.RegistryChange(nil), o.Changes...)
	sort.Slice(changes, func(a, b int) bool { return changes[a].ID < changes[b].ID })
	chd, err := vrschema.ChangesDigestOf(changes)
	if err != nil || chd != out.ChangesDigest {
		return c, errors.Join(ErrIntent, errors.New("the served changes are not the ones VR bound"), err)
	}
	commit := vrschema.OutputCommit(vrschema.OutputCommitInput{Network: s.Network, ChainID: d.ChainID, Registry: d.Registry, ResultID: r,
		Predecessor: out.Predecessor, Attempt: out.Attempt, ModuleTag: out.ModuleTag, Native: out.Native, SnapshotDigest: out.SnapshotDigest,
		PolicyDigest: out.PolicyDigest, MembersDigest: out.MembersDigest, KDigest: out.KDigest, ChangesDigest: out.ChangesDigest})
	if commit != out.OutputCommit {
		return c, fmt.Errorf("%w: outputCommit does not recompute", ErrIntent)
	}
	verdicts, err := vrschema.FoldVerdicts(rc.Fold, changes)
	if err != nil {
		return c, errors.Join(ErrIntent, err)
	}
	for i := range changes {
		changes[i].Verdict = uint64(verdicts[i])
	}
	validators := make([]*types.NodeInfo, 0, len(j))
	root := make([]evmassign.RootMember, 0, len(j))
	bindings := make([]evmassign.Binding, 0, len(j))
	for _, m := range j {
		validators = append(validators, &types.NodeInfo{NodeID: m.EVMNodeID, SigKey: bytes.Clone(m.EVMKey), Stake: m.Weight})
		root = append(root, evmassign.RootMember{NodeID: m.RootNodeID, Key: bytes.Clone(m.RootKey), Weight: m.Weight})
		bindings = append(bindings, evmassign.Binding{RootNodeID: m.RootNodeID, EVMNodeID: m.EVMNodeID})
	}
	sort.Slice(root, func(a, b int) bool { return root[a].NodeID < root[b].NodeID })
	sort.Slice(bindings, func(a, b int) bool { return bindings[a].RootNodeID < bindings[b].RootNodeID })
	succ, err := evmassign.NewSuccessor(rc.Installed, validators)
	if err != nil {
		return c, errors.Join(ErrIntent, err)
	}
	rules := weightvalidation.EVMRules(weightvalidation.ModeWeighted)
	if err := errors.Join(evmassign.ValidateSuccessorWith(rules, rc.Installed, succ), evmassign.ValidateCoupling(root, succ, bindings),
		evmassign.ValidateIdentities(j, root, succ, bindings)); err != nil {
		return c, errors.Join(ErrIntent, err)
	}
	assignment, err := types.Cbor.Marshal(succ)
	if err != nil {
		return c, errors.Join(ErrIntent, err)
	}
	old, err := evmassign.PDRHash(rc.Installed)
	if err != nil {
		return c, errors.Join(ErrIntent, err)
	}
	exposure, err := evmassign.ExposureCommit(k)
	if err != nil {
		return c, errors.Join(ErrIntent, err)
	}
	chain, err := vrschema.WordU64(d.ChainID)
	if err != nil {
		return c, errors.Join(ErrIntent, err)
	}
	contracts, snap, pol := d.ContractsDigest(), vradmit.AuthorizationWord(out.SnapshotDigest), vradmit.AuthorizationWord(out.PolicyDigest)
	auth := &evmassign.Authorization{Network: d.RootNetwork, Chain: chain, Contracts: contracts[:], ResultID: bytes.Clone(r[:]),
		SnapshotDigest: snap[:], BaseRootBodyID: bytes.Clone(rc.Predecessor[:]), BaseAssignmentHash: bytes.Clone(rc.Lifecycle.IncumbentAssignment[:]),
		K: k, ExposureDigest: exposure[:], Policies: pol[:]}
	c = vrschema.CandidateV6{Version: vrschema.CandidateV6Version, Kind: evmassign.KindPrimary, Network: d.RootNetwork, Predecessor: bytes.Clone(rc.Predecessor[:]),
		Attempt: rc.Attempt, RootMembers: root, OldShardEpoch: rc.Installed.Epoch, OldActiveHash: old[:], Assignment: assignment, PoPs: []evmassign.PoP{},
		Bindings: bindings, Identities: j, Authorization: auth, SourceRef: bytes.Clone(r[:]), RegistryChanges: changes}
	if err := evmassign.VerifyLifecycle(vradmit.V5Of(c), rc.Lifecycle); err != nil {
		return c, errors.Join(ErrIntent, err)
	}
	if _, err := c.Encode(); err != nil {
		return c, errors.Join(ErrIntent, err)
	}
	return c, nil
}

// CandidateOf decodes the intent's unsigned candidate.
func CandidateOf(i Intent) (vrschema.CandidateV6, error) {
	c, err := vrschema.DecodeCandidateV6(i.Candidate)
	if err != nil {
		return c, errors.Join(ErrIntent, err)
	}
	if len(c.PoPs) != 0 || c.Kind != evmassign.KindPrimary {
		return c, fmt.Errorf("%w: the intent's candidate is not an unsigned primary", ErrIntent)
	}
	return c, nil
}

// PoPContext is the possession-proof context of the intent's successor (today's evmassign.PoPMessage context) and its successor assignment.
func PoPContext(i Intent) (evmassign.PoPContext, *types.PartitionDescriptionRecord, error) {
	var ctx evmassign.PoPContext
	c, err := CandidateOf(i)
	if err != nil {
		return ctx, nil, err
	}
	succ, err := vradmit.V5Of(c).Successor()
	if err != nil {
		return ctx, nil, errors.Join(ErrIntent, err)
	}
	ids, err := evmassign.IdentitiesDigest(c.Identities)
	if err != nil {
		return ctx, nil, errors.Join(ErrIntent, err)
	}
	if len(i.PredecessorBodyID) != 32 {
		return ctx, nil, fmt.Errorf("%w: predecessor", ErrIntent)
	}
	ctx = evmassign.PoPContext{Network: i.Network, Predecessor: [32]byte(i.PredecessorBodyID), Attempt: i.Attempt, Identities: ids}
	return ctx, succ, nil
}

// SignPoP is stage 2 for one successor EVM key: the possession proof of today's evmassign.PoPMessage under the intent's context. A signer
// persists and re-serves its first proof per (intent, member) (sticky); this function only makes one.
func SignPoP(i Intent, self evmassign.Identity, s abcrypto.Signer) (PoPOffer, error) {
	d, err := i.Digest()
	if err != nil {
		return PoPOffer{}, errors.Join(ErrIntent, err)
	}
	ctx, succ, err := PoPContext(i)
	if err != nil {
		return PoPOffer{}, err
	}
	p, err := evmassign.SignPoP(s, ctx, succ, self.EVMNodeID)
	if err != nil {
		return PoPOffer{}, errors.Join(ErrAssembly, err)
	}
	return PoPOffer{IntentDigest: d[:], EVMNodeID: self.EVMNodeID, PoP: p}, nil
}

// VerifyPoP checks one offer: for this intent, by a successor validator, valid under the intent's context.
func VerifyPoP(i Intent, p PoPOffer) error {
	d, err := i.Digest()
	if err != nil {
		return errors.Join(ErrIntent, err)
	}
	if !bytes.Equal(p.IntentDigest, d[:]) || p.PoP.NodeID != p.EVMNodeID {
		return fmt.Errorf("%w: a possession proof of another intent or node", ErrAssembly)
	}
	ctx, succ, err := PoPContext(i)
	if err != nil {
		return err
	}
	for _, v := range succ.Validators {
		if v.NodeID == p.EVMNodeID {
			return verifyOnePoP(ctx, succ, v, p.PoP)
		}
	}
	return fmt.Errorf("%w: %s is not a successor validator", ErrAssembly, p.EVMNodeID)
}

// verifyOnePoP is evmassign.VerifyPoPs for one validator of the successor: its node and key, the one accepted encoding (low s, a recovery
// byte that recovers the key) of a signature over the possession message of the whole assignment.
func verifyOnePoP(ctx evmassign.PoPContext, succ *types.PartitionDescriptionRecord, v *types.NodeInfo, p evmassign.PoP) error {
	if p.NodeID != v.NodeID || !bytes.Equal(p.Key, v.SigKey) || len(p.Signature) != ethcrypto.SignatureLength {
		return fmt.Errorf("%w: the proof does not name validator %q", ErrAssembly, v.NodeID)
	}
	ver, err := abcrypto.NewVerifierSecp256k1(v.SigKey)
	if err != nil {
		return errors.Join(ErrAssembly, err)
	}
	msg, err := evmassign.PoPMessage(ctx, succ, v.NodeID)
	if err != nil {
		return errors.Join(ErrAssembly, err)
	}
	if err := ver.VerifyBytes(p.Signature, msg); err != nil {
		return fmt.Errorf("%w: validator %q: %w", ErrAssembly, v.NodeID, err)
	}
	digest := sha256.Sum256(msg)
	if pub, err := ethcrypto.SigToPub(digest[:], p.Signature); err != nil || !bytes.Equal(ethcrypto.CompressPubkey(pub), v.SigKey) {
		return fmt.Errorf("%w: validator %q: the recovery byte does not recover the key", ErrAssembly, v.NodeID)
	}
	return nil
}

// AssemblerOrder lists the incumbents ascending by SHA-256(intentDigest || nodeID); the assembler of view v is order[v mod n].
func AssemblerOrder(intent [32]byte, incumbents []string) []string {
	return vrschema.AssemblerOrder(intent, incumbents)
}

// Assembler is the assembler of view v.
func Assembler(intent [32]byte, incumbents []string, view uint64) string {
	return vrschema.Assembler(vrschema.AssemblerOrder(intent, incumbents), view)
}

// Assemble is the candidate of stage 3: the intent's unsigned candidate with one verified possession proof per successor validator, in
// the successor assignment's (EVM node) order. Any valid proof of a member is accepted: two encodings that both verify both assemble.
// It returns the candidate, its canonical v6 bytes and their digest.
func Assemble(i Intent, pops []PoPOffer) (vrschema.CandidateV6, []byte, [32]byte, error) {
	var none [32]byte
	c, err := CandidateOf(i)
	if err != nil {
		return c, nil, none, err
	}
	_, succ, err := PoPContext(i)
	if err != nil {
		return c, nil, none, err
	}
	byNode := map[string]evmassign.PoP{}
	for _, p := range pops {
		if _, dup := byNode[p.EVMNodeID]; dup {
			continue // sticky: the first verified proof of a member is kept
		}
		if err := VerifyPoP(i, p); err != nil {
			return c, nil, none, err
		}
		byNode[p.EVMNodeID] = p.PoP
	}
	c.PoPs = make([]evmassign.PoP, 0, len(succ.Validators))
	for _, v := range succ.Validators {
		p, ok := byNode[v.NodeID]
		if !ok {
			return c, nil, none, fmt.Errorf("%w: no possession proof of %s", ErrAssembly, v.NodeID)
		}
		c.PoPs = append(c.PoPs, p)
	}
	raw, err := c.Encode()
	if err != nil {
		return c, nil, none, errors.Join(ErrAssembly, err)
	}
	return c, raw, sha256.Sum256(raw), nil
}

// SignAssembly signs the assembly of view slot with the assembler's root key.
func SignAssembly(i Intent, slot uint64, candidate []byte, s abcrypto.Signer) (Assembly, error) {
	d, err := i.Digest()
	if err != nil {
		return Assembly{}, errors.Join(ErrIntent, err)
	}
	a := Assembly{IntentDigest: d[:], Slot: slot, Candidate: bytes.Clone(candidate)}
	msg, err := a.SignedBytes()
	if err != nil {
		return Assembly{}, err
	}
	if a.Sig, err = s.SignBytes(msg); err != nil {
		return Assembly{}, err
	}
	return a, nil
}

// VerifyAssembly is the full semantic verification of an assembly against the intent (design sections 5.3.3 and 5.3.5 item 3): it names
// the intent, its candidate is exactly the intent's unsigned candidate plus one possession proof per successor validator in EVM node
// order, and every proof verifies (bytes are verified, not compared). The assembler's signature is checked by the caller, who knows the
// committed view and its assembler (VerifyAssemblySig, or vradmit.VerifyCertificate at Freeze).
func VerifyAssembly(i Intent, a Assembly) (vrschema.CandidateV6, error) {
	d, err := i.Digest()
	if err != nil {
		return vrschema.CandidateV6{}, errors.Join(ErrIntent, err)
	}
	if !bytes.Equal(a.IntentDigest, d[:]) {
		return vrschema.CandidateV6{}, fmt.Errorf("%w: of another intent", ErrAssembly)
	}
	c, err := vrschema.DecodeCandidateV6(a.Candidate)
	if err != nil {
		return c, errors.Join(ErrAssembly, err)
	}
	unsigned := c
	unsigned.PoPs = []evmassign.PoP{}
	raw, err := unsigned.Encode()
	if err != nil || !bytes.Equal(raw, i.Candidate) {
		return c, fmt.Errorf("%w: the candidate is not the intent's with possession proofs", ErrAssembly)
	}
	ctx, succ, err := PoPContext(i)
	if err != nil {
		return c, err
	}
	if err := evmassign.VerifyPoPs(ctx, succ, c.PoPs); err != nil {
		return c, errors.Join(ErrAssembly, err)
	}
	return c, nil
}

// VerifyAssemblySig checks the assembly's signature by the assembler of its slot among the incumbents (node id to root key).
func VerifyAssemblySig(a Assembly, incumbents map[string][]byte) error {
	ids := make([]string, 0, len(incumbents))
	for id := range incumbents {
		ids = append(ids, id)
	}
	if len(ids) == 0 || len(a.IntentDigest) != 32 {
		return fmt.Errorf("%w: no incumbents", ErrAssembly)
	}
	who := Assembler([32]byte(a.IntentDigest), ids, a.Slot)
	msg, err := a.SignedBytes()
	if err != nil {
		return err
	}
	if err := vrschema.Verify(incumbents[who], a.Sig, msg); err != nil {
		return fmt.Errorf("%w: not signed by view %d's assembler %s: %w", ErrAssembly, a.Slot, who, err)
	}
	return nil
}

// BodyContext is what the successor body needs from the root's verified history beyond the intent: the predecessor link of a body that
// succeeds the current epoch (q3format.Prior of the installed body) and the chain's protocol configuration.
type BodyContext struct {
	PredecessorLink []byte
	Config          q3format.ProtocolConfig
}

// EarliestActivation is the body's earliest bound, anchorRound + 16.
func EarliestActivation(i Intent) uint64 { return vrschema.EarliestActivation(i.AnchorRound) }

// members is J's root committee as the body carries it, ascending by node id, with its quorum threshold.
func members(i Intent) (evmroot.WeightSet, uint64, error) {
	c, err := CandidateOf(i)
	if err != nil {
		return nil, 0, err
	}
	ws := make(evmroot.WeightSet, 0, len(c.RootMembers))
	var total quorumweight.Tally
	for _, m := range c.RootMembers {
		ws = append(ws, evmroot.Member{StakingID: m.NodeID, NodeID: m.NodeID, ConsensusKey: bytes.Clone(m.Key), Weight: m.Weight})
		if err := total.Add(m.NodeID, m.Weight); err != nil {
			return nil, 0, errors.Join(ErrIntent, err)
		}
	}
	sort.Slice(ws, func(a, b int) bool { return ws[a].NodeID < ws[b].NodeID })
	threshold, err := quorumweight.Threshold(total.Weight())
	if err != nil {
		return nil, 0, errors.Join(ErrIntent, err)
	}
	return ws, threshold, nil
}

// DeriveBody is the successor body V3 of an assembled candidate (its digest): network, the next root epoch, J's root committee and
// threshold, the pre-freeze summary of (network, predecessor, attempt), the change record over the assembled candidate's digest and the
// earliest activation anchorRound + 16 (an earliest bound only: the activation round is fixed at commit), the predecessor link and the
// protocol configuration. The body is per assembly: two valid PoP encodings make two candidates and two bodies.
func DeriveBody(i Intent, rootEpoch uint64, candidateDigest [32]byte, bc BodyContext) (q3format.BodyV3, error) {
	ws, threshold, err := members(i)
	if err != nil {
		return q3format.BodyV3{}, err
	}
	if rootEpoch == ^uint64(0) || i.AnchorRound > ^uint64(0)-vrschema.EarliestOffset {
		return q3format.BodyV3{}, fmt.Errorf("%w: epoch or anchor overflow", ErrIntent)
	}
	zero := make([]byte, 32)
	earliest := EarliestActivation(i)
	b := q3format.BodyV3{Network: i.Network, Epoch: rootEpoch + 1, EarliestActivation: earliest, Members: ws, RootThreshold: threshold,
		StateSummary:     evmroot.D4PreFreezeSummary(i.Network, i.PredecessorBodyID, i.Attempt, 0, zero, zero),
		ChangeRecordHash: evmroot.D4CandidateContextHash(i.Network, i.PredecessorBodyID, i.Attempt, candidateDigest[:], earliest),
		PredecessorHash:  bytes.Clone(bc.PredecessorLink), Config: bc.Config}
	if err := b.Validate(); err != nil {
		return b, errors.Join(ErrIntent, err)
	}
	return b, nil
}

// TrustBase is the successor trust base derived from the intent, which every readiness signs (trustBaseSig): J's root committee with its
// weights and quorum threshold for the next root epoch, starting at the earliest activation, unsigned; and its signing bytes.
func TrustBase(i Intent, rootEpoch uint64) (*types.RootTrustBaseV1, []byte, error) {
	ws, threshold, err := members(i)
	if err != nil {
		return nil, nil, err
	}
	nodes := make([]*types.NodeInfo, len(ws))
	for n, m := range ws {
		nodes[n] = &types.NodeInfo{NodeID: m.NodeID, SigKey: bytes.Clone(m.ConsensusKey), Stake: m.Weight}
	}
	tb, err := quorumweight.NewTrustBase(types.NetworkID(i.Network), nodes, types.WithEpoch(rootEpoch+1), types.WithEpochStart(EarliestActivation(i)),
		types.WithQuorumThreshold(threshold))
	if err != nil {
		return nil, nil, errors.Join(ErrIntent, err)
	}
	raw, err := tb.SigBytes()
	if err != nil {
		return nil, nil, errors.Join(ErrIntent, err)
	}
	return tb, raw, nil
}

// SignReadiness is stage 4 for one successor member: over a fully verified assembly (the caller has verified it, VerifyAssembly), the
// member's q3format receipt over the body's receipt context, its signature over the successor trust base (TrustBase), its support
// commitments (strictly ascending ruleId) and the envelope, all by its root key. A member signs at most one assembly per view; the caller
// persists (intent, view, candidate digest) before releasing it.
func SignReadiness(i Intent, a Assembly, body q3format.BodyV3, self string, trustBase []byte, commitments []SupportCommitment, s abcrypto.Signer) (Readiness, error) {
	cd := sha256.Sum256(a.Candidate)
	receipt, err := q3format.SignReceipt(q3format.ContextFor(body, i.Attempt, cd), self, s)
	if err != nil {
		return Readiness{}, errors.Join(ErrReadiness, err)
	}
	enc, err := vrschema.EncodeReadinessReceipt(receipt)
	if err != nil {
		return Readiness{}, errors.Join(ErrReadiness, err)
	}
	rs, err := vrschema.RuleSupportDigest(commitments)
	if err != nil {
		return Readiness{}, errors.Join(ErrReadiness, err)
	}
	tbs, err := s.SignBytes(trustBase)
	if err != nil {
		return Readiness{}, errors.Join(ErrReadiness, err)
	}
	id := body.Identity()
	r := Readiness{IntentDigest: bytes.Clone(a.IntentDigest), Slot: a.Slot, CandidateDigest: cd[:], BodyID: id[:], RuleSupportDigest: rs[:],
		Commitments: commitments, Receipt: enc, TrustBaseSig: tbs}
	env, err := r.EnvelopeBytes()
	if err != nil {
		return Readiness{}, errors.Join(ErrReadiness, err)
	}
	if r.EnvelopeSig, err = s.SignBytes(env); err != nil {
		return Readiness{}, errors.Join(ErrReadiness, err)
	}
	return r, nil
}

// SignCommitment signs one rule-support commitment of a member's exact binding.
func SignCommitment(network uint64, m evmassign.Identity, rule, release vrschema.Word, s abcrypto.Signer) (SupportCommitment, error) {
	c := SupportCommitment{Network: network, StakingID: bytes.Clone(m.StakingID), Generation: m.Generation, RootKeyHash: ethcrypto.Keccak256(m.RootKey),
		RuleID: bytes.Clone(rule[:]), ReleaseDigest: bytes.Clone(release[:])}
	msg, err := c.SignedBytes()
	if err != nil {
		return c, err
	}
	c.Sig, err = s.SignBytes(msg)
	return c, err
}

// Certificate is the view certificate of an assembly: exactly one readiness per successor member, in the candidate's identity order
// (ascending StakingID). Readiness of other members, of another view or of another body is not taken.
func Certificate(a Assembly, successors []evmassign.Identity, readiness map[string]Readiness, bodyID [32]byte) (ViewCertificate, error) {
	cd := sha256.Sum256(a.Candidate)
	c := ViewCertificate{Assembly: a, Readiness: make([]Readiness, 0, len(successors))}
	for _, m := range successors {
		r, ok := readiness[m.RootNodeID]
		if !ok || r.Slot != a.Slot || !bytes.Equal(r.IntentDigest, a.IntentDigest) || !bytes.Equal(r.CandidateDigest, cd[:]) || !bytes.Equal(r.BodyID, bodyID[:]) {
			return c, fmt.Errorf("%w: no readiness of %s for this assembly", ErrReadiness, m.RootNodeID)
		}
		c.Readiness = append(c.Readiness, r)
	}
	return c, nil
}

// VerifyCertificate is Freeze validity items 2 to 4 (design section 5.3.5) over the intent and its successor body: vradmit's check, the
// one the executor runs.
func VerifyCertificate(in vradmit.CertificateInput) error { return vradmit.VerifyCertificate(in) }

// VerifyHandoffView is the replay rule of control op 5.
func VerifyHandoffView(r vrschema.HandoffViewReplay, view, blockUCTime uint64) error {
	return vrschema.VerifyHandoffView(r, view, blockUCTime)
}

// ViewTimeoutSeconds is T(L, v) = 10 * 2^(L + floor(v/n)) seconds, never when saturated.
func ViewTimeoutSeconds(level uint8, view uint64, n uint32) (secs uint64, never bool) {
	return vrschema.ViewTimeoutSeconds(level, view, n)
}

// CertificateAdmissible says whether a complete certificate of certView may still be carried: any complete certificate of a committed
// view (including a late one of an earlier view retained in I-RET) until the first Freeze commits.
func CertificateAdmissible(certView, committedView uint64, freezeCommitted bool) bool {
	return vrschema.CertificateAdmissible(certView, committedView, freezeCommitted)
}

// LeaderChoice is the proposer policy (design section 5.3.2 "Proposer priority" and section 5.6): a due rejection first, then a Prepare
// when a complete verified certificate is held and the gates hold, then a due HandoffView.
func LeaderChoice(certComplete, gatesHold, viewDue, rejectionDue, quietForPrepare bool) string {
	return vrschema.LeaderChoice(certComplete, gatesHold, viewDue, rejectionDue, quietForPrepare)
}

// Deadline is openTime + T(L, v) with the carry check: never is a deadline no timestamp meets.
func Deadline(open uint64, level uint8, view uint64, n uint32) (at uint64, never bool) {
	return vrschema.Deadline(open, level, view, n)
}
