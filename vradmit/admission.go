// Package vradmit is the root's judgment of the validator registry (VR) generation (VT-05a, ristik/bft-core#1145): registry-mode
// admission of a candidate v6 against VR proven at the frozen parent (design section 5.2), the RejectResult v2 due table, the
// HolderRetirement v2 verdict, rule support and its committed table (section 7.3), the HandoffView replay rule and the live-vote
// residence rule (section 5.3.2), and the root's VR control state with the backoff machine (section 5.5).
//
// Every function is pure: the proven VR words come from rootchain/vrstate, the committed root facts from the executor. The frozen
// reference vrschema is used directly for every encoding, digest, fold, gate and transition it defines; this package adds only the
// composition the schema leaves to the roots.
package vradmit

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-core/continuity"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// OutputState is what VR proves about one result R at a certified EVM state: V+0 to V+4, V+6 and outputs[R].
type OutputState struct {
	ResultID    vrschema.Word
	Network     vrschema.Word
	OpenOutput  vrschema.Word
	LastAcked   vrschema.Word
	PendingPair vrschema.Word
	Limits      vrschema.CommitteeLimits
	Status      vrschema.Status
	Output      vrschema.OutputRecord
}

// Deployment names the VR generation the roots judge: the root network id, VR's network word and chain id word (the EVM-side
// deployment domain), VR's address and code hash (pinned in the genesis EVM PDR).
type Deployment struct {
	RootNetwork  uint64
	NetworkWord  vrschema.Word
	ChainID      vrschema.Word
	Registry     [20]byte
	RegistryCode [32]byte
}

// ContractsDigest is the Authorization.Contracts a VR-mode candidate carries: keccak256(abi.encode(VR address, VR code hash)). The
// schema leaves the field to the roots; it binds the recovery authorization to the one pinned VR generation.
func (d Deployment) ContractsDigest() vrschema.Word {
	return vrschema.Keccak(func() []byte { w := vrschema.AddrWord(d.Registry); return w[:] }(), d.RegistryCode[:])
}

// The refusals, one per design section 5.2 item.
var (
	ErrAdmission    = errors.New("vradmit: registry output refused")
	ErrNetwork      = fmt.Errorf("%w: (1) VR network word", ErrAdmission)
	ErrNotOpen      = fmt.Errorf("%w: (2) R is not the open Published output over the acknowledged result", ErrAdmission)
	ErrCommit       = fmt.Errorf("%w: (3) outputCommit does not recompute from the candidate", ErrAdmission)
	ErrLimits       = fmt.Errorf("%w: (4) committee limits", ErrAdmission)
	ErrH3           = fmt.Errorf("%w: (5) H3 candidate checks", ErrAdmission)
	ErrVerdicts     = fmt.Errorf("%w: (6) verdicts are not FoldVerdicts", ErrAdmission)
	ErrAckGate      = fmt.Errorf("%w: (6) shard acknowledgement gate", ErrAdmission)
	ErrActivation   = fmt.Errorf("%w: (7) activation gates", ErrAdmission)
	ErrInconsistent = fmt.Errorf("%w: (8) VR health is Inconsistent at P", ErrAdmission)
	ErrCertificate  = fmt.Errorf("%w: (9) view certificate", ErrAdmission)
	ErrResolved     = fmt.Errorf("%w: the result is already resolved", ErrAdmission)
)

// MemberOf is the VR member of one identity record: the id is the StakingID's uint64, the node words keccak256 of the node ids, the
// key hashes keccak256 of the 33-byte keys. Every preimage the roots hold is bound to VR only through these words.
func MemberOf(i evmassign.Identity) (vrschema.Member, error) {
	id, err := evmassign.CustodyID(i.StakingID)
	if err != nil {
		return vrschema.Member{}, err
	}
	rw, err1 := evmassign.NodeIDWord(i.RootNodeID)
	ew, err2 := evmassign.NodeIDWord(i.EVMNodeID)
	if err := errors.Join(err1, err2); err != nil {
		return vrschema.Member{}, err
	}
	if len(i.RootKey) != evmassign.KeyLen || len(i.EVMKey) != evmassign.KeyLen || len(i.OperatorPayee) != 20 || len(i.ExposureDigest) != 32 {
		return vrschema.Member{}, fmt.Errorf("%w: identity %d field widths", evmassign.ErrIdentity, id)
	}
	return vrschema.Member{ID: id, Generation: i.Generation, Weight: i.Weight, RawWeight: i.RawWeight, RootNodeWord: rw,
		RootKeyHash: vrschema.Word(ethcrypto.Keccak256Hash(i.RootKey)), EVMNodeWord: ew, EVMKeyHash: vrschema.Word(ethcrypto.Keccak256Hash(i.EVMKey)),
		Payee: [20]byte(i.OperatorPayee), ExposureDigest: vrschema.Word(i.ExposureDigest)}, nil
}

// MembersDigestOf is VR's membersDigest of identity records in ascending StakingID (the ids then ascend too).
func MembersDigestOf(ids []evmassign.Identity) (vrschema.Word, error) {
	ms := make([]vrschema.Member, 0, len(ids))
	for _, i := range ids {
		m, err := MemberOf(i)
		if err != nil {
			return vrschema.Word{}, err
		}
		ms = append(ms, m)
	}
	return vrschema.MembersDigest(ms)
}

// VerifyMembers hash-verifies identity records served by an unproven view (the captured-binding preimages of FD-16) against a proven
// membersDigest: the roots never take a node id, key or payee on a server's word.
func VerifyMembers(ids []evmassign.Identity, proven vrschema.Word) error {
	d, err := MembersDigestOf(ids)
	if err != nil {
		return err
	}
	if d != proven {
		return fmt.Errorf("%w: the served bindings are not the ones VR captured", ErrCommit)
	}
	return nil
}

// LimitsSatisfied is design section 5.2 item 4 for a module output: nMin <= |S| <= nMax, or |S| strictly closer to the range than |O|.
func LimitsSatisfied(l vrschema.CommitteeLimits, o, s int) bool {
	dist := func(x int) int {
		switch {
		case x < int(l.NMin):
			return int(l.NMin) - x
		case x > int(l.NMax):
			return x - int(l.NMax)
		}
		return 0
	}
	return dist(s) == 0 || dist(s) < dist(o)
}

// Admission is everything VerifyRegistryOutput judges. The candidate is the decoded canonical v6 of the certified assembly; State is VR
// proven at P (the frozen parent bound by Prepare); the rest is committed root state at the Freeze block.
type Admission struct {
	Deployment Deployment
	Candidate  vrschema.CandidateV6
	State      OutputState
	// Acknowledged is the root's acknowledged result: the retained candidate's Authorization.ResultID, or GENESIS_RESULT.
	Acknowledged vrschema.Word
	// Resolved reports a committed RejectResult, Abort closure or acknowledgement of R (a resolved R never gets a Freeze).
	Resolved bool
	// Verify is the H3 context: the candidate's PoP context, successor root members, control partition and weight rules, and the
	// installed EVM configuration with its root committee (Digest is filled here).
	Verify evmassign.VerifyContext
	// Lifecycle is the acknowledged committee (K, the incumbent), the continuity policy and the pending chain.
	Lifecycle evmassign.LifecycleContext
	// Fold is the verdicts' input; Acked and EVMAcked the acknowledgement gate's shard facts at the Freeze block.
	Fold     vrschema.FoldInput
	Acked    map[vrschema.ShardKey]bool
	EVMAcked bool
	// PrepareUCTime is the UC time of the Prepare (the activation time gate).
	PrepareUCTime uint64
	// Support carries the committed support table and the Freeze's rule-support evidence; admission fills in the rest of the gate's
	// input from the fold context, the candidate and the certificate. Certificate is the view certificate's input.
	Support     SupportInput
	Certificate CertificateInput
}

// Verified is what admission establishes: the v5 view of the candidate (for the existing install path), its successor assignment and
// the fold verdicts.
type Verified struct {
	V5        evmassign.Candidate
	Successor []byte
	Verdicts  []uint8
}

// V5Of is the candidate v6 as the v5 candidate the H3 checks and the install path read: the same fields, Version 5, no Changes and no
// SourceRef (the aggregator changes are derived from the Accepted RegistryChanges, never carried twice).
func V5Of(c vrschema.CandidateV6) evmassign.Candidate {
	return evmassign.Candidate{Version: evmassign.CandidateVersion, Kind: c.Kind, Network: c.Network, Predecessor: c.Predecessor, Attempt: c.Attempt,
		RootMembers: c.RootMembers, OldShardEpoch: c.OldShardEpoch, OldActiveHash: c.OldActiveHash, Assignment: c.Assignment, PoPs: c.PoPs,
		Supersedes: c.Supersedes, Bindings: c.Bindings, Identities: c.Identities, Authorization: c.Authorization, ReplacedAssignment: c.ReplacedAssignment}
}

// VerifyRegistryOutput is registry-mode admission of a primary candidate (design section 5.2), every item in order. A recovery
// candidate re-installs K by DeriveRecovery and is not a registry output.
func VerifyRegistryOutput(a Admission) (Verified, error) {
	c, s, o := a.Candidate, a.State, a.State.Output
	var out Verified
	if c.Kind != evmassign.KindPrimary || c.Authorization == nil || len(c.SourceRef) != 32 {
		return out, fmt.Errorf("%w: not a primary registry candidate", ErrH3)
	}
	r := vrschema.Word(c.SourceRef)
	if a.Resolved {
		return out, ErrResolved
	}
	// (1)
	if s.Network != a.Deployment.NetworkWord || c.Network != a.Deployment.RootNetwork {
		return out, ErrNetwork
	}
	// (2)
	if s.ResultID != r || s.OpenOutput != r || o.State != vrschema.OutPublished || o.Predecessor != s.LastAcked || s.LastAcked != a.Acknowledged ||
		s.PendingPair != (vrschema.Word{}) {
		return out, ErrNotOpen
	}
	// (3) the candidate's identities, K and registry changes recompute VR's digests; K is the acknowledged committee
	auth := c.Authorization
	if !bytes.Equal(auth.ResultID, r[:]) || !bytes.Equal(auth.SnapshotDigest, o.SnapshotDigest[:]) || !bytes.Equal(auth.Policies, o.PolicyDigest[:]) {
		return out, fmt.Errorf("%w: the authorization names another result, snapshot or policy", ErrCommit)
	}
	if cd := a.Deployment.ContractsDigest(); !bytes.Equal(auth.Contracts, cd[:]) {
		return out, fmt.Errorf("%w: the authorization names another VR generation", ErrCommit)
	}
	md, err := MembersDigestOf(c.Identities)
	if err != nil {
		return out, errors.Join(ErrCommit, err)
	}
	kd, err := MembersDigestOf(auth.K)
	if err != nil {
		return out, errors.Join(ErrCommit, err)
	}
	inc, err1 := evmassign.IdentitiesDigest(a.Lifecycle.Incumbent)
	kid, err2 := evmassign.IdentitiesDigest(auth.K)
	if err := errors.Join(err1, err2); err != nil || inc != kid {
		return out, errors.Join(ErrCommit, errors.New("K is not the acknowledged committee"), err)
	}
	chd, err := vrschema.ChangesDigestOf(c.RegistryChanges)
	if err != nil {
		return out, errors.Join(ErrCommit, err)
	}
	commit := vrschema.OutputCommit(vrschema.OutputCommitInput{Network: s.Network, ChainID: a.Deployment.ChainID, Registry: a.Deployment.Registry,
		ResultID: r, Predecessor: o.Predecessor, Attempt: o.Attempt, ModuleTag: o.ModuleTag, Native: o.Native, SnapshotDigest: o.SnapshotDigest,
		PolicyDigest: o.PolicyDigest, MembersDigest: md, KDigest: kd, ChangesDigest: chd})
	if md != o.MembersDigest || kd != o.KDigest || chd != o.ChangesDigest || commit != o.OutputCommit {
		return out, ErrCommit
	}
	// (4)
	n := len(c.Identities)
	if n < 1 || n > vrschema.MaxCommittee || (!o.Native && !LimitsSatisfied(s.Limits, len(auth.K), n)) {
		return out, fmt.Errorf("%w: %d members under %+v from %d", ErrLimits, n, s.Limits, len(auth.K))
	}
	// (5) the H3/#85 checks, unchanged: coupling, identities, quantization, continuity O->J and J->K, span and supersession, the
	// root-context PoP of every successor key (readiness of every member is item 9)
	v5 := V5Of(c)
	raw, err := v5.Encode()
	if err != nil {
		return out, errors.Join(ErrH3, err)
	}
	vc := a.Verify
	d := sha256.Sum256(raw)
	vc.Digest = d[:]
	if _, _, err := evmassign.Verify(raw, vc); err != nil {
		return out, errors.Join(ErrH3, err)
	}
	if err := errors.Join(evmassign.CheckQuantized(c.Identities), evmassign.CheckQuantized(auth.K)); err != nil {
		return out, errors.Join(ErrH3, err)
	}
	if err := evmassign.VerifyLifecycle(v5, a.Lifecycle); err != nil {
		return out, errors.Join(ErrH3, err)
	}
	if _, err := continuity.Check(evmassign.Members(c.Identities), evmassign.Members(auth.K), a.Lifecycle.Policy); err != nil {
		return out, errors.Join(ErrH3, evmassign.ErrContinuity, fmt.Errorf("J->K: %w", err))
	}
	// (6)
	verdicts, err := vrschema.FoldVerdicts(a.Fold, c.RegistryChanges)
	if err != nil {
		return out, errors.Join(ErrVerdicts, err)
	}
	for i, v := range verdicts {
		if uint64(v) != c.RegistryChanges[i].Verdict {
			return out, fmt.Errorf("%w: change %d carries %d, the fold gives %d", ErrVerdicts, c.RegistryChanges[i].ID, c.RegistryChanges[i].Verdict, v)
		}
	}
	if i, ok := vrschema.AckGate(c.RegistryChanges, verdicts, a.Acked, a.EVMAcked); !ok {
		return out, fmt.Errorf("%w: entry %d (-1: the EVM shard)", ErrAckGate, i)
	}
	// (7)
	effective := vrschema.Effective(a.Fold.Schedule)
	if err := vrschema.PrepareTimeGate(a.Fold.SuccessorRootEpoch, a.PrepareUCTime, effective); err != nil {
		return out, errors.Join(ErrActivation, err)
	}
	sup := a.Support // the gate reads the same committed schedule, successor epoch, committees and certificate as everything else
	sup.Network, sup.SuccessorEpoch, sup.Schedule = a.Deployment.RootNetwork, a.Fold.SuccessorRootEpoch, a.Fold.Schedule
	sup.J, sup.K, sup.Readiness, sup.IntentDigest = c.Identities, auth.K, a.Certificate.Certificate.Readiness, a.Certificate.IntentDigest[:]
	if err := VerifyRuleSupport(sup); err != nil {
		return out, errors.Join(ErrActivation, err)
	}
	// (8)
	if s.Status.Health == vrschema.HealthInconsistent {
		return out, ErrInconsistent
	}
	// (9) the certificate carries exactly this candidate's canonical bytes
	cb, err := c.Encode()
	if err != nil {
		return out, errors.Join(ErrCertificate, err)
	}
	a.Certificate.CandidateBytes = cb
	if err := VerifyCertificate(a.Certificate); err != nil {
		return out, errors.Join(ErrCertificate, err)
	}
	return Verified{V5: v5, Successor: c.Assignment, Verdicts: verdicts}, nil
}
