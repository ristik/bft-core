// Package handoff is an inert wire and state contract for the D4 handoff.
// No consensus or transaction admission path calls this package.
package handoff

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/m2contract"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	ErrPhase     = errors.New("handoff: invalid phase")
	ErrBody      = errors.New("handoff: invalid or reordered body")
	ErrParent    = errors.New("handoff: stale frozen parent")
	ErrShard     = errors.New("handoff: wrong shard")
	ErrSuccessor = errors.New("handoff: competing successor")
	ErrAborted   = errors.New("handoff: attempt aborted")
	ErrProof     = errors.New("handoff: unauthenticated root proof")
	ErrProposal  = errors.New("handoff: proposal is not authority")
	ErrBoundary  = errors.New("handoff: invalid activation boundary")
	ErrNotFinal  = errors.New("handoff: commit not final")
	ErrNoQuorum  = errors.New("handoff: old quorum unavailable")
	ErrCodec     = errors.New("handoff: invalid encoding")
)

const Version uint64 = 1
const PipelineDepth uint64 = evmroot.PipelineDepth

type Phase uint8

const (
	Idle Phase = iota
	Prepared
	Frozen
	Endorsed
	Committed
	Activated
	Acknowledged
	Aborted
)

type Context struct {
	Network, Epoch, Attempt, MinActivation uint64
	Partition                              uint32
	Shard                                  []byte
	Predecessor                            [32]byte
	Candidate                              [32]byte
}
type FreezeRecord struct {
	Context  Context
	Body     [32]byte
	Summary  [32]byte
	Parent   [32]byte
	FrozenID [32]byte
}
type CommitRecord struct {
	FrozenID          [32]byte
	Body              [32]byte
	Round, Activation uint64
	SuccessorTR       [32]byte
	ID                [32]byte
}
type AckRecord struct {
	FrozenID        [32]byte
	CommitID        [32]byte
	FrozenParent    [32]byte
	SuccessorParent [32]byte
	SuccessorTR     [32]byte
	EVMRound        uint64
}

func enc(v ...any) ([]byte, error) { return types.Cbor.Marshal(v) }
func exact(data []byte, n int, domain string) ([]any, error) {
	var v []any
	if err := types.Cbor.Unmarshal(data, &v); err != nil || len(v) != n || v[0] != domain {
		return nil, ErrCodec
	}
	b, e := enc(v...)
	if e != nil || !bytes.Equal(b, data) {
		return nil, ErrCodec
	}
	return v, nil
}
func u(v any) (uint64, error) {
	x, ok := v.(uint64)
	if !ok {
		return 0, ErrCodec
	}
	return x, nil
}
func b32(v any) ([32]byte, error) {
	var x [32]byte
	b, ok := v.([]byte)
	if !ok || len(b) != 32 {
		return x, ErrCodec
	}
	copy(x[:], b)
	return x, nil
}
func raw(v any) ([]byte, error) {
	x, ok := v.([]byte)
	if !ok {
		return nil, ErrCodec
	}
	return x, nil
}
func hash(v ...any) [32]byte { b, _ := enc(v...); return sha256.Sum256(b) }
func (c Context) Encode() ([]byte, error) {
	return enc("UNICITY_HANDOFF_CONTEXT", Version, c.Network, c.Epoch, c.Attempt, c.MinActivation, uint64(c.Partition), c.Shard, c.Predecessor[:], c.Candidate[:])
}
func DecodeContext(data []byte) (Context, error) {
	var c Context
	v, e := exact(data, 10, "UNICITY_HANDOFF_CONTEXT")
	if e != nil {
		return c, e
	}
	if x, e := u(v[1]); e != nil || x != Version {
		return c, ErrCodec
	}
	for i, p := range []*uint64{&c.Network, &c.Epoch, &c.Attempt, &c.MinActivation} {
		*p, e = u(v[i+2])
		if e != nil {
			return c, e
		}
	}
	p, e := u(v[6])
	if e != nil || p > math.MaxUint32 {
		return c, ErrCodec
	}
	c.Partition = uint32(p)
	c.Shard, e = raw(v[7])
	if e != nil {
		return c, e
	}
	c.Predecessor, e = b32(v[8])
	if e != nil {
		return c, e
	}
	c.Candidate, e = b32(v[9])
	return c, e
}
func (r FreezeRecord) Encode() ([]byte, error) {
	c, _ := r.Context.Encode()
	return enc("UNICITY_HANDOFF_FREEZE", Version, c, r.Body[:], r.Summary[:], r.Parent[:], r.FrozenID[:])
}
func DecodeFreeze(data []byte) (FreezeRecord, error) {
	var r FreezeRecord
	v, e := exact(data, 7, "UNICITY_HANDOFF_FREEZE")
	if e != nil {
		return r, e
	}
	if x, e := u(v[1]); e != nil || x != Version {
		return r, ErrCodec
	}
	c, e := raw(v[2])
	if e != nil {
		return r, e
	}
	r.Context, e = DecodeContext(c)
	if e != nil {
		return r, e
	}
	for i, p := range []*[32]byte{&r.Body, &r.Summary, &r.Parent, &r.FrozenID} {
		*p, e = b32(v[i+3])
		if e != nil {
			return r, e
		}
	}
	return r, nil
}
func (r CommitRecord) Encode() ([]byte, error) {
	return enc("UNICITY_HANDOFF_COMMIT", Version, r.FrozenID[:], r.Body[:], r.Round, r.Activation, r.SuccessorTR[:], r.ID[:])
}
func DecodeCommit(data []byte) (CommitRecord, error) {
	var r CommitRecord
	v, e := exact(data, 8, "UNICITY_HANDOFF_COMMIT")
	if e != nil {
		return r, e
	}
	if x, e := u(v[1]); e != nil || x != Version {
		return r, ErrCodec
	}
	r.FrozenID, e = b32(v[2])
	if e != nil {
		return r, e
	}
	r.Body, e = b32(v[3])
	if e != nil {
		return r, e
	}
	r.Round, e = u(v[4])
	if e != nil {
		return r, e
	}
	r.Activation, e = u(v[5])
	if e != nil {
		return r, e
	}
	r.SuccessorTR, e = b32(v[6])
	if e != nil {
		return r, e
	}
	r.ID, e = b32(v[7])
	return r, e
}
func (r AckRecord) Encode() ([]byte, error) {
	return enc("UNICITY_HANDOFF_ACK", Version, r.FrozenID[:], r.CommitID[:], r.FrozenParent[:], r.SuccessorParent[:], r.SuccessorTR[:], r.EVMRound)
}
func DecodeAck(data []byte) (AckRecord, error) {
	var r AckRecord
	v, e := exact(data, 8, "UNICITY_HANDOFF_ACK")
	if e != nil {
		return r, e
	}
	if x, e := u(v[1]); e != nil || x != Version {
		return r, ErrCodec
	}
	for i, p := range []*[32]byte{&r.FrozenID, &r.CommitID, &r.FrozenParent, &r.SuccessorParent, &r.SuccessorTR} {
		*p, e = b32(v[i+2])
		if e != nil {
			return r, e
		}
	}
	r.EVMRound, e = u(v[7])
	return r, e
}

// RootProofVerifier is the future consensus adapter. It must verify QC signatures
// against the historical old trust base, block ancestry, committed content,
// and the consecutive commit-capable QC relation before returning nil.
type RootProofVerifier interface {
	VerifyOrdered(kind string, recordID [32]byte, proof []byte) error
	VerifyFinal(commitID [32]byte, commitRound uint64, proof []byte) error
	VerifyEndorse(frozenID [32]byte, proof []byte) error
}
type Machine struct {
	Phase    Phase
	Context  Context
	Freeze   FreezeRecord
	Commit   CommitRecord
	Ack      AckRecord
	Final    bool
	verifier RootProofVerifier
}

func New(c Context, v RootProofVerifier) *Machine { return &Machine{Context: c, verifier: v} }
func (m *Machine) ordered(kind string, id [32]byte, p []byte) error {
	if m.verifier == nil || len(p) == 0 || m.verifier.VerifyOrdered(kind, id, p) != nil {
		return ErrProof
	}
	return nil
}
func (m *Machine) Prepare(proof []byte) error {
	if m.Phase != Idle {
		return ErrPhase
	}
	id := hash("UNICITY_HANDOFF_PREPARE", m.Context.Candidate[:], m.Context.Attempt)
	if e := m.ordered("prepare", id, proof); e != nil {
		return e
	}
	m.Phase = Prepared
	return nil
}
func (m *Machine) FreezeWith(r FreezeRecord, body evmroot.TrustBaseBodyV2, expectedParent [32]byte, proof []byte) error {
	if m.Phase != Prepared {
		return ErrPhase
	}
	if r.Context.Partition != m.Context.Partition || !bytes.Equal(r.Context.Shard, m.Context.Shard) {
		return ErrShard
	}
	if r.Parent != expectedParent {
		return ErrParent
	}
	if !sameContext(r.Context, m.Context) {
		return ErrBody
	}
	id := body.Identity()
	if body.Validate() != nil || r.Body != id || body.EarliestActivation != m.Context.MinActivation || !bytes.Equal(body.PredecessorHash, m.Context.Predecessor[:]) || r.Summary == ([32]byte{}) || r.Parent == ([32]byte{}) {
		return ErrBody
	}
	want := hash("UNICITY_HANDOFF_FROZEN", r.Body[:], r.Summary[:], r.Parent[:], m.Context.Candidate[:], m.Context.Attempt, m.Context.Predecessor[:])
	if r.FrozenID != want {
		return ErrBody
	}
	if e := m.ordered("freeze", r.FrozenID, proof); e != nil {
		return e
	}
	m.Freeze = r
	m.Phase = Frozen
	return nil
}
func (m *Machine) Endorse(proof []byte) error {
	if m.Phase != Frozen {
		return ErrPhase
	}
	if m.verifier == nil || len(proof) == 0 || m.verifier.VerifyEndorse(m.Freeze.FrozenID, proof) != nil {
		return ErrNoQuorum
	}
	m.Phase = Endorsed
	return nil
}
func (m *Machine) CommitWith(r CommitRecord, proof []byte) error {
	if m.Phase == Aborted {
		return ErrAborted
	}
	if m.Phase >= Committed {
		if m.Commit.ID != r.ID {
			return ErrSuccessor
		}
		return ErrPhase
	}
	if m.Phase != Endorsed {
		return ErrPhase
	}
	if r.FrozenID != m.Freeze.FrozenID || r.Body != m.Freeze.Body {
		return ErrBody
	}
	if r.Activation < m.Context.MinActivation || r.Round > math.MaxUint64-PipelineDepth || r.Activation < r.Round+PipelineDepth {
		return ErrBoundary
	}
	if r.SuccessorTR == ([32]byte{}) {
		return ErrSuccessor
	}
	want := hash("UNICITY_HANDOFF_COMMIT", r.FrozenID[:], r.Activation, r.SuccessorTR[:], m.Context.Attempt, m.Context.Predecessor[:])
	if r.ID != want {
		return ErrBody
	}
	if e := m.ordered("commit", r.ID, proof); e != nil {
		return e
	}
	m.Commit = r
	m.Phase = Committed
	return nil
}
func (m *Machine) Finalize(proof []byte) error {
	if m.Phase != Committed {
		return ErrPhase
	}
	if m.verifier == nil || len(proof) == 0 || m.verifier.VerifyFinal(m.Commit.ID, m.Commit.Round, proof) != nil {
		return ErrProof
	}
	m.Final = true
	return nil
}
func (m *Machine) Activate(observed uint64) error {
	if m.Phase == Aborted {
		return ErrAborted
	}
	if m.Phase != Committed {
		return ErrPhase
	}
	if !m.Final {
		return ErrNotFinal
	}
	if observed < m.Commit.Activation {
		return ErrBoundary
	}
	m.Phase = Activated
	return nil
}
func (m *Machine) Acknowledge(r AckRecord, proof []byte) error {
	if m.Phase != Activated {
		return ErrPhase
	}
	if r.FrozenID != m.Freeze.FrozenID || r.CommitID != m.Commit.ID || r.FrozenParent != m.Freeze.Parent || r.SuccessorTR != m.Commit.SuccessorTR || r.SuccessorParent != m.Freeze.Parent {
		return ErrParent
	}
	id := hash("UNICITY_HANDOFF_ACK_ID", r.CommitID[:], r.SuccessorParent[:], r.EVMRound)
	if e := m.ordered("ack", id, proof); e != nil {
		return e
	}
	m.Ack = r
	m.Phase = Acknowledged
	return nil
}
func (m *Machine) Abort(proof []byte) error {
	if m.Phase >= Committed && m.Phase != Aborted {
		return ErrPhase
	}
	if m.Phase == Aborted {
		return ErrAborted
	}
	if m.Phase == Idle {
		return ErrPhase
	}
	id := hash("UNICITY_HANDOFF_ABORT", m.Context.Candidate[:], m.Context.Attempt)
	if e := m.ordered("abort", id, proof); e != nil {
		return e
	}
	m.Phase = Aborted
	return nil
}
func (m *Machine) LocalProposal() error { return ErrProposal }
func (m *Machine) Authorized(round uint64) bool {
	return m.Phase >= Committed && m.Phase <= Acknowledged && round >= m.Commit.Activation
}

func sameContext(a, b Context) bool {
	return a.Network == b.Network && a.Epoch == b.Epoch && a.Attempt == b.Attempt && a.MinActivation == b.MinActivation && a.Predecessor == b.Predecessor && a.Candidate == b.Candidate
}

// ActivatedInterval uses the WP1 durable activation encoding. The caller must
// persist it atomically with the verified commit and close the prior interval.
func (m *Machine) ActivatedInterval(body evmroot.TrustBaseBodyV2, end uint64) (m2contract.TrustInterval, error) {
	if m.Phase < Committed || m.Phase == Aborted || !m.Final {
		return m2contract.TrustInterval{}, ErrNotFinal
	}
	id := body.Identity()
	if id != m.Commit.Body {
		return m2contract.TrustInterval{}, ErrBody
	}
	r := m2contract.TrustInterval{Body: body, Activation: evmroot.ActivatedTrustBase{BodyIdentity: id[:], EpochStart: m.Commit.Activation, ActivationCommitID: m.Commit.ID[:]}, End: end}
	if _, err := r.Encode(); err != nil {
		return m2contract.TrustInterval{}, err
	}
	return r, nil
}
