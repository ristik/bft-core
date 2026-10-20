package rootevidence

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// Sender sends one transaction and waits for its outcome (posrelayer.Sender is one). It returns an error unless the transaction succeeded.
type Sender interface {
	Send(ctx context.Context, to [20]byte, value *big.Int, data []byte) (ethcommon.Hash, error)
}

// Outcome is what Submit decided about a paired slot.
type Outcome int

const (
	// Submitted: the pair was sent and the contract admitted it (the case exists).
	Submitted Outcome = iota + 1
	// AlreadyAdmitted: the offence is already known to the contract, by this submitter or another reporter; nothing is sent.
	AlreadyAdmitted
	// TooLate: the certified view proves the cutoff has passed, or the contract reverted EvidenceLate/RoundBeforeEpoch. Permanent: not retried.
	TooLate
	// Unresolved: the offence's exposure cannot be resolved yet, or the contract reverted with a condition that can change (assignment not
	// yet activated). Transient: kept and retried with backoff by the caller.
	Unresolved
	// Rejected: the contract refuses the pair for a reason retrying cannot change (bad signature, key or epoch mismatch, identical statements).
	Rejected
)

func (o Outcome) String() string {
	return [...]string{"", "submitted", "already-admitted", "too-late", "unresolved", "rejected"}[o]
}

// Submission is the outcome with what identifies it on chain.
type Submission struct {
	Outcome Outcome
	Offence [32]byte
	CaseID  [32]byte
	TxHash  ethcommon.Hash
	Reason  string
}

// Submitter turns a paired slot into an ordinary EVM transaction and settles the resulting case. It holds only a funded EVM account: no root or
// owner key. Reading is untrusted: the contract verifies the pair itself, and a wrong answer here is a revert, not a wrong admission.
type Submitter struct {
	Reader   Reader
	Sender   Sender
	Evidence [20]byte
	ChainID  *big.Int
	// Assignments are the candidate assignment ids the offence's exposure is resolved among (the assignment whose root epoch is the voting epoch
	// and whose exposure holds the voter's key).
	Assignments [][32]byte
}

func (s *Submitter) call(ctx context.Context, to [20]byte, a abi.ABI, method string, args ...any) ([]any, error) {
	data, err := a.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	out, err := s.Reader.Call(ctx, to, data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", method, err)
	}
	return a.Unpack(method, out)
}

func (s *Submitter) addr(ctx context.Context, method string) ([20]byte, error) {
	o, err := s.call(ctx, s.Evidence, evidenceAbi, method)
	if err != nil {
		return [20]byte{}, err
	}
	a, _ := o[0].(ethcommon.Address)
	return a, nil
}

func (s *Submitter) config(ctx context.Context) (network [32]byte, cfg votesig.Config, err error) {
	o, err := s.call(ctx, s.Evidence, evidenceAbi, "network")
	if err != nil {
		return
	}
	network, _ = o[0].([32]byte)
	n, err := s.call(ctx, s.Evidence, evidenceAbi, "rootNetwork")
	if err != nil {
		return
	}
	g, err := s.call(ctx, s.Evidence, evidenceAbi, "rootGenesis")
	if err != nil {
		return
	}
	rn, _ := n[0].(uint64)
	rg, _ := g[0].([32]byte)
	cfg = votesig.Config{Scheme: votesig.SchemeDomainBound, Network: rn, Genesis: rg}
	return network, cfg, cfg.Validate()
}

// Resolved is the certified view of the assignment that held the voter's key in the offence's epoch.
type Resolved struct {
	AssignmentID [32]byte
	ExposureID   [32]byte
	Assignment   Assignment
	Terms        Terms
}

// ErrNoExposure means no candidate assignment holds the voter's key in the voting epoch.
var ErrNoExposure = errors.New("rootevidence: no exposure of the voter's key in the voting epoch among the assignments")

// Resolve finds the exposure of the slot's key among the candidate assignments and reads the assignment's cutoff values and policy windows.
func (s *Submitter) Resolve(ctx context.Context, r *SlotRecord) (*Resolved, error) {
	custody, err := s.addr(ctx, "custody")
	if err != nil {
		return nil, err
	}
	keyHash := ethcrypto.Keccak256Hash(r.Key)
	for _, id := range s.Assignments {
		a, err := s.call(ctx, custody, custodyAbi, "assignments", id)
		if err != nil {
			return nil, err
		}
		if epoch, _ := a[2].(uint64); epoch != r.Epoch {
			continue
		}
		exps, err := s.call(ctx, custody, custodyAbi, "assignmentExposures", id)
		if err != nil {
			return nil, err
		}
		list, _ := exps[0].([][32]byte)
		for _, e := range list {
			x, err := s.call(ctx, custody, custodyAbi, "exposures", e)
			if err != nil {
				return nil, err
			}
			if h, _ := x[5].([32]byte); h != keyHash {
				continue
			}
			t, err := s.call(ctx, custody, custodyAbi, "policyTerms", id)
			if err != nil {
				return nil, err
			}
			pt := abi.ConvertType(t[0], new(policyTerms)).(*policyTerms)
			res := &Resolved{AssignmentID: id, ExposureID: e, Terms: Terms{EvidenceWindow: pt.EvidenceWindow, SuffixEvidenceWindow: pt.SuffixEvidenceWindow}}
			res.Assignment.Offset, _ = a[4].(uint64)
			res.Assignment.FirstRound, _ = a[5].(uint64)
			res.Assignment.OffsetSet, _ = a[6].(bool)
			res.Assignment.HKnown, _ = a[7].(bool)
			res.Assignment.HRound, _ = a[8].(uint64)
			res.Assignment.Closed, _ = a[9].(bool)
			res.Assignment.PClose, _ = a[10].(uint64)
			return res, nil
		}
	}
	return nil, ErrNoExposure
}

func (s *Submitter) progress(ctx context.Context) (uint64, error) {
	roots, err := s.addr(ctx, "roots")
	if err != nil {
		return 0, err
	}
	o, err := s.call(ctx, roots, rootsAbi, "progress")
	if err != nil {
		return 0, err
	}
	p, _ := o[0].(uint64)
	return p, nil
}

type policyTerms struct {
	PenaltyBps           uint16
	LifetimeCapBps       uint16
	BountyBps            uint16
	BountyCap            *big.Int
	EvidenceWindow       uint64
	SuffixEvidenceWindow uint64
	HoldNormal           uint64
	HoldSuffix           uint64
	HoldRetirement       uint64
	TimeFloor            uint64
}

type caseView struct {
	OffenceID  [32]byte
	ExposureID [32]byte
	Id         uint64
	Reporter   ethcommon.Address
	Budget     *big.Int
	Debited    *big.Int
	Cursor     uint32
	LotCount   uint32
}

func (s *Submitter) caseInfo(ctx context.Context, id [32]byte) (*caseView, error) {
	o, err := s.call(ctx, s.Evidence, evidenceAbi, "caseInfo", id)
	if err != nil {
		return nil, err
	}
	return abi.ConvertType(o[0], new(caseView)).(*caseView), nil
}

// Submit sends the pair of a paired slot once, unless the contract already knows the offence or the certified view proves it late. It never
// rebroadcasts on its own: a restart calls Submit again and offenceSeen decides.
func (s *Submitter) Submit(ctx context.Context, r *SlotRecord) (*Submission, error) {
	if !r.Paired() {
		return nil, fmt.Errorf("%w: the slot holds one statement", ErrBuild)
	}
	network, cfg, err := s.config(ctx)
	if err != nil {
		return nil, err
	}
	h := voteHeader{Network: network, Domain: DomainRoot, Key: r.Key, VotingEpoch: r.Epoch, VotingRound: r.Round}
	o, err := s.call(ctx, s.Evidence, evidenceAbi, "offenceIDOf", h)
	if err != nil {
		return nil, err
	}
	offence, _ := o[0].([32]byte)
	res := &Submission{Offence: offence}
	if res.CaseID, err = CaseID(network, s.ChainID, s.Evidence, offence); err != nil {
		return nil, err
	}
	seen, err := s.call(ctx, s.Evidence, evidenceAbi, "offenceSeen", offence)
	if err != nil {
		return nil, err
	}
	if b, _ := seen[0].(bool); b {
		res.Outcome, res.Reason = AlreadyAdmitted, "the contract already knows the offence"
		return res, nil
	}
	rv, err := s.Resolve(ctx, r)
	if err != nil {
		if errors.Is(err, ErrNoExposure) {
			res.Outcome, res.Reason = Unresolved, err.Error()
			return res, nil
		}
		return nil, err
	}
	progress, err := s.progress(ctx)
	if err != nil {
		return nil, err
	}
	if late, why := Retention(rv.Assignment, rv.Terms, progress, r.Round); late {
		res.Outcome, res.Reason = TooLate, why
		return res, nil
	}
	data, err := SubmitCalldata(network, cfg, r, rv.ExposureID)
	if err != nil {
		return nil, err
	}
	res.TxHash, err = s.Sender.Send(ctx, s.Evidence, nil, data)
	if err != nil {
		return s.classify(res, err)
	}
	info, err := s.caseInfo(ctx, res.CaseID)
	if err != nil {
		return nil, err
	}
	if info.Reporter == (ethcommon.Address{}) {
		return nil, fmt.Errorf("transaction %s succeeded but the case %x does not exist", res.TxHash, res.CaseID)
	}
	res.Outcome = Submitted
	return res, nil
}

var (
	lateErrors      = []string{"EvidenceLate", "RoundBeforeEpoch"}
	transientErrors = []string{"AssignmentNotActivated", "ExposureUnknown"}
	duplicateErrors = []string{"DuplicateOffence"}
)

// revertName is the name of the contract error a failed call carries, if the client returned its data.
func revertName(err error) string {
	var de rpc.DataError
	if !errors.As(err, &de) {
		return ""
	}
	str, _ := de.ErrorData().(string)
	raw, e := hex.DecodeString(strings.TrimPrefix(str, "0x"))
	if e != nil || len(raw) < 4 {
		return ""
	}
	for name, ev := range evidenceAbi.Errors {
		if string(ev.ID[:4]) == string(raw[:4]) {
			return name
		}
	}
	return ""
}

func in(name string, list []string) bool {
	for _, n := range list {
		if n == name {
			return true
		}
	}
	return false
}

// classify turns a failed send into the permanent or transient answer the caller needs. An error it cannot classify is returned as is.
func (s *Submitter) classify(res *Submission, err error) (*Submission, error) {
	switch name := revertName(err); {
	case in(name, duplicateErrors):
		res.Outcome, res.Reason = AlreadyAdmitted, "another reporter's pair was admitted first"
	case in(name, lateErrors):
		res.Outcome, res.Reason = TooLate, name
	case in(name, transientErrors):
		res.Outcome, res.Reason = Unresolved, name
	case name != "":
		res.Outcome, res.Reason = Rejected, name
	default:
		return nil, err
	}
	return res, nil
}

// Settle settles the next ascending lots of a case in batches of the contract's maxBatch, from the on-chain cursor, until the case is settled.
// It is permissionless and resumable: after an interruption the cursor is read again. It returns the number of settle transactions sent.
func (s *Submitter) Settle(ctx context.Context, caseID [32]byte) (int, error) {
	info, err := s.caseInfo(ctx, caseID)
	if err != nil {
		return 0, err
	}
	if info.Reporter == (ethcommon.Address{}) {
		return 0, fmt.Errorf("rootevidence: unknown case %x", caseID)
	}
	custody, err := s.addr(ctx, "custody")
	if err != nil {
		return 0, err
	}
	lots, err := s.call(ctx, custody, custodyAbi, "exposureLots", info.ExposureID)
	if err != nil {
		return 0, err
	}
	all, _ := lots[0].([]*big.Int)
	mb, err := s.call(ctx, s.Evidence, evidenceAbi, "maxBatch")
	if err != nil {
		return 0, err
	}
	batch, _ := mb[0].(uint32)
	if batch == 0 {
		return 0, errors.New("rootevidence: the contract's maxBatch is zero")
	}
	sent := 0
	for cursor := int(info.Cursor); cursor < int(info.LotCount) && cursor < len(all); {
		end := min(cursor+int(batch), int(info.LotCount), len(all))
		data, err := evidenceAbi.Pack("settleEvidence", caseID, all[cursor:end])
		if err != nil {
			return sent, err
		}
		if _, err := s.Sender.Send(ctx, s.Evidence, nil, data); err != nil {
			return sent, err
		}
		sent++
		cursor = end
	}
	return sent, nil
}
