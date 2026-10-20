package rootevidence

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	basetypes "github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// The contract surface of the submitter: the public entry points and getters of Evidence and StakeCustody (unicity-pos-contracts, src/p85).
// Everything read here only decides what the submitter proposes; the contract re-verifies every word of what it is sent.

const voteHeaderABI = `{"name":"h","type":"tuple","components":[{"name":"network","type":"bytes32"},{"name":"domain","type":"uint8"},{"name":"key","type":"bytes"},{"name":"votingEpoch","type":"uint64"},{"name":"votingRound","type":"uint64"}]}`

func signedVoteABI(name string) string {
	return `{"name":"` + name + `","type":"tuple","components":[{"name":"parent","type":"uint64"},{"name":"exec","type":"bytes32"},{"name":"timestamp","type":"uint64"},{"name":"committing","type":"bool"},{"name":"commitHash","type":"bytes32"},{"name":"commitRound","type":"uint64"},{"name":"commitEpoch","type":"uint64"},{"name":"commitTimestamp","type":"uint64"},{"name":"signature","type":"bytes"},{"name":"sealSignature","type":"bytes"}]}`
}

var evidenceABI = `[
 {"type":"function","name":"submitEvidence","stateMutability":"nonpayable","inputs":[` + voteHeaderABI + `,` + signedVoteABI("a") + `,` + signedVoteABI("b") + `,{"name":"exposureID","type":"bytes32"}],"outputs":[{"type":"bytes32"}]},
 {"type":"function","name":"settleEvidence","stateMutability":"nonpayable","inputs":[{"name":"caseID","type":"bytes32"},{"name":"lotIDs","type":"uint256[]"}],"outputs":[{"type":"uint256"}]},
 {"type":"function","name":"offenceIDOf","stateMutability":"pure","inputs":[` + voteHeaderABI + `],"outputs":[{"type":"bytes32"}]},
 {"type":"function","name":"offenceSeen","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"bool"}]},
 {"type":"function","name":"network","stateMutability":"view","inputs":[],"outputs":[{"type":"bytes32"}]},
 {"type":"function","name":"rootNetwork","stateMutability":"view","inputs":[],"outputs":[{"type":"uint64"}]},
 {"type":"function","name":"rootGenesis","stateMutability":"view","inputs":[],"outputs":[{"type":"bytes32"}]},
 {"type":"function","name":"maxBatch","stateMutability":"view","inputs":[],"outputs":[{"type":"uint32"}]},
 {"type":"function","name":"custody","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
 {"type":"function","name":"roots","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
 {"type":"function","name":"caseInfo","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"tuple","components":[
   {"name":"offenceID","type":"bytes32"},{"name":"exposureID","type":"bytes32"},{"name":"id","type":"uint64"},{"name":"reporter","type":"address"},
   {"name":"budget","type":"uint256"},{"name":"debited","type":"uint256"},{"name":"cursor","type":"uint32"},{"name":"lotCount","type":"uint32"}]}]},
 {"type":"error","name":"EvidenceLate","inputs":[]},{"type":"error","name":"DuplicateOffence","inputs":[]},
 {"type":"error","name":"AssignmentNotActivated","inputs":[]},{"type":"error","name":"RoundBeforeEpoch","inputs":[]},
 {"type":"error","name":"ExposureUnknown","inputs":[]},{"type":"error","name":"NotAttributable","inputs":[]},
 {"type":"error","name":"KeyMismatch","inputs":[]},{"type":"error","name":"EpochMismatch","inputs":[]},
 {"type":"error","name":"BadSignature","inputs":[]},{"type":"error","name":"IdenticalStatements","inputs":[]},
 {"type":"error","name":"BadStatement","inputs":[]},{"type":"error","name":"CommitMismatch","inputs":[]},
 {"type":"error","name":"SealSignatureMissing","inputs":[]},{"type":"error","name":"SealSignatureForbidden","inputs":[]},
 {"type":"error","name":"WrongNetwork","inputs":[]},{"type":"error","name":"BadDomain","inputs":[]},
 {"type":"error","name":"CaseSettled","inputs":[]},{"type":"error","name":"NotNextLot","inputs":[]},{"type":"error","name":"UnknownCase","inputs":[]}
]`

const custodyABI = `[
 {"type":"function","name":"assignmentExposures","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"bytes32[]"}]},
 {"type":"function","name":"exposures","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[
   {"name":"assignmentID","type":"bytes32"},{"name":"id","type":"uint64"},{"name":"generation","type":"uint64"},{"name":"weight","type":"uint64"},
   {"name":"rawWeight","type":"uint64"},{"name":"rootKeyHash","type":"bytes32"},{"name":"evmKeyHash","type":"bytes32"},
   {"name":"operatorPayee","type":"address"},{"name":"referencesReleased","type":"bool"},{"name":"sessionLocks","type":"uint32"}]},
 {"type":"function","name":"exposureLots","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"uint256[]"}]},
 {"type":"function","name":"assignments","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[
   {"name":"state","type":"uint8"},{"name":"lineage","type":"bytes32"},{"name":"rootEpoch","type":"uint64"},{"name":"evmEpoch","type":"uint64"},
   {"name":"offset","type":"uint64"},{"name":"firstRound","type":"uint64"},{"name":"offsetSet","type":"bool"},{"name":"hKnown","type":"bool"},
   {"name":"hRound","type":"uint64"},{"name":"closed","type":"bool"},{"name":"pClose","type":"uint64"},{"name":"tClose","type":"uint64"},
   {"name":"closureKey","type":"bytes32"},{"name":"exposureDigest","type":"bytes32"},{"name":"keyDigest","type":"bytes32"},{"name":"policyID","type":"uint32"}]},
 {"type":"function","name":"policyTerms","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"tuple","components":[
   {"name":"penaltyBps","type":"uint16"},{"name":"lifetimeCapBps","type":"uint16"},{"name":"bountyBps","type":"uint16"},{"name":"bountyCap","type":"uint128"},
   {"name":"evidenceWindow","type":"uint64"},{"name":"suffixEvidenceWindow","type":"uint64"},{"name":"holdNormal","type":"uint64"},{"name":"holdSuffix","type":"uint64"},
   {"name":"holdRetirement","type":"uint64"},{"name":"timeFloor","type":"uint64"}]}]}
]`

const rootsABI = `[{"type":"function","name":"progress","stateMutability":"view","inputs":[],"outputs":[{"type":"uint64"}]}]`

var evidenceAbi, custodyAbi, rootsAbi abi.ABI

func init() {
	for dst, src := range map[*abi.ABI]string{&evidenceAbi: evidenceABI, &custodyAbi: custodyABI, &rootsAbi: rootsABI} {
		a, err := abi.JSON(strings.NewReader(src))
		if err != nil {
			panic(fmt.Sprintf("rootevidence: ABI: %v", err))
		}
		*dst = a
	}
}

// Reader performs the read-only calls (eth_call at one block; the caller pins it). posrelayer.RPCReader is one.
type Reader interface {
	Call(ctx context.Context, to [20]byte, data []byte) ([]byte, error)
}

// DomainRoot is the Evidence contract's root vote domain (DOMAIN_ROOT).
const DomainRoot = 1

type voteHeader struct {
	Network     [32]byte
	Domain      uint8
	Key         []byte
	VotingEpoch uint64
	VotingRound uint64
}

type signedVote struct {
	Parent          uint64
	Exec            [32]byte
	Timestamp       uint64
	Committing      bool
	CommitHash      [32]byte
	CommitRound     uint64
	CommitEpoch     uint64
	CommitTimestamp uint64
	Signature       []byte
	SealSignature   []byte
}

// ErrBuild is a statement or pair that cannot be put into the contract's form.
var ErrBuild = errors.New("rootevidence: cannot build the evidence call")

func toSignedVote(s *Statement) (signedVote, error) {
	if len(s.Exec) != 32 {
		return signedVote{}, fmt.Errorf("%w: executed state hash is %d bytes", ErrBuild, len(s.Exec))
	}
	v := signedVote{Parent: s.Parent, Timestamp: s.Timestamp, Committing: s.Committing, Signature: s.Signature, SealSignature: s.SealSignature}
	copy(v.Exec[:], s.Exec)
	if s.Committing {
		if len(s.CommitHash) != 32 {
			return signedVote{}, fmt.Errorf("%w: commit hash is %d bytes", ErrBuild, len(s.CommitHash))
		}
		copy(v.CommitHash[:], s.CommitHash)
		v.CommitRound, v.CommitEpoch, v.CommitTimestamp = s.CommitRound, s.CommitEpoch, s.CommitTimestamp
	}
	return v, nil
}

// CheckPreimage rebuilds the preimage the contract derives from the typed fields (the native votesig helpers, with the root network and genesis
// the contract pins) and compares it with the one the statement was verified under. A statement the contract would rebuild differently is never sent.
func (r *SlotRecord) checkPreimage(cfg votesig.Config, s *Statement) error {
	vi := votesig.VoteInfo{Epoch: r.Epoch, Round: r.Round, Parent: s.Parent, Timestamp: s.Timestamp}
	copy(vi.Exec[:], s.Exec)
	var commit votesig.Commit
	if s.Committing {
		commit = votesig.Commit{Hash: s.CommitHash, Round: s.CommitRound}
	}
	pv, err := cfg.VotePreimage(vi, commit)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBuild, err)
	}
	if !bytes.Equal(pv, s.PV) {
		return fmt.Errorf("%w: the contract would rebuild a different preimage than the one the statement was verified under", ErrBuild)
	}
	if !s.Committing {
		return nil
	}
	// the contract rebuilds the native seal bytes the seal signature covers from the commit fields and the vote info hash
	vh, err := cfg.VoteInfoHash(vi)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBuild, err)
	}
	seal := basetypes.UnicitySeal{Version: 1, NetworkID: basetypes.NetworkID(cfg.Network), RootChainRoundNumber: s.CommitRound, Epoch: s.CommitEpoch,
		Timestamp: s.CommitTimestamp, PreviousHash: vh[:], Hash: s.CommitHash}
	sb, err := seal.SigBytes()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBuild, err)
	}
	if !bytes.Equal(sb, s.SealBytes) {
		return fmt.Errorf("%w: the contract would rebuild different seal bytes than the ones the seal signature was verified under", ErrBuild)
	}
	return nil
}

// SubmitCalldata is evidence.submitEvidence(header, a, b, exposureID) for a paired slot, with the original vote and seal signatures. The statements
// are ordered by digest so the call is the same whichever journal supplied which half.
func SubmitCalldata(network [32]byte, cfg votesig.Config, r *SlotRecord, exposureID [32]byte) ([]byte, error) {
	if !r.Paired() {
		return nil, fmt.Errorf("%w: the slot holds one statement", ErrBuild)
	}
	a, b := r.First, *r.Second
	if da, db := a.Digest(), b.Digest(); bytes.Compare(da[:], db[:]) > 0 {
		a, b = b, a
	}
	for _, s := range []*Statement{&a, &b} {
		if err := r.checkPreimage(cfg, s); err != nil {
			return nil, err
		}
	}
	va, err := toSignedVote(&a)
	if err != nil {
		return nil, err
	}
	vb, err := toSignedVote(&b)
	if err != nil {
		return nil, err
	}
	h := voteHeader{Network: network, Domain: DomainRoot, Key: r.Key, VotingEpoch: r.Epoch, VotingRound: r.Round}
	return evidenceAbi.Pack("submitEvidence", h, va, vb, exposureID)
}

var caseDomain = ethcrypto.Keccak256Hash([]byte("unicity.p85.case"))

// CaseID is the id the contract gives the case of an offence: keccak256(abi.encode(CASE_DOMAIN, network, chainid, evidence, offenceID)).
func CaseID(network [32]byte, chainID *big.Int, evidence [20]byte, offenceID [32]byte) ([32]byte, error) {
	b32, u256, addr := mustType("bytes32"), mustType("uint256"), mustType("address")
	packed, err := abi.Arguments{{Type: b32}, {Type: b32}, {Type: u256}, {Type: addr}, {Type: b32}}.Pack(
		[32]byte(caseDomain), network, chainID, ethcommon.Address(evidence), offenceID)
	if err != nil {
		return [32]byte{}, err
	}
	return ethcrypto.Keccak256Hash(packed), nil
}

func mustType(t string) abi.Type {
	ty, err := abi.NewType(t, "", nil)
	if err != nil {
		panic(err)
	}
	return ty
}
