package consensus

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

type (
	QuorumInfo interface {
		GetQuorumThreshold() uint64
		GetMaxFaultyNodes() uint64
	}

	ConsensusWithSignatures struct {
		voteInfo   *drctypes.RoundInfo
		commitInfo *types.UnicitySeal
		signatures map[string]hex.Bytes
		// scheme 2: the seal signatures of the same voters, kept only for a committing statement
		scheme         uint64
		sealSignatures map[string]hex.Bytes
	}

	VoteRegister struct {
		// Hash of ConsensusInfo to signatures/votes for it
		hashToSignatures map[voteID]*ConsensusWithSignatures
		// Tracks all timeout votes for this round
		// if 2f+1 or threshold votes, then TC is formed
		timeoutCert *drctypes.TimeoutCert
		// Helper, to avoid duplicate votes
		authorToVote map[string]voteID
	}

	// sha256 hash is used to create ID for a vote
	voteID = [sha256.Size]byte
)

type profile2QuorumInfo struct{ QuorumInfo }

func (q profile2QuorumInfo) GetRootNodes() []*types.NodeInfo {
	if members, ok := q.QuorumInfo.(interface{ GetRootNodes() []*types.NodeInfo }); ok {
		return members.GetRootNodes()
	}
	return nil
}

func (profile2QuorumInfo) usesStakeWeighting() {}

var ErrVoteIsNil = errors.New("vote is nil")

func NewVoteRegister() *VoteRegister {
	return &VoteRegister{
		hashToSignatures: make(map[voteID]*ConsensusWithSignatures),
		timeoutCert:      nil,
		authorToVote:     make(map[string]voteID),
	}
}

func (v *VoteRegister) InsertVote(vote *abdrc.VoteMsg, quorumInfo QuorumInfo) (*drctypes.QuorumCert, error) {
	if vote == nil {
		return nil, ErrVoteIsNil
	}

	// Get hash of consensus structure
	bs, err := vote.LedgerCommitInfo.SigBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal unicity seal: %w", err)
	}
	commitInfoHash := sha256.Sum256(bs)
	domainBound := vote.Scheme == votesig.SchemeDomainBound
	committing := len(vote.LedgerCommitInfo.Hash) != 0 || vote.LedgerCommitInfo.RootChainRoundNumber != 0
	if domainBound {
		// votes of the two schemes are never grouped, and so never counted, together: the group key carries the scheme. The
		// native seal bytes bind the vote info hash (and with it the epoch and round) and the commit data, which together
		// determine the signed statement PV.
		commitInfoHash = sha256.Sum256(append([]byte{byte(votesig.SchemeDomainBound)}, bs...))
		if committing && len(vote.SealSignature) == 0 {
			return nil, fmt.Errorf("%w: committing scheme 2 vote from %q has no seal signature", votesig.ErrSignerSets, vote.Author)
		}
	}

	// has the author already voted in this round?
	if prevVoteHash, voted := v.authorToVote[vote.Author]; voted {
		// Check if vote has changed
		if commitInfoHash != prevVoteHash {
			// new equivocating vote, this is a security event
			return nil, fmt.Errorf("equivocating vote, previous %X, new %X", prevVoteHash, commitInfoHash)
		}
		return nil, fmt.Errorf("%w: duplicate vote from %q", quorumweight.ErrDuplicateSigner, vote.Author)
	}
	// Store vote from author
	v.authorToVote[vote.Author] = commitInfoHash
	// register commit hash
	// Create new entry if not present
	if _, present := v.hashToSignatures[commitInfoHash]; !present {
		v.hashToSignatures[commitInfoHash] = &ConsensusWithSignatures{
			commitInfo: vote.LedgerCommitInfo,
			voteInfo:   vote.VoteInfo,
			signatures: make(map[string]hex.Bytes),
		}
		if domainBound {
			v.hashToSignatures[commitInfoHash].scheme = votesig.SchemeDomainBound
			if committing {
				v.hashToSignatures[commitInfoHash].sealSignatures = make(map[string]hex.Bytes)
			}
		}
	}
	// Add signature from vote
	quorum := v.hashToSignatures[commitInfoHash]
	quorum.signatures[vote.Author] = vote.Signature
	if quorum.sealSignatures != nil {
		quorum.sealSignatures[vote.Author] = vote.SealSignature
	}
	// Check QC
	weight, err := signedWeight(quorum.signatures, quorumInfo)
	if err != nil {
		return nil, fmt.Errorf("vote weight: %w", err)
	}
	if reached(weight, quorumInfo) {
		qc := drctypes.NewQuorumCertificateFromVote(quorum.voteInfo, quorum.commitInfo, quorum.signatures)
		if quorum.scheme == votesig.SchemeDomainBound {
			// the certificate is made of the two signature maps of the one set of voters; the seal map is the only one a UC takes
			qc.Scheme, qc.SealSignatures = votesig.SchemeDomainBound, quorum.sealSignatures
		}
		return qc, nil
	}
	// Vote registered, no QC could be formed
	return nil, nil
}

/*
InsertTimeoutVote returns non nil TC when quorum has been achieved.
Second return value is number of signatures in the TC.
*/
func (v *VoteRegister) InsertTimeoutVote(timeout *abdrc.TimeoutMsg, quorumInfo QuorumInfo) (*drctypes.TimeoutCert, uint64, error) {
	// Create partial timeout cert on first vote received
	if v.timeoutCert == nil {
		v.timeoutCert = &drctypes.TimeoutCert{
			Timeout:    timeout.Timeout,
			Signatures: make(map[string]*drctypes.TimeoutVote),
		}
	}
	// append signature
	if err := v.timeoutCert.Add(timeout.Author, timeout.Timeout, timeout.Signature); err != nil {
		return nil, 0, fmt.Errorf("failed to add vote to timeout certificate: %w", err)
	}

	// Check if TC can be formed
	sigCount, err := signedTimeoutWeight(v.timeoutCert.Signatures, quorumInfo)
	if err != nil {
		return nil, 0, fmt.Errorf("timeout vote weight: %w", err)
	}
	if reached(sigCount, quorumInfo) {
		return v.timeoutCert, sigCount, nil
	}
	// No quorum yet, but also no error all is fine
	return nil, sigCount, nil
}

// reached is the quorum test over an already checked weight sum.
func reached(weight uint64, quorum QuorumInfo) bool {
	return quorumweight.Reached(weight, quorum.GetQuorumThreshold())
}

// authorWeight is the weight of one author: the member's stake under profile 2, 1 per author otherwise. An author that
// is not a member of a weighted committee is an error, not weight 0.
func authorWeight(quorum QuorumInfo, author string) (uint64, error) {
	if _, enabled := quorum.(interface{ usesStakeWeighting() }); !enabled {
		return 1, nil
	}
	if members, ok := quorum.(interface{ GetRootNodes() []*types.NodeInfo }); ok {
		for _, member := range members.GetRootNodes() {
			if member != nil && member.NodeID == author {
				return member.Stake, nil
			}
		}
		return 0, fmt.Errorf("%w: %q", quorumweight.ErrUnknownSigner, author)
	}
	return 1, nil
}

func signedWeight(votes map[string]hex.Bytes, quorum QuorumInfo) (uint64, error) {
	var tally quorumweight.Tally
	for author := range votes {
		w, err := authorWeight(quorum, author)
		if err != nil {
			return 0, err
		}
		if err := tally.Add(author, w); err != nil {
			return 0, err
		}
	}
	return tally.Weight(), nil
}

func signedTimeoutWeight(votes map[string]*drctypes.TimeoutVote, quorum QuorumInfo) (uint64, error) {
	var tally quorumweight.Tally
	for author := range votes {
		w, err := authorWeight(quorum, author)
		if err != nil {
			return 0, err
		}
		if err := tally.Add(author, w); err != nil {
			return 0, err
		}
	}
	return tally.Weight(), nil
}

// committeeWeight is the total voting weight of the committee through the checked tally: the member's stake under
// profile 2 and 1 per unique member otherwise (the same unit weight authorWeight gives each signer). It reports false
// for a QuorumInfo that does not list its members, which only a test double can be.
func committeeWeight(quorum QuorumInfo) (uint64, bool, error) {
	members, ok := quorum.(interface{ GetRootNodes() []*types.NodeInfo })
	if !ok {
		return 0, false, nil
	}
	_, weighted := quorum.(interface{ usesStakeWeighting() })
	var tally quorumweight.Tally
	for _, member := range members.GetRootNodes() {
		if member == nil {
			return 0, true, quorumweight.ErrUnknownSigner
		}
		w := uint64(1)
		if weighted {
			w = member.Stake
		}
		if err := tally.Add(member.NodeID, w); err != nil {
			return 0, true, err
		}
	}
	if tally.Weight() == 0 {
		return 0, true, quorumweight.ErrZeroWeight
	}
	return tally.Weight(), true, nil
}

// maxFaultyWeight is the timeout-vote weight that is still tolerated before the pacemaker jumps to the timeout state:
// total weight - threshold, with the total taken through committeeWeight. A committee that is empty or whose total
// overflows can never amplify, so it returns the largest value.
func maxFaultyWeight(quorum QuorumInfo) uint64 {
	total, listed, err := committeeWeight(quorum)
	if !listed {
		return quorum.GetMaxFaultyNodes() // a test double without members; a production trust base always lists them
	}
	if err != nil {
		return math.MaxUint64
	}
	if threshold := quorum.GetQuorumThreshold(); total >= threshold {
		return total - threshold
	}
	return 0
}

func (v *VoteRegister) Reset() {
	clear(v.hashToSignatures)
	clear(v.authorToVote)
	v.timeoutCert = nil
}
