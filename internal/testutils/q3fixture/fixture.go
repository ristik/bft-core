// Package q3fixture builds one committed Q3 activation for tests: a unit genesis committee of four, its commit of a root-only
// handoff to a coupled V3 committee with chosen weights (three retained members and one new), the proof envelope the history
// verifies, the native recovery checkpoint the root installs its anchor from, and the readiness receipts of every successor member.
package q3fixture

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// PartitionID and the empty shard are the EVM shard of the fixture's checkpoint.
const (
	PartitionID types.PartitionID = 0x00FF0001
	Network                       = 5
	attempt                       = 0
)

// Options shape the fixture. The zero value is the 6,1,1,1 activation at A*=7 with the old commit sealed at round 4.
type Options struct {
	Weights         []uint64 // successor weights in member order; four members
	CommitSealRound uint64   // the old committee's commit round (>= the ordered round 4)
	SignedBy        int      // how many of the four old members sign the commit; default 3 (the unit threshold); fewer is a forgery
	// After appends an activation to the given fixture's chain: its weighted committee commits this fixture's successor body
	// under scheme 2. The
	// old committee signs with its first SignedBy members in member order (default 2: the heavy member and one light one, weight 7
	// of 9). By default the commit and activation are eight rounds after the predecessor's.
	After *Fixture
	// Frozen is the frozen EVM parent the checkpoint and the evidence name; default 32 bytes of 5.
	Frozen []byte
	// Chain makes this another activation of the same chain as the given fixture: the same genesis and old committee, so that the
	// proofs of both authenticate under the same old keys and differ only in what the options change (the weights, say).
	Chain *Fixture
	// Assignment makes the handoff coupled: the committed candidate carries a successor EVM assignment whose validators mirror the
	// root weights, with proofs of possession and the root-to-EVM bindings. The activation is then the one the install of a
	// candidate-bearing handoff takes: the manager installs it only with the committed candidate (ErrQ3Candidate otherwise), and the
	// request history serves its weighted context.
	Assignment bool
	// CandidateRootWeights are the weights the candidate states for the successor root committee (in node-id order) when they are not
	// the body's, and EVMWeights the EVM validators' weights when they do not mirror the candidate's root weights (a coupling
	// violation). Each defaults to what the other states.
	CandidateRootWeights []uint64
	EVMWeights           []uint64
	// MutateCandidate edits the candidate before its digest is bound, so that the chain of hashes stays consistent and only the
	// edited property is wrong.
	MutateCandidate func(*evmassign.Candidate)
	// ShardState and Installed supply the authenticated state and configuration for a successive coupled handoff.
	ShardState *storage.ShardInfo
	Installed  *types.PartitionDescriptionRecord
}

// Fixture is one activation and everything that authenticates it.
type Fixture struct {
	Old             *types.RootTrustBaseV1
	Genesis         [32]byte
	OldNodes        []*testutils.TestNode
	NewNodes        []*testutils.TestNode // the successor committee in member order: the first three are old members
	Members         evmroot.WeightSet
	Body            q3format.BodyV3
	Evidence        q3format.Evidence
	Receipts        []q3format.Receipt
	Proof           handoff.OldCommitProof
	ProofBytes      []byte
	Link            q3format.Link
	Envelope        q3format.Envelope
	EnvelopeBytes   []byte
	Snapshot        *abdrc.CommittedBlock
	ShardConf       *types.PartitionDescriptionRecord
	Claim           q3format.Claim
	Candidate       []byte                            // the committed candidate preimage, with Options.Assignment
	Successor       *types.PartitionDescriptionRecord // the EVM assignment it activates (before the activation round is set)
	FrozenParent    []byte
	CommitSealRound uint64
	EVMSigners      map[string]abcrypto.Signer
	Prev            *Fixture // the first activation this one follows, with Options.After
}

// Signers maps node id to signer for a committee.
func Signers(nodes []*testutils.TestNode) map[string]abcrypto.Signer {
	out := make(map[string]abcrypto.Signer, len(nodes))
	for _, n := range nodes {
		out[n.PeerConf.ID.String()] = n.Signer
	}
	return out
}

// New builds the fixture.
func New(t *testing.T, o Options) *Fixture {
	t.Helper()
	if o.Weights == nil {
		o.Weights = []uint64{6, 1, 1, 1}
	}
	if o.CommitSealRound == 0 {
		o.CommitSealRound = 4
		if o.After != nil {
			o.CommitSealRound = o.After.CommitSealRound + 8
		}
	}
	if o.SignedBy == 0 {
		o.SignedBy = 3
		if o.After != nil {
			o.SignedBy = 2
		}
	}
	if o.Frozen == nil {
		o.Frozen = bytes.Repeat([]byte{5}, 32)
	}
	require.Len(t, o.Weights, 4)
	f := &Fixture{FrozenParent: bytes.Clone(o.Frozen), CommitSealRound: o.CommitSealRound}
	switch {
	case o.After != nil:
		f.Old, f.OldNodes = o.After.Old, o.After.NewNodes
	case o.Chain != nil:
		f.OldNodes, f.Old = o.Chain.OldNodes, o.Chain.Old
	default:
		f.OldNodes = make([]*testutils.TestNode, 4)
		for i := range f.OldNodes {
			f.OldNodes[i] = testutils.NewTestNode(t)
		}
		f.Old = testtrustbase.NewTrustBaseFromSigners(t, Signers(f.OldNodes)).(*types.RootTrustBaseV1)
	}
	genesisID, err := f.Old.Hash(crypto.SHA256)
	require.NoError(t, err)
	copy(f.Genesis[:], genesisID)
	// the epoch whose committee commits this handoff: the genesis (epoch 1, scheme 1, unit) or the first activation's (epoch 2,
	// scheme 2, weighted)
	oldID, oldEpoch, oldVersion, oldTB, oldCfg := genesisID, uint64(1), uint64(1), f.Old, votesig.Config{}
	bodyEpoch, aMin, activate, ordered := uint64(2), uint64(7), uint64(7), uint64(4)
	if o.After != nil {
		h, err := q3format.NewHistory(f.Old)
		require.NoError(t, err)
		h, err = h.VerifyEnvelope(o.After.Envelope)
		require.NoError(t, err, "the preceding activations must be valid")
		tip := h.Tip()
		oldCfg, err = h.Signing(tip.Epoch())
		require.NoError(t, err)
		tipID := tip.BodyID()
		oldID, oldEpoch, oldVersion, oldTB = tipID[:], tip.Epoch(), tip.Version(), tip.Projection()
		bodyEpoch, aMin, activate, ordered = oldEpoch+1, tip.Start()+8, tip.Start()+8, o.CommitSealRound
		f.Prev = o.After
	}

	f.NewNodes = append([]*testutils.TestNode(nil), f.OldNodes[:3]...)
	f.NewNodes = append(f.NewNodes, testutils.NewTestNode(t))
	for i, n := range f.NewNodes {
		verifier, err := n.Signer.Verifier()
		require.NoError(t, err)
		key, err := verifier.MarshalPublicKey()
		require.NoError(t, err)
		f.Members = append(f.Members, evmroot.Member{StakingID: fmt.Sprintf("stake-%d", i), NodeID: n.PeerConf.ID.String(), ConsensusKey: key, Weight: o.Weights[i]})
	}
	var total uint64
	for _, w := range o.Weights {
		total += w
	}
	prior, err := q3format.Prior{Network: Network, Epoch: oldEpoch, BodyVersion: oldVersion, Identity: oldID}.Hash()
	require.NoError(t, err)
	body := q3format.BodyV3{Network: Network, Epoch: bodyEpoch, EarliestActivation: aMin, Members: f.Members, RootThreshold: total*2/3 + 1,
		StateSummary: bytes.Repeat([]byte{0x22}, 32), PredecessorHash: prior, Config: q3format.Q3Config(Network, f.Genesis)}
	operator, err := evmroot.D4OperatorCandidateDigest(f.Members)
	require.NoError(t, err)
	var shardConf *types.PartitionDescriptionRecord
	_, validators := testutils.CreateTestNodes(t, 3)
	shardConf = &types.PartitionDescriptionRecord{Version: 1, NetworkID: Network, PartitionID: PartitionID, ShardID: types.ShardID{},
		PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 2500 * time.Millisecond, Validators: validators, Epoch: 0, EpochStart: 1}
	if o.After != nil {
		shardConf = o.After.ShardConf // the same shard: the node's orchestration holds one configuration of it
	}
	if o.Installed != nil {
		shardConf = o.Installed
	}
	f.ShardConf = shardConf
	if o.Assignment {
		operator = f.assignment(t, o, oldID)
	}
	body.ChangeRecordHash = evmroot.D4CandidateContextHash(Network, oldID, attempt, operator[:], body.EarliestActivation)
	require.NoError(t, body.Validate())
	f.Body = body
	bodyID := body.Identity()

	state, err := storage.NewShardInfo(f.ShardConf, crypto.SHA256)
	require.NoError(t, err)
	if o.ShardState != nil {
		copyState := *o.ShardState
		copyIR := *o.ShardState.IR
		copyState.IR = &copyIR
		state = &copyState
	}
	state.IR.BlockHash = bytes.Clone(o.Frozen)
	state.IR.Hash = bytes.Repeat([]byte{0x37}, 32)
	trHash, err := state.TR.Hash()
	require.NoError(t, err)
	if o.Assignment { // a coupled handoff commits the technical record derived from the candidate's successor assignment
		derived, derr := storage.AssignmentSuccessorTRHash(state, f.Candidate, activate, crypto.SHA256)
		switch {
		case derr == nil:
			trHash = derived
		case o.MutateCandidate == nil && o.EVMWeights == nil && o.CandidateRootWeights == nil:
			require.NoError(t, derr) // only a deliberately malformed candidate may fail to derive
		}
	}

	f.Evidence = q3format.Evidence{Summary: bytes.Repeat([]byte{0x55}, 32), FrozenParent: bytes.Clone(o.Frozen), CandidateDigest: operator[:]}
	record := evmroot.OrderedHandoffRecord{Network: Network, Epoch: oldEpoch, Attempt: attempt, OrderedRound: ordered, ActivationRound: activate,
		PredecessorBodyID: oldID, NextBodyID: bodyID[:], SuccessorTRHash: trHash, Kind: "commit",
		FrozenID: evmroot.D4FrozenID(bodyID[:], f.Evidence.Summary, f.Evidence.FrozenParent, f.Evidence.CandidateDigest, attempt, oldID)}
	control := evmroot.ControlState{Network: Network, Epoch: oldEpoch, Attempt: attempt, OrderedRound: ordered, PredecessorBodyID: oldID, Phase: "committed",
		RecordBytes: record.Bytes(), PreviousDigest: bytes.Repeat([]byte{4}, 32), FrozenParent: bytes.Clone(o.Frozen)}
	key := types.PartitionShardID{PartitionID: PartitionID, ShardID: types.ShardID{}.Key()}
	states := storage.ShardStates{States: map[types.PartitionShardID]*storage.ShardInfo{key: state}, Changed: storage.ShardSet{key: {}}, Control: &control}
	tree, _, err := states.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	path, err := tree.Certificate(evmroot.D4ControlPartition)
	require.NoError(t, err)
	stamp := types.NewTimestamp()
	vote := &rctypes.RoundInfo{Version: 1, RoundNumber: o.CommitSealRound + 1, ParentRoundNumber: o.CommitSealRound, Epoch: oldEpoch, Timestamp: stamp, CurrentRootHash: tree.RootHash()}
	seal := &types.UnicitySeal{Version: 1, NetworkID: Network, RootChainRoundNumber: o.CommitSealRound, Epoch: oldEpoch, Timestamp: stamp, Hash: tree.RootHash()}
	qc := &rctypes.QuorumCert{VoteInfo: vote, LedgerCommitInfo: seal, Signatures: map[string]hex.Bytes{}}
	if oldCfg.Scheme == votesig.SchemeDomainBound {
		vote.Timestamp = 0 // a scheme 2 vote info carries no timestamp
		vi := votesig.VoteInfo{Epoch: vote.Epoch, Round: vote.RoundNumber, Parent: vote.ParentRoundNumber}
		copy(vi.Exec[:], vote.CurrentRootHash)
		vh, err := oldCfg.VoteInfoHash(vi)
		require.NoError(t, err)
		seal.PreviousHash = vh[:]
		pv, sealBytes, _, err := rctypes.DomainBoundStatement(oldCfg, vote, seal, true)
		require.NoError(t, err)
		qc.Scheme, qc.SealSignatures = votesig.SchemeDomainBound, map[string]hex.Bytes{}
		for _, n := range f.OldNodes[:o.SignedBy] {
			id := n.PeerConf.ID.String()
			qc.Signatures[id], err = n.Signer.SignBytes(pv)
			require.NoError(t, err)
			qc.SealSignatures[id], err = n.Signer.SignBytes(sealBytes)
			require.NoError(t, err)
		}
	} else {
		voteHash, err := vote.Hash(crypto.SHA256)
		require.NoError(t, err)
		seal.PreviousHash = voteHash
		message, err := seal.SigBytes()
		require.NoError(t, err)
		for _, n := range f.OldNodes[:o.SignedBy] {
			sig, err := n.Signer.SignBytes(message)
			require.NoError(t, err)
			qc.Signatures[n.PeerConf.ID.String()] = sig
		}
	}
	f.Proof = handoff.OldCommitProof{Profile: evmroot.D4Profile, Record: record, Control: control, ControlPath: path, CommitQC: qc}
	f.ProofBytes, err = types.Cbor.Marshal(f.Proof)
	require.NoError(t, err)
	// the old committee's certificates of the checkpoint: what the shard's last certified record becomes
	oldBlock := &storage.ExecutedBlock{HashAlgo: crypto.SHA256, RootHash: tree.RootHash(), ShardState: states}
	certificates, err := oldBlock.GenerateCertificates(qc)
	require.NoError(t, err)
	require.Len(t, certificates, 1)
	shardInfo := abdrc.ShardInfo{Partition: PartitionID, Shard: types.ShardID{}, T2Timeout: state.T2Timeout, RootHash: state.RootHash,
		PrevEpochStat: state.PrevEpochStat, Stat: state.Stat, PrevEpochFees: state.PrevEpochFees, Fees: state.Fees, IR: state.IR, IRTR: state.TR,
		ShardConfHash: state.ShardConfHash, UC: &state.LastCR.UC, TR: &state.LastCR.Technical}
	f.Snapshot = &abdrc.CommittedBlock{Block: &rctypes.BlockData{Version: 2, Epoch: oldEpoch, Round: o.CommitSealRound, Payload: &rctypes.Payload{Version: 2}},
		ShardInfo: []abdrc.ShardInfo{shardInfo}, Control: &control, CommitQc: qc}

	ctx := q3format.ContextFor(body, attempt, [32]byte(f.Evidence.CandidateDigest))
	for i, m := range f.Members {
		r, err := q3format.SignReceipt(ctx, m.NodeID, f.NewNodes[i].Signer)
		require.NoError(t, err)
		f.Receipts = append(f.Receipts, r)
	}
	sort.Slice(f.Receipts, func(a, b int) bool { return f.Receipts[a].NodeID < f.Receipts[b].NodeID }) // the envelope orders them by node id
	f.Link = q3format.Link{Body: body, Evidence: f.Evidence, Proof: f.ProofBytes, Receipts: f.Receipts}
	threshold := oldTB.QuorumThreshold
	var signed uint64
	for _, n := range f.OldNodes[:o.SignedBy] {
		for _, m := range oldTB.RootNodes {
			if m.NodeID == n.PeerConf.ID.String() {
				signed += m.Stake
			}
		}
	}
	if signed < threshold {
		// a commit below the old threshold authenticates nothing: the claim is what an honest history would derive for the record
		f.Claim = q3format.Claim{Epoch: bodyEpoch, Start: activate, BodyID: bodyID, PriorVersion: oldVersion}
		copy(f.Claim.CommitID[:], record.ID())
		copy(f.Claim.PriorID[:], oldID)
	} else {
		h, err := q3format.NewHistory(f.Old)
		require.NoError(t, err)
		if o.After != nil {
			h, err = h.VerifyEnvelope(o.After.Envelope)
			require.NoError(t, err)
		}
		next, err := h.WithV3(f.Link)
		require.NoError(t, err, "the fixture must be a valid activation")
		f.Claim = next.Tip().Claim()
	}
	f.Link.Claim = f.Claim
	f.Envelope = q3format.Envelope{RootInput: []byte{0xAB}, TargetParent: bytes.Clone(o.Frozen), Links: []q3format.Link{f.Link}}
	if o.After != nil { // retain the whole lineage so the history rebuilds from the genesis alone
		f.Envelope.Links = append(append([]q3format.Link(nil), o.After.Envelope.Links...), f.Link)
	}
	f.EnvelopeBytes, err = f.Envelope.Encode()
	require.NoError(t, err)
	return f
}

// assignment builds the coupled candidate for the successor committee and returns its digest, which the body binds.
func (f *Fixture) assignment(t *testing.T, o Options, oldID []byte) [32]byte {
	t.Helper()
	root := make([]evmassign.RootMember, len(f.Members))
	for i, m := range f.Members {
		root[i] = evmassign.RootMember{NodeID: m.NodeID, Key: m.ConsensusKey, Weight: m.Weight}
	}
	sort.Slice(root, func(i, j int) bool { return root[i].NodeID < root[j].NodeID })
	if o.CandidateRootWeights != nil {
		for i := range root {
			root[i].Weight = o.CandidateRootWeights[i]
		}
	}
	type evmKey struct {
		signer abcrypto.Signer
		info   *types.NodeInfo
	}
	f.EVMSigners = make(map[string]abcrypto.Signer)
	keys := make([]evmKey, len(root))
	validators := make([]*types.NodeInfo, len(root))
	for i, m := range root {
		signer, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		verifier, err := signer.Verifier()
		require.NoError(t, err)
		pub, err := verifier.MarshalPublicKey()
		require.NoError(t, err)
		weight := m.Weight
		if o.EVMWeights != nil {
			weight = o.EVMWeights[i]
		}
		keys[i] = evmKey{signer, &types.NodeInfo{NodeID: fmt.Sprintf("evm-%d", i), SigKey: pub, Stake: weight}}
		validators[i] = keys[i].info
		f.EVMSigners[keys[i].info.NodeID] = signer
	}
	succ, err := evmassign.NewSuccessor(f.ShardConf, validators)
	require.NoError(t, err)
	f.Successor = succ
	ctx := evmassign.PoPContext{Network: Network, Attempt: attempt}
	copy(ctx.Predecessor[:], oldID)
	var pops []evmassign.PoP
	var bindings []evmassign.Binding
	for i, k := range keys {
		pop, err := evmassign.SignPoP(k.signer, ctx, succ, k.info.NodeID)
		require.NoError(t, err)
		pops = append(pops, pop)
		bindings = append(bindings, evmassign.Binding{RootNodeID: root[i].NodeID, EVMNodeID: k.info.NodeID})
	}
	raw, err := types.Cbor.Marshal(succ)
	require.NoError(t, err)
	old, err := evmassign.PDRHash(f.ShardConf)
	require.NoError(t, err)
	c := evmassign.Candidate{Version: evmassign.CandidateVersion, Network: Network, Predecessor: bytes.Clone(oldID), Attempt: attempt, RootMembers: root,
		OldShardEpoch: f.ShardConf.Epoch, OldActiveHash: old[:], Assignment: raw, PoPs: pops, Bindings: bindings}
	if o.MutateCandidate != nil {
		o.MutateCandidate(&c)
	}
	f.Candidate, err = c.Encode()
	require.NoError(t, err)
	return sha256.Sum256(f.Candidate)
}
