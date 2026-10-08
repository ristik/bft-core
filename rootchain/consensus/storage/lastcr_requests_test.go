package storage

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// lastCRPipeline is the installed EVM shard (unit policy) of a BlockStore on which pipelines are executed before their commits.
type lastCRPipeline struct {
	t        *testing.T
	f        *assignmentFixture
	s        *BlockStore
	hist     activeHistory
	verifier *viewVerifier
}

func newLastCRPipeline(t *testing.T) *lastCRPipeline {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.installShard(t, f.current, func(si *ShardInfo) { lastCRFixture(f, si) })
	h := f.commitAssignment(t)
	anchorBlock, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	f.addSuccessorBlock(t, s, 7, anchorBlock)
	genesisAnchor, err := NewRequestAnchor(f.current, crypto.SHA256, 1, f.predecessor, fxVersion)
	require.NoError(t, err)
	body := bytes.Clone(h.commit.NextBodyID)
	activation, err := newRequestActivation(h.activated, crypto.SHA256, quorumweight.PolicyUnit, nil, h.genesis.Epoch, body, h.genesis.Start, h.successorT, fxVersion)
	require.NoError(t, err)
	hist := activeHistory{chain: []*RequestActivation{genesisAnchor, activation}, body: body}
	return &lastCRPipeline{t: t, f: f, s: s, hist: hist, verifier: &viewVerifier{t: t, history: hist}}
}

func (p *lastCRPipeline) add(s *BlockStore, round, parent uint64, reqs ...*rctypes.IRChangeReq) (*ExecutedBlock, error) {
	p.t.Helper()
	pb := mustBlock(p.t, s, parent)
	_, err := s.Add(&rctypes.BlockData{Version: 2, Round: round, Epoch: 2, Timestamp: 1_000 + round, Payload: &rctypes.Payload{Version: 2, Requests: reqs},
		Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: parent, Epoch: 2, CurrentRootHash: pb.RootHash}}}, p.verifier)
	if err != nil {
		return nil, err
	}
	return mustBlock(p.t, s, round), nil
}

func (p *lastCRPipeline) commit(s *BlockStore, round uint64) {
	p.t.Helper()
	b := mustBlock(p.t, s, round)
	_, err := s.blockTree.Commit(&rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round + 1, ParentRoundNumber: round, Epoch: 2},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: round, Epoch: 2, Timestamp: 1_000 + round, Hash: b.RootHash}})
	require.NoError(p.t, err)
}

func (p *lastCRPipeline) timeout() *rctypes.IRChangeReq {
	return &rctypes.IRChangeReq{Partition: p.f.current.PartitionID, CertReason: rctypes.T2Timeout}
}

// request is the quorum proof of the given installed members for the state the view of the tip expects, with every field overridable.
type reqOpts struct {
	timestamp, round, epoch uint64
	prev, hash              []byte
	reason                  rctypes.IRChangeReason
}

func (p *lastCRPipeline) proof(tip *ExecutedBlock, o reqOpts, keys ...evmKey) *rctypes.IRChangeReq {
	p.t.Helper()
	cr := tip.ShardState.States[p.f.shard].LastCR
	cur := tip.ShardState.States[p.f.shard]
	if o.round == 0 {
		o.round = cr.Technical.Round
	}
	if o.epoch == 0 && cr.Technical.Epoch != 0 {
		o.epoch = cr.Technical.Epoch
	}
	if o.timestamp == 0 {
		o.timestamp = cr.UC.UnicitySeal.Timestamp
	}
	if o.prev == nil {
		o.prev = bytes.Clone(cur.IR.Hash)
	}
	if o.hash == nil {
		o.hash = bytes.Repeat([]byte{0x78}, 32)
	}
	var reqs []*certification.BlockCertificationRequest
	for i, k := range keys {
		hash := o.hash
		if o.reason == rctypes.QuorumNotPossible { // every member certifies another state
			hash = append(bytes.Clone(o.hash[:31]), byte(i+1))
		}
		r := &certification.BlockCertificationRequest{PartitionID: p.f.current.PartitionID, ShardID: types.ShardID{}, NodeID: k.id,
			InputRecord: &types.InputRecord{Version: 1, RoundNumber: o.round, Epoch: o.epoch, PreviousHash: o.prev, Hash: hash,
				BlockHash: bytes.Repeat([]byte{0x77}, 32), SummaryValue: []byte{3}, Timestamp: o.timestamp}}
		require.NoError(p.t, r.Sign(k.signer))
		reqs = append(reqs, r)
	}
	reason := o.reason
	return &rctypes.IRChangeReq{Partition: p.f.current.PartitionID, CertReason: reason, Requests: reqs}
}

func (p *lastCRPipeline) members() []evmKey {
	return []evmKey{p.f.nextKeys[0], p.f.nextKeys[1], p.f.nextKeys[3]}
}

// The core regression: a pipeline executed BEFORE a T2 commit is extended with a freshly signed request that is based on the committed repeat
// UC and technical record, and it is accepted. The timeout, commit, fresh request and its commit repeat, and a timeout after a state-changing
// certification derives its repeat IR from the latest certified state, never from stale metadata.
func TestFreshRequestExecutesOnThePreexistingTipAfterEveryRepeatCommit(t *testing.T) {
	p := newLastCRPipeline(t)
	s := p.s
	parent := uint64(7)
	var lastIR []byte
	for cycle := 0; cycle < 3; cycle++ {
		base := parent + 10 // the timeout is older than T2 against the latest certified root round
		b1, err := p.add(s, base, parent, p.timeout())
		require.NoError(t, err, "cycle %d: the T2 timeout executes", cycle)
		if lastIR != nil {
			require.Equal(t, lastIR, []byte(b1.ShardState.States[p.f.shard].IR.Hash), "cycle %d: the repeat IR derives from the latest certified state, not stale metadata", cycle)
		}
		_, err = p.add(s, base+1, base)
		require.NoError(t, err)
		tip, err := p.add(s, base+2, base+1)
		require.NoError(t, err)
		rootBefore := mustBlock(t, s, parent).ShardState.States[p.f.shard].LastCR
		require.Same(t, rootBefore, tip.ShardState.States[p.f.shard].LastCR, "cycle %d: an executed but uncommitted timeout publishes no pair", cycle)

		p.commit(s, base)
		fresh := mustBlock(t, s, base).ShardState.States[p.f.shard].LastCR
		require.NotSame(t, rootBefore, fresh)
		require.Same(t, fresh, tip.ShardState.States[p.f.shard].LastCR)

		ack, err := p.add(s, base+3, base+2, p.proof(tip, reqOpts{hash: bytes.Repeat([]byte{byte(0x78 + cycle)}, 32)}, p.members()...))
		require.NoError(t, err, "cycle %d: the fresh request on the pre-existing tip", cycle)
		require.Contains(t, ack.ShardState.Changed, p.f.shard, "cycle %d", cycle)
		got := ack.ShardState.States[p.f.shard]
		require.Equal(t, bytes.Repeat([]byte{byte(0x78 + cycle)}, 32), []byte(got.IR.Hash))
		lastIR = bytes.Clone(got.IR.Hash)
		p.commit(s, base+3)
		require.Same(t, mustBlock(t, s, base+3).ShardState.States[p.f.shard].LastCR, ack.ShardState.States[p.f.shard].LastCR)
		// the next cycle's request must carry another state
		parent = base + 3
		_ = got
	}
}

// After a newer repeat UC commits, a request built on the superseded pair is refused, each way alone, with the stale sentinel at admission and
// the existing no-effect treatment at execution; the fresh one built on the same state is accepted.
func TestStaleRequestsAfterANewerRepeatCommit(t *testing.T) {
	p := newLastCRPipeline(t)
	s := p.s
	_, err := p.add(s, 8, 7, p.timeout())
	require.NoError(t, err)
	_, err = p.add(s, 9, 8)
	require.NoError(t, err)
	tip, err := p.add(s, 10, 9)
	require.NoError(t, err)
	oldSeal := tip.ShardState.States[p.f.shard].LastCR.UC.UnicitySeal.Timestamp
	p.commit(s, 8)
	cr := tip.ShardState.States[p.f.shard].LastCR
	require.NotEqual(t, oldSeal, cr.UC.UnicitySeal.Timestamp, "premise: the seal moved")

	parentID, err := tip.BlockData.Hash(crypto.SHA256)
	require.NoError(t, err)
	view, err := ResolveParentView(p.hist, nil, tip.ShardState.States[p.f.shard], parentID, 11, crypto.SHA256, PurposeExecute, nil)
	require.NoError(t, err)

	okOpts := reqOpts{}
	require.NoError(t, view.ValidRequest(p.proof(tip, okOpts, p.members()[0]).Requests[0]), "control")

	cur := tip.ShardState.States[p.f.shard]
	next := uint64(100)
	for name, tc := range map[string]struct {
		opts reqOpts
		keys []evmKey
		want error
	}{
		"the old seal timestamp alone": {reqOpts{timestamp: oldSeal}, p.members(), ErrStaleRequestContext},
		"a future timestamp":           {reqOpts{timestamp: cr.UC.UnicitySeal.Timestamp + 1}, p.members(), ErrStaleRequestContext},
		"another previous state":       {reqOpts{prev: bytes.Repeat([]byte{9}, 32)}, p.members(), ErrStaleRequestContext},
		"another epoch":                {reqOpts{epoch: cr.Technical.Epoch + 1}, p.members(), ErrStaleRequestContext},
		"another round":                {reqOpts{round: cr.Technical.Round + 1}, p.members(), ErrStaleRequestContext},
		"a retired signer":             {reqOpts{}, []evmKey{p.f.oldKeys[3]}, ErrNodeNotInTrustBase},
	} {
		t.Run(name, func(t *testing.T) {
			proof := p.proof(tip, tc.opts, tc.keys...)
			require.ErrorIs(t, view.ValidRequest(proof.Requests[0]), tc.want)
			_, err := view.VerifyIRChangeReq(proof, t2Rounds)
			require.ErrorIs(t, err, tc.want)
			// at execution the ineligible request is ignored: nothing changes
			next++
			child, err := p.add(s, next, 10, proof)
			if err == nil {
				require.NotContains(t, child.ShardState.Changed, p.f.shard)
				require.Equal(t, cur.IR.Hash, child.ShardState.States[p.f.shard].IR.Hash)
			} else {
				require.ErrorIs(t, err, tc.want)
			}
		})
	}
	t.Run("a request built on the superseded pair as a whole", func(t *testing.T) {
		proof := p.proof(tip, reqOpts{timestamp: oldSeal, round: cr.Technical.Round - 1}, p.members()...)
		_, err := view.VerifyIRChangeReq(proof, t2Rounds)
		require.ErrorIs(t, err, ErrStaleRequestContext)
	})
}

// A QuorumNotPossible repeat and a freeze-free empty suffix: the repeat replaces the pair although the IR round, epoch and state repeat; a
// commit that generates no response leaves the pair, its seal and its identity untouched in the root and in every descendant.
func TestQuorumNotPossibleRepeatAndAnEmptyCommitKeepThePair(t *testing.T) {
	p := newLastCRPipeline(t)
	s := p.s
	// the first repeat commits (the successor epoch's record becomes the certified one), then a state-changing certification, so that a stale
	// pair would revert the IR on a later repeat
	_, err := p.add(s, 8, 7, p.timeout())
	require.NoError(t, err)
	_, err = p.add(s, 9, 8)
	require.NoError(t, err)
	p.commit(s, 8)
	tip, err := p.add(s, 10, 9, p.proof(mustBlock(t, s, 9), reqOpts{}, p.members()...))
	require.NoError(t, err)
	require.Contains(t, tip.ShardState.Changed, p.f.shard)
	certified := bytes.Clone(tip.ShardState.States[p.f.shard].IR.Hash)
	require.Equal(t, bytes.Repeat([]byte{0x78}, 32), certified, "premise: the state-changing certification executed")
	p.commit(s, 10)
	afterCert := mustBlock(t, s, 10).ShardState.States[p.f.shard].LastCR

	// every installed member certifies another state: no quorum is possible
	np := p.proof(mustBlock(t, s, 10), reqOpts{reason: rctypes.QuorumNotPossible}, p.f.nextKeys[0], p.f.nextKeys[1], p.f.nextKeys[2], p.f.nextKeys[3])
	b11, err := p.add(s, 11, 10, np)
	require.NoError(t, err)
	_, err = p.add(s, 12, 11)
	require.NoError(t, err)
	require.Contains(t, b11.ShardState.Changed, p.f.shard)
	require.Equal(t, certified, []byte(b11.ShardState.States[p.f.shard].IR.Hash), "the repeat IR is the latest certified one")
	p.commit(s, 11)
	repeated := mustBlock(t, s, 11).ShardState.States[p.f.shard].LastCR
	require.NotSame(t, afterCert, repeated, "the repeat replaces the pair")
	require.Equal(t, afterCert.UC.InputRecord.RoundNumber, repeated.UC.InputRecord.RoundNumber, "although the IR round repeats")
	require.Less(t, afterCert.UC.UnicitySeal.RootChainRoundNumber, repeated.UC.UnicitySeal.RootChainRoundNumber)
	require.Same(t, repeated, mustBlock(t, s, 12).ShardState.States[p.f.shard].LastCR)

	// a commit that generates no response invents none
	p.commit(s, 12)
	require.Same(t, repeated, mustBlock(t, s, 12).ShardState.States[p.f.shard].LastCR)
	require.Equal(t, repeated.UC.UnicitySeal.Timestamp, mustBlock(t, s, 12).ShardState.States[p.f.shard].LastCR.UC.UnicitySeal.Timestamp)
	// and a timeout after the repeat still derives from the certified state
	b20, err := p.add(s, 20, 12, p.timeout())
	require.NoError(t, err)
	require.Equal(t, certified, []byte(b20.ShardState.States[p.f.shard].IR.Hash))
}

// Recovery ordering: the store reopened after a repeat commit, with persisted pending blocks that still hold the old pair, certifies a fresh
// request from the old tip to the same state as the uninterrupted store (the historical frontier is the persisted root's, not today's pair
// overlaid on an archived parent).
func TestReopenedStoreCertifiesFromTheOldTipLikeTheUninterruptedOne(t *testing.T) {
	p := newLastCRPipeline(t)
	s := p.s
	_, err := p.add(s, 8, 7, p.timeout())
	require.NoError(t, err)
	_, err = p.add(s, 9, 8)
	require.NoError(t, err)
	tip, err := p.add(s, 10, 9)
	require.NoError(t, err)
	p.commit(s, 8)
	proof := p.proof(tip, reqOpts{}, p.members()...)

	reopened, err := New(crypto.SHA256, p.f.store.storage, p.f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	got, err := p.add(reopened, 11, 10, proof)
	require.NoError(t, err, "the reopened store accepts the request built on the committed pair")
	want, err := p.add(s, 11, 10, proof)
	require.NoError(t, err)
	a, b := got.ShardState.States[p.f.shard], want.ShardState.States[p.f.shard]
	require.Equal(t, b.TR, a.TR)
	require.Equal(t, b.IR, a.IR)
	require.Contains(t, got.ShardState.Changed, p.f.shard)
	require.Equal(t, want.RootHash, got.RootHash)

	// a stale request is refused by the reopened store as well
	stale := p.proof(tip, reqOpts{timestamp: fxTimestamp}, p.members()...)
	ignored, err := p.add(reopened, 13, 10, stale)
	require.NoError(t, err)
	require.NotContains(t, ignored.ShardState.Changed, p.f.shard)
}
