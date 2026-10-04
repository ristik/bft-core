package consensus

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"go.etcd.io/bbolt"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// The scheme 2 safety module signs one statement per (epoch, round, kind). The tests run it on a real bolt file that is
// closed and reopened, so "restart" means what it says, and every refusal is pinned to its sentinel.

type fixedSigning struct {
	cfg votesig.Config
	err error
}

func (f fixedSigning) SigningConfig(uint64) (votesig.Config, error) { return f.cfg, f.err }

var errCrash = errors.New("simulated crash")

// crashingSigner fails the n-th and every later SignBytes call (counting from 1) when failFrom > 0.
type crashingSigner struct {
	abcrypto.Signer
	calls, failFrom int
}

func (c *crashingSigner) SignBytes(b []byte) ([]byte, error) {
	c.calls++
	if c.failFrom > 0 && c.calls >= c.failFrom {
		return nil, errCrash
	}
	return c.Signer.SignBytes(b)
}

// crashingStorage fails SetHighestQcRound (a vote) or SetHighestVotedRound (a timeout) once, after the decision and the signed
// message were recorded and before the signed message was returned.
type crashingStorage struct {
	storage.BoltDB
	failQc, failVoted bool
}

func (c *crashingStorage) SetHighestVotedRound(round uint64) error {
	if c.failVoted {
		c.failVoted = false
		return errCrash
	}
	return c.BoltDB.SetHighestVotedRound(round)
}

func (c *crashingStorage) SetHighestQcRound(q, v uint64) error {
	if c.failQc {
		c.failQc = false
		return errCrash
	}
	return c.BoltDB.SetHighestQcRound(q, v)
}

type decisionRig struct {
	t      *testing.T
	path   string
	signer abcrypto.Signer
	cfg    votesig.Config
	// executed is the local executed block of every committed round the rig is asked about
	executed CommittedBlockInfo
	db       *storage.BoltDB
}

func newDecisionRig(t *testing.T) *decisionRig {
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	cfg := domainBoundConfig()
	return &decisionRig{t: t, path: filepath.Join(t.TempDir(), "rc.db"), signer: signer, cfg: cfg,
		executed: CommittedBlockInfo{Epoch: 1, RootHash: bytes.Repeat([]byte{7}, 32), Timestamp: 4242}}
}

// open (re)opens the database file: the module that comes out has only what was persisted.
func (r *decisionRig) open(signer abcrypto.Signer, resolver SigningResolver) (*SafetyModule, storage.BoltDB) {
	r.closeDB()
	db, err := storage.NewBoltStorage(r.path, storage.WithNoSync())
	require.NoError(r.t, err)
	r.db = &db
	r.t.Cleanup(r.closeDB)
	return r.module(db, signer, resolver), db
}

// closeDB is the crash: whatever was not persisted is gone.
func (r *decisionRig) closeDB() {
	if r.db != nil {
		_ = r.db.Close()
		r.db = nil
	}
}

func (r *decisionRig) module(store SafetyStorage, signer abcrypto.Signer, resolver SigningResolver) *SafetyModule {
	m, err := NewSafetyModule(types.NetworkID(r.cfg.Network), "node1", signer, store,
		WithDomainBoundSigning(resolver, func(uint64) (CommittedBlockInfo, error) { return r.executed, nil }))
	require.NoError(r.t, err)
	return m
}

func (r *decisionRig) scheme2() SigningResolver { return fixedSigning{cfg: r.cfg} }

func hash32(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// committingBlock extends the QC of round-1, which commits it; its voting epoch is 1 as is the committed round's.
func (r *decisionRig) committingBlock(round uint64) *drctypes.BlockData {
	info := &drctypes.RoundInfo{Version: 1, RoundNumber: round - 1, Epoch: 1, ParentRoundNumber: round - 2, Timestamp: 99, CurrentRootHash: r.executed.RootHash}
	qc, err := newQuorumCertificate(r.t, info, nil)
	require.NoError(r.t, err)
	return &drctypes.BlockData{Round: round, Epoch: 1, Timestamp: 5000, Qc: qc}
}

// nonCommittingBlock extends a QC two rounds back through a timeout certificate of the previous round.
func (r *decisionRig) nonCommittingBlock(round uint64) (*drctypes.BlockData, *drctypes.TimeoutCert) {
	info := &drctypes.RoundInfo{Version: 1, RoundNumber: round - 2, Epoch: 1, ParentRoundNumber: round - 3, Timestamp: 99, CurrentRootHash: hash32(8)}
	qc, err := newQuorumCertificate(r.t, info, nil)
	require.NoError(r.t, err)
	tc := &drctypes.TimeoutCert{Timeout: &drctypes.Timeout{Epoch: 1, Round: round - 1, HighQc: qc}}
	return &drctypes.BlockData{Round: round, Epoch: 1, Qc: qc}, tc
}

func (r *decisionRig) verifyVote(v *abdrc.VoteMsg) {
	r.t.Helper()
	ver, err := r.signer.Verifier()
	require.NoError(r.t, err)
	pv, sealBytes, committing, err := drctypes.DomainBoundStatement(r.cfg, v.VoteInfo, v.LedgerCommitInfo, len(v.SealSignature) != 0)
	require.NoError(r.t, err)
	require.EqualValues(r.t, votesig.SchemeDomainBound, v.Scheme)
	require.NoError(r.t, ver.VerifyBytes(v.Signature, pv))
	if committing {
		require.NoError(r.t, ver.VerifyBytes(v.SealSignature, sealBytes))
	} else {
		require.Empty(r.t, v.SealSignature)
	}
}

func TestDomainBoundVoteSignsBothStatementsFromTheExecutedBlock(t *testing.T) {
	r := newDecisionRig(t)
	m, _ := r.open(r.signer, r.scheme2())

	v, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
	require.NoError(t, err)
	r.verifyVote(v)
	require.NotEmpty(t, v.SealSignature, "a committing vote carries the second signature")
	require.EqualValues(t, 4242, v.LedgerCommitInfo.Timestamp, "the seal timestamp is the executed block's, not the QC's")
	require.Zero(t, v.VoteInfo.Timestamp, "a scheme 2 vote info signs no timestamp")

	block, tc := r.nonCommittingBlock(8)
	v, err = m.MakeVote(block, hash32(2), nil, tc)
	require.NoError(t, err)
	r.verifyVote(v)
	require.Empty(t, v.SealSignature, "a non-committing vote has no seal signature")
}

func TestDomainBoundVoteRefusesAnExecutedBlockThatIsNotTheCommittedRound(t *testing.T) {
	for name, executed := range map[string]CommittedBlockInfo{
		"epoch": {Epoch: 2, RootHash: hash32(7), Timestamp: 1},
		"root":  {Epoch: 1, RootHash: hash32(9), Timestamp: 1},
	} {
		t.Run(name, func(t *testing.T) {
			r := newDecisionRig(t)
			r.executed = executed
			m, db := r.open(r.signer, r.scheme2())
			// the QC's committed round keeps epoch 1 and root 7: only the executed block differs
			block := r.committingBlock(5)
			block.Qc.VoteInfo.CurrentRootHash = hash32(7)
			_, err := m.MakeVote(block, hash32(1), nil, nil)
			require.ErrorIs(t, err, ErrCommittedBlock)
			d, derr := db.Decision(storage.DecisionVote, 1, 5)
			require.NoError(t, derr)
			require.Nil(t, d, "nothing was recorded for a vote that cannot be built")
		})
	}
	t.Run("no executed block source", func(t *testing.T) {
		r := newDecisionRig(t)
		_, db := r.open(r.signer, r.scheme2())
		m, err := NewSafetyModule(types.NetworkID(r.cfg.Network), "node1", r.signer, db, WithDomainBoundSigning(r.scheme2(), nil))
		require.NoError(t, err)
		_, err = m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
		require.ErrorIs(t, err, ErrCommittedBlock)
	})
}

func TestDomainBoundVoteSurvivesRestartButNeverSignsASecondStatement(t *testing.T) {
	r := newDecisionRig(t)
	m, _ := r.open(r.signer, r.scheme2())
	first, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
	require.NoError(t, err)
	r.closeDB()

	restarted, _ := r.open(r.signer, r.scheme2())
	// the retry of the same statement is reproduced, and it verifies
	again, err := restarted.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
	require.NoError(t, err)
	r.verifyVote(again)
	require.Equal(t, first.LedgerCommitInfo, again.LedgerCommitInfo)
	require.Equal(t, first.VoteInfo, again.VoteInfo)

	// a different executed state for the same (epoch, round) is a second decision
	_, err = restarted.MakeVote(r.committingBlock(5), hash32(2), nil, nil)
	require.ErrorIs(t, err, storage.ErrDecisionConflict)
	// and so is a different committed timestamp
	r.executed.Timestamp++
	retimed, _ := r.open(r.signer, r.scheme2())
	_, err = retimed.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
	require.ErrorIs(t, err, storage.ErrDecisionConflict)
}

// The signatures are made in memory and the decision is recorded with the complete signed vote before the vote is returned:
// a crash before or between the signatures leaves nothing recorded, so a retry is free and nothing was released.
func TestDomainBoundVoteCrashBeforeTheRecordLeavesNoDecision(t *testing.T) {
	for name, failFrom := range map[string]int{"before the vote signature": 1, "between the two signatures": 2} {
		t.Run(name, func(t *testing.T) {
			r := newDecisionRig(t)
			crashing := &crashingSigner{Signer: r.signer, failFrom: failFrom}
			m, db := r.open(crashing, r.scheme2())
			_, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
			require.ErrorIs(t, err, errCrash)
			d, err := db.Decision(storage.DecisionVote, 1, 5)
			require.NoError(t, err)
			require.Nil(t, d, "no signature left the node, so no decision is recorded")
			r.closeDB()

			restarted, db2 := r.open(r.signer, r.scheme2())
			v, err := restarted.MakeVote(r.committingBlock(5), hash32(2), nil, nil)
			require.NoError(t, err, "nothing was released, so another statement is still the node's first")
			r.verifyVote(v)
			d, err = db2.Decision(storage.DecisionVote, 1, 5)
			require.NoError(t, err)
			require.NotNil(t, d)
			// and from here on it is the recorded one
			_, err = restarted.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
			require.ErrorIs(t, err, storage.ErrDecisionConflict)
		})
	}
}

func TestDomainBoundVoteCrashAfterRecordBeforeTheRoundIsPersisted(t *testing.T) {
	r := newDecisionRig(t)
	r.closeDB()
	db, err := storage.NewBoltStorage(r.path, storage.WithNoSync())
	require.NoError(t, err)
	r.db = &db
	before := db.GetHighestVotedRound()
	store := &crashingStorage{BoltDB: db, failQc: true}
	m := r.module(store, r.signer, r.scheme2())
	_, hqc := r.nonCommittingBlock(8) // a high QC the first vote carried
	carried := hqc.Timeout.HighQc
	_, err = m.MakeVote(r.committingBlock(5), hash32(1), carried, nil)
	require.ErrorIs(t, err, errCrash)
	require.Equal(t, before, db.GetHighestVotedRound(), "the crash left the round unpersisted")
	r.closeDB()

	restarted, db2 := r.open(r.signer, r.scheme2())
	_, err = restarted.MakeVote(r.committingBlock(5), hash32(2), nil, nil)
	require.ErrorIs(t, err, storage.ErrDecisionConflict, "the recorded decision holds although the round was not persisted")
	// the retry, even with another high QC at hand, returns the message that was recorded, high QC included
	v, err := restarted.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
	require.NoError(t, err)
	r.verifyVote(v)
	require.NotNil(t, v.HighQc)
	require.Equal(t, carried.GetRound(), v.HighQc.GetRound(), "the recorded vote's own high QC, not the retry's")
	_, recorded, err := db2.SignedDecision(storage.DecisionVote, 1, 5)
	require.NoError(t, err)
	again, err := types.Cbor.Marshal(v)
	require.NoError(t, err)
	require.Equal(t, recorded, again, "the returned vote is the recorded message byte for byte")
	require.EqualValues(t, 5, db2.GetHighestVotedRound(), "the reproduction persisted the round")
}

func TestDomainBoundVoteStillObeysTheVotingRules(t *testing.T) {
	r := newDecisionRig(t)
	m, db := r.open(r.signer, r.scheme2())
	_, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
	require.NoError(t, err)
	// a lower round is refused by the round rule, and is not recorded as a decision
	_, err = m.MakeVote(r.committingBlock(4), hash32(1), nil, nil)
	require.ErrorIs(t, err, ErrAlreadyVotedForRound)
	d, err := db.Decision(storage.DecisionVote, 1, 4)
	require.NoError(t, err)
	require.Nil(t, d)
	// a block that does not extend its QC is refused and not recorded
	bad := r.committingBlock(9)
	bad.Qc.VoteInfo.RoundNumber = 3
	_, err = m.MakeVote(bad, hash32(1), nil, nil)
	require.ErrorIs(t, err, ErrNotSafeToVote)
	require.ErrorIs(t, err, ErrBlockNotExtendingQC)
	d, err = db.Decision(storage.DecisionVote, 1, 9)
	require.NoError(t, err)
	require.Nil(t, d)
}

func TestDomainBoundTimeoutIsOneDecisionPerRoundAndKind(t *testing.T) {
	r := newDecisionRig(t)
	m, _ := r.open(r.signer, r.scheme2())
	_, hqc := r.nonCommittingBlock(8) // any QC works as the high QC
	timeout := func(round uint64) *abdrc.TimeoutMsg {
		return abdrc.NewTimeoutMsg(&drctypes.Timeout{Epoch: 1, Round: round, HighQc: hqc.Timeout.HighQc}, "node1", hqc)
	}
	first := timeout(8)
	require.NoError(t, m.SignTimeout(first, hqc))
	require.EqualValues(t, votesig.SchemeDomainBound, first.Scheme)
	pt, err := first.Preimage(r.cfg)
	require.NoError(t, err)
	ver, err := r.signer.Verifier()
	require.NoError(t, err)
	require.NoError(t, ver.VerifyBytes(first.Signature, pt))
	r.closeDB()

	restarted, _ := r.open(r.signer, r.scheme2())
	again := timeout(8)
	require.NoError(t, restarted.SignTimeout(again, hqc), "the same timeout is reproduced after a restart")
	require.NoError(t, ver.VerifyBytes(again.Signature, pt))
	require.Equal(t, first.Signature, again.Signature, "it is the recorded message, not a new signature")

	// a different statement for round 8: another signer-visible high QC round
	other := timeout(8)
	other.Timeout.HighQc = &drctypes.QuorumCert{VoteInfo: &drctypes.RoundInfo{Version: 1, RoundNumber: 5, Epoch: 1, ParentRoundNumber: 4, Timestamp: 99, CurrentRootHash: hash32(3)},
		LedgerCommitInfo: hqc.Timeout.HighQc.LedgerCommitInfo}
	other.LastTC = &drctypes.TimeoutCert{Timeout: &drctypes.Timeout{Epoch: 1, Round: 7, HighQc: other.Timeout.HighQc}}
	require.ErrorIs(t, restarted.SignTimeout(other, other.LastTC), storage.ErrDecisionConflict)

	// a vote of the same round is another kind: it is not blocked by the timeout decision of that round
	block, tc := r.nonCommittingBlock(8)
	_, err = restarted.MakeVote(block, hash32(2), nil, tc)
	require.ErrorIs(t, err, ErrAlreadyVotedForRound, "the round rule, not the decision store, refuses the vote after a timeout")
}

func TestDomainBoundTimeoutCrashBeforeTheRecordLeavesNoDecision(t *testing.T) {
	r := newDecisionRig(t)
	crashing := &crashingSigner{Signer: r.signer, failFrom: 1}
	m, db := r.open(crashing, r.scheme2())
	_, hqc := r.nonCommittingBlock(8)
	msg := abdrc.NewTimeoutMsg(&drctypes.Timeout{Epoch: 1, Round: 8, HighQc: hqc.Timeout.HighQc}, "node1", hqc)
	require.ErrorIs(t, m.SignTimeout(msg, hqc), errCrash)
	d, err := db.Decision(storage.DecisionTimeout, 1, 8)
	require.NoError(t, err)
	require.Nil(t, d, "no signature left the node, so no decision is recorded")
	r.closeDB()

	restarted, _ := r.open(r.signer, r.scheme2())
	msg = abdrc.NewTimeoutMsg(&drctypes.Timeout{Epoch: 1, Round: 8, HighQc: hqc.Timeout.HighQc}, "node1", hqc)
	require.NoError(t, restarted.SignTimeout(msg, hqc))
}

// A crash after the decision and the signed timeout were recorded and before the timeout was returned: the recorded message is
// what a restart finds and sends, with the HighQC and last TC it was signed with.
func TestDomainBoundTimeoutCrashAfterTheRecordReplaysTheRecordedMessage(t *testing.T) {
	r := newDecisionRig(t)
	r.closeDB()
	db, err := storage.NewBoltStorage(r.path, storage.WithNoSync())
	require.NoError(t, err)
	r.db = &db
	m := r.module(&crashingStorage{BoltDB: db, failVoted: true}, r.signer, r.scheme2())
	_, hqc := r.nonCommittingBlock(8)
	msg := abdrc.NewTimeoutMsg(&drctypes.Timeout{Epoch: 1, Round: 8, HighQc: hqc.Timeout.HighQc}, "node1", hqc)
	require.ErrorIs(t, m.SignTimeout(msg, hqc), errCrash)
	r.closeDB()

	restarted, db2 := r.open(r.signer, r.scheme2())
	recorded, err := restarted.RecordedTimeout(1, 8)
	require.NoError(t, err)
	require.NotNil(t, recorded)
	require.Equal(t, hqc.Timeout.HighQc.GetRound(), recorded.Timeout.GetHqcRound(), "the HighQC it was signed with")
	require.NotNil(t, recorded.LastTC, "and the last TC")
	pt, err := recorded.Preimage(r.cfg)
	require.NoError(t, err)
	ver, err := r.signer.Verifier()
	require.NoError(t, err)
	require.NoError(t, ver.VerifyBytes(recorded.Signature, pt))
	require.EqualValues(t, 8, db2.GetHighestVotedRound(), "reading it back fences the round as the signing did")

	none, err := restarted.RecordedTimeout(1, 9)
	require.NoError(t, err)
	require.Nil(t, none, "no recorded timeout for another round")
}

func TestDomainBoundTimeoutStillObeysTheTimeoutRules(t *testing.T) {
	r := newDecisionRig(t)
	m, db := r.open(r.signer, r.scheme2())
	// the vote of round 5 raises the highest QC round to 4
	_, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
	require.NoError(t, err)
	// a timeout of round 7 carrying a QC of round 3 ignores it
	old := &drctypes.QuorumCert{VoteInfo: &drctypes.RoundInfo{Version: 1, RoundNumber: 3, Epoch: 1, ParentRoundNumber: 2, Timestamp: 99, CurrentRootHash: hash32(3)},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, PreviousHash: hash32(3)}}
	tc := &drctypes.TimeoutCert{Timeout: &drctypes.Timeout{Epoch: 1, Round: 6, HighQc: old}}
	msg := abdrc.NewTimeoutMsg(&drctypes.Timeout{Epoch: 1, Round: 7, HighQc: old}, "node1", tc)
	err = m.SignTimeout(msg, tc)
	require.ErrorIs(t, err, ErrNotSafeToTimeout)
	require.ErrorIs(t, err, ErrHighQcRoundTooLow)
	d, err := db.Decision(storage.DecisionTimeout, 1, 7)
	require.NoError(t, err)
	require.Nil(t, d, "a refused timeout is not recorded")
}

func TestSafetyModuleKeepsTheLegacyFormWhereTheEpochIsLegacy(t *testing.T) {
	r := newDecisionRig(t)
	m, db := r.open(r.signer, fixedSigning{cfg: votesig.Config{Scheme: votesig.SchemeLegacy, Network: r.cfg.Network}})
	info := NewDummyVoteInfo(4, hash32(1))
	info.Epoch = 1
	qc, err := newQuorumCertificate(t, info, nil)
	require.NoError(t, err)
	v, err := m.MakeVote(&drctypes.BlockData{Round: 5, Epoch: 1, Qc: qc}, hash32(2), nil, nil)
	require.NoError(t, err)
	require.Zero(t, v.Scheme)
	require.Empty(t, v.SealSignature)
	d, err := db.Decision(storage.DecisionVote, 1, 5)
	require.NoError(t, err)
	require.Nil(t, d, "the legacy path records no decision")
}

func TestDomainBoundSigningFailsClosed(t *testing.T) {
	r := newDecisionRig(t)
	t.Run("storage that cannot persist a decision", func(t *testing.T) {
		m := r.module(mockSafetyStorage{getHighestVotedRound: func() uint64 { return 0 },
			setHighestQcRound: func(uint64, uint64) error { return nil }}, r.signer, r.scheme2())
		_, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
		require.ErrorIs(t, err, ErrNoDecisionStore)
	})
	t.Run("missing signing history", func(t *testing.T) {
		m, _ := r.open(r.signer, fixedSigning{err: errCrash})
		_, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
		require.ErrorIs(t, err, errCrash)
	})
	t.Run("missing signing history for a timeout", func(t *testing.T) {
		m, _ := r.open(r.signer, fixedSigning{err: errCrash})
		_, hqc := r.nonCommittingBlock(8)
		msg := abdrc.NewTimeoutMsg(&drctypes.Timeout{Epoch: 1, Round: 8, HighQc: hqc.Timeout.HighQc}, "node1", hqc)
		require.ErrorIs(t, m.SignTimeout(msg, hqc), errCrash)
		require.Empty(t, msg.Signature)
	})
	t.Run("an executed state hash that is not 32 bytes", func(t *testing.T) {
		m, _ := r.open(r.signer, r.scheme2())
		_, err := m.MakeVote(r.committingBlock(5), []byte{1, 2, 3}, nil, nil)
		require.ErrorIs(t, err, votesig.ErrStatement)
	})
}

// In default startup the safety module receives the frontier proxy, not the database: the proxy must carry the decision
// store through, and a refused second statement is a refusal, not a storage fault that disables the sampler.
func TestDomainBoundDecisionsThroughTheFrontierProxy(t *testing.T) {
	r := newDecisionRig(t)
	_, db := r.open(r.signer, r.scheme2())
	sampler := &frontierSampler{}
	sampler.eligible.Store(true)
	proxy := &frontierPersistentStore{PersistentStore: db, sampler: sampler, reader: db}
	m := r.module(proxy, r.signer, r.scheme2())

	_, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
	require.NoError(t, err)
	stored, err := db.Decision(storage.DecisionVote, 1, 5)
	require.NoError(t, err)
	require.NotNil(t, stored, "the decision reached the real store")

	_, err = m.MakeVote(r.committingBlock(5), hash32(2), nil, nil)
	require.ErrorIs(t, err, storage.ErrDecisionConflict)
	require.True(t, sampler.eligible.Load() && !sampler.faulted.Load(), "a refused statement is not a storage fault")
	// the proxy itself, asked for a conflicting statement directly, refuses without latching a fault
	require.ErrorIs(t, proxy.RecordSignedDecision(storage.DecisionVote, 1, 5, []byte{1}, []byte{2}), storage.ErrDecisionConflict)
	require.True(t, sampler.eligible.Load() && !sampler.faulted.Load())

	// a real storage failure does latch the fault
	r.closeDB()
	require.ErrorIs(t, proxy.RecordSignedDecision(storage.DecisionVote, 1, 9, []byte{1}, []byte{2}), bbolt.ErrDatabaseNotOpen)
	require.True(t, sampler.faulted.Load())
}

// In an epoch that signs legacy (every epoch in production today) the recorded-timeout lookup does not touch the decision store.
func TestRecordedTimeoutIsInertInALegacyEpoch(t *testing.T) {
	r := newDecisionRig(t)
	m := r.module(mockSafetyStorage{getHighestVotedRound: func() uint64 { return 0 }}, r.signer,
		fixedSigning{cfg: votesig.Config{Scheme: votesig.SchemeLegacy, Network: r.cfg.Network}})
	msg, err := m.RecordedTimeout(1, 8)
	require.NoError(t, err)
	require.Nil(t, msg)
	// the module without any signing resolver is legacy too
	bare, err := NewSafetyModule(types.NetworkID(r.cfg.Network), "node1", r.signer, mockSafetyStorage{})
	require.NoError(t, err)
	msg, err = bare.RecordedTimeout(1, 8)
	require.NoError(t, err)
	require.Nil(t, msg)
}
