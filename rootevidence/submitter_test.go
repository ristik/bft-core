package rootevidence

import (
	"context"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

var (
	evAddr      = [20]byte{0xe1}
	custodyAddr = [20]byte{0xc1}
	rootsAddr   = [20]byte{0xa1}
	netWord     = sha256.Sum256([]byte("p85-network"))
	chainID     = big.NewInt(1337)
	assignment  = sha256.Sum256([]byte("assignment"))
	exposure    = sha256.Sum256([]byte("exposure"))
)

// pairedRecord is a slot of voter 1 in epoch 2 round 12 holding two different committing statements, as the fixture's root genesis signs them.
func pairedRecord(t *testing.T, f *fixture) *SlotRecord {
	t.Helper()
	j := newJournal(t, 0)
	for _, exec := range []byte{1, 2} {
		_, err := j.Record(f.observe(t, "1", 2, 12, true, exec))
		require.NoError(t, err)
	}
	rec, err := j.Get(Slot{"1", 2, 12})
	require.NoError(t, err)
	require.True(t, rec.Paired())
	return rec
}

func TestSubmitCalldata(t *testing.T) {
	f := newFixture(t)
	rec := pairedRecord(t, f)

	data, err := SubmitCalldata(netWord, f.cfg, rec, exposure)
	require.NoError(t, err)
	m := evidenceAbi.Methods["submitEvidence"]
	require.Equal(t, m.ID, data[:4])
	args, err := m.Inputs.Unpack(data[4:])
	require.NoError(t, err)
	h := abi.ConvertType(args[0], new(voteHeader)).(*voteHeader)
	require.Equal(t, voteHeader{Network: netWord, Domain: DomainRoot, Key: rec.Key, VotingEpoch: 2, VotingRound: 12}, *h)
	a := abi.ConvertType(args[1], new(signedVote)).(*signedVote)
	b := abi.ConvertType(args[2], new(signedVote)).(*signedVote)
	require.Equal(t, exposure, args[3])
	require.NotEqual(t, a.Exec, b.Exec, "two different statements")
	for _, v := range []*signedVote{a, b} {
		require.True(t, v.Committing)
		require.EqualValues(t, 11, v.Parent)
		require.EqualValues(t, 11, v.CommitRound)
		require.EqualValues(t, 2, v.CommitEpoch)
		require.EqualValues(t, 4242, v.CommitTimestamp)
		require.NotEmpty(t, v.Signature)
		require.NotEmpty(t, v.SealSignature, "a committing vote's seal signature travels with it")
	}
	// the original signatures, not re-made ones
	sigs := map[string]bool{string(rec.First.Signature): true, string(rec.Second.Signature): true}
	require.True(t, sigs[string(a.Signature)] && sigs[string(b.Signature)] && string(a.Signature) != string(b.Signature))

	t.Run("the call does not depend on which half came first", func(t *testing.T) {
		swapped := *rec
		first, second := rec.First, *rec.Second
		swapped.First, swapped.Second = second, &first
		again, err := SubmitCalldata(netWord, f.cfg, &swapped, exposure)
		require.NoError(t, err)
		require.Equal(t, data, again)
	})
	t.Run("a statement the contract would rebuild differently is never sent", func(t *testing.T) {
		bad := *rec
		st := *rec.Second
		st.Parent-- // the typed fields no longer give the preimage the signature was verified under
		bad.Second = &st
		_, err := SubmitCalldata(netWord, f.cfg, &bad, exposure)
		require.ErrorIs(t, err, ErrBuild)

		other := f.cfg
		other.Genesis = sha256.Sum256([]byte("another genesis"))
		_, err = SubmitCalldata(netWord, other, rec, exposure)
		require.ErrorIs(t, err, ErrBuild, "the root genesis is part of the preimage")
	})
	t.Run("seal fields the contract would rebuild differently are never sent", func(t *testing.T) {
		for name, mutate := range map[string]func(*Statement){
			"commit timestamp": func(st *Statement) { st.CommitTimestamp++ },
			"commit epoch":     func(st *Statement) { st.CommitEpoch-- },
			"seal bytes":       func(st *Statement) { st.SealBytes = append([]byte{0}, st.SealBytes...) },
		} {
			bad := *rec
			st := *rec.Second
			mutate(&st)
			bad.Second = &st
			_, err := SubmitCalldata(netWord, f.cfg, &bad, exposure)
			require.ErrorIs(t, err, ErrBuild, name)
		}
	})
	t.Run("one statement is not an offence", func(t *testing.T) {
		single := *rec
		single.Second = nil
		_, err := SubmitCalldata(netWord, f.cfg, &single, exposure)
		require.ErrorIs(t, err, ErrBuild)
	})
}

// fakeChain answers the submitter's reads from a small state and records what it sends. It encodes with the same ABIs, so a wrong selector,
// argument type or tuple shape in the submitter fails here.
type fakeChain struct {
	t        *testing.T
	f        *fixture
	rec      *SlotRecord
	seen     bool
	progress uint64
	asg      Assignment
	terms    Terms
	rootKeyH [32]byte
	epoch    uint64
	lots     []*big.Int
	cursor   uint32
	maxBatch uint32
	admitted map[[32]byte]bool
	sent     [][]byte
	sendErr  error
}

func newFakeChain(t *testing.T, f *fixture, rec *SlotRecord) *fakeChain {
	return &fakeChain{t: t, f: f, rec: rec, progress: 1000, asg: Assignment{OffsetSet: true, Offset: 900, FirstRound: 10, HKnown: true, HRound: 40, Closed: true, PClose: 5000},
		terms: Terms{EvidenceWindow: 100, SuffixEvidenceWindow: 50}, rootKeyH: ethcrypto.Keccak256Hash(rec.Key), epoch: rec.Epoch,
		lots: []*big.Int{big.NewInt(11), big.NewInt(12), big.NewInt(13), big.NewInt(14), big.NewInt(15)}, maxBatch: 2, admitted: map[[32]byte]bool{}}
}

func (c *fakeChain) offence() [32]byte {
	return ethcrypto.Keccak256Hash(c.rec.Key, []byte{byte(c.rec.Epoch), byte(c.rec.Round)})
}

func (c *fakeChain) Call(_ context.Context, to [20]byte, data []byte) ([]byte, error) {
	var a abi.ABI
	switch to {
	case evAddr:
		a = evidenceAbi
	case custodyAddr:
		a = custodyAbi
	case rootsAddr:
		a = rootsAbi
	default:
		c.t.Fatalf("call to an unknown address %x", to)
	}
	m, err := a.MethodById(data[:4])
	require.NoError(c.t, err)
	in, err := m.Inputs.Unpack(data[4:])
	require.NoError(c.t, err)
	var out []any
	switch m.Name {
	case "network":
		out = []any{netWord}
	case "rootNetwork":
		out = []any{c.f.cfg.Network}
	case "rootGenesis":
		out = []any{c.f.cfg.Genesis}
	case "custody":
		out = []any{ethcommon.Address(custodyAddr)}
	case "roots":
		out = []any{ethcommon.Address(rootsAddr)}
	case "progress":
		out = []any{c.progress}
	case "maxBatch":
		out = []any{c.maxBatch}
	case "offenceIDOf":
		out = []any{c.offence()}
	case "offenceSeen":
		out = []any{c.seen}
	case "assignments":
		epoch := c.epoch
		if in[0] != assignment {
			epoch = 99 // another assignment: not the voting epoch's
		}
		out = []any{uint8(1), [32]byte{}, epoch, uint64(0), c.asg.Offset, c.asg.FirstRound, c.asg.OffsetSet, c.asg.HKnown, c.asg.HRound, c.asg.Closed,
			c.asg.PClose, uint64(0), [32]byte{}, [32]byte{}, [32]byte{}, uint32(1)}
	case "assignmentExposures":
		out = []any{[][32]byte{exposure}}
	case "exposures":
		out = []any{assignment, uint64(7), uint64(1), uint64(1), uint64(1), c.rootKeyH, [32]byte{}, ethcommon.Address{}, false, uint32(0)}
	case "policyTerms":
		out = []any{policyTerms{BountyCap: big.NewInt(0), EvidenceWindow: c.terms.EvidenceWindow, SuffixEvidenceWindow: c.terms.SuffixEvidenceWindow}}
	case "exposureLots":
		out = []any{c.lots}
	case "caseInfo":
		v := caseView{ExposureID: exposure, Budget: big.NewInt(0), Debited: big.NewInt(0), Cursor: c.cursor, LotCount: uint32(len(c.lots))}
		if c.admitted[in[0].([32]byte)] || c.cursor > 0 {
			v.Reporter = ethcommon.Address{0xaa}
		}
		out = []any{v}
	default:
		c.t.Fatalf("unexpected read %s", m.Name)
	}
	return m.Outputs.Pack(out...)
}

type revertErr struct{ data string }

func (e revertErr) Error() string          { return "execution reverted" }
func (e revertErr) ErrorData() interface{} { return e.data }
func (e revertErr) ErrorCode() int         { return 3 }

func (c *fakeChain) Send(_ context.Context, to [20]byte, _ *big.Int, data []byte) (ethcommon.Hash, error) {
	require.Equal(c.t, evAddr, to)
	c.sent = append(c.sent, data)
	if c.sendErr != nil {
		return ethcommon.Hash{}, c.sendErr
	}
	if string(data[:4]) == string(evidenceAbi.Methods["submitEvidence"].ID) {
		caseID, err := CaseID(netWord, chainID, evAddr, c.offence())
		require.NoError(c.t, err)
		c.admitted[caseID] = true
		c.seen = true
	}
	return ethcommon.Hash{1}, nil
}

func (c *fakeChain) submitter() *Submitter {
	return &Submitter{Reader: c, Sender: c, Evidence: evAddr, ChainID: chainID, Assignments: [][32]byte{{0xde, 0xad}, assignment}}
}

func TestCaseIDMatchesTheContractFormula(t *testing.T) {
	// keccak256(abi.encode(CASE_DOMAIN, network, block.chainid, address(this), offenceID)), written out word by word
	offence := sha256.Sum256([]byte("offence"))
	want := ethcrypto.Keccak256Hash(
		ethcrypto.Keccak256([]byte("unicity.p85.case")), netWord[:], ethcommon.LeftPadBytes(chainID.Bytes(), 32), ethcommon.LeftPadBytes(evAddr[:], 32), offence[:])
	got, err := CaseID(netWord, chainID, evAddr, offence)
	require.NoError(t, err)
	require.Equal(t, [32]byte(want), got)
}

func TestSubmit(t *testing.T) {
	f := newFixture(t)
	rec := pairedRecord(t, f)

	t.Run("a genuine pair is sent once and the case exists", func(t *testing.T) {
		c := newFakeChain(t, f, rec)
		res, err := c.submitter().Submit(context.Background(), rec)
		require.NoError(t, err)
		require.Equal(t, Submitted, res.Outcome)
		require.Len(t, c.sent, 1)
		want, err := SubmitCalldata(netWord, f.cfg, rec, exposure)
		require.NoError(t, err)
		require.Equal(t, want, c.sent[0])

		// a restart asks again: the contract knows the offence, nothing more is sent
		again, err := c.submitter().Submit(context.Background(), rec)
		require.NoError(t, err)
		require.Equal(t, AlreadyAdmitted, again.Outcome)
		require.Equal(t, res.CaseID, again.CaseID)
		require.Len(t, c.sent, 1)
	})

	t.Run("an offence another reporter won is not resubmitted", func(t *testing.T) {
		c := newFakeChain(t, f, rec)
		c.seen = true
		res, err := c.submitter().Submit(context.Background(), rec)
		require.NoError(t, err)
		require.Equal(t, AlreadyAdmitted, res.Outcome)
		require.Empty(t, c.sent)
	})

	t.Run("no exposure of the key in the voting epoch: transient, nothing sent", func(t *testing.T) {
		c := newFakeChain(t, f, rec)
		c.epoch = 3
		res, err := c.submitter().Submit(context.Background(), rec)
		require.NoError(t, err)
		require.Equal(t, Unresolved, res.Outcome)
		require.Empty(t, c.sent)

		c = newFakeChain(t, f, rec)
		c.rootKeyH = [32]byte{9} // the exposure holds another key
		res, err = c.submitter().Submit(context.Background(), rec)
		require.NoError(t, err)
		require.Equal(t, Unresolved, res.Outcome)
		require.Empty(t, c.sent)
	})

	t.Run("a certified view that proves the cutoff passed is not sent", func(t *testing.T) {
		c := newFakeChain(t, f, rec)
		c.progress = 900 + 2 + 100 + 1 // offset + (round-firstRound) + window, plus one
		res, err := c.submitter().Submit(context.Background(), rec)
		require.NoError(t, err)
		require.Equal(t, TooLate, res.Outcome)
		require.Empty(t, c.sent)

		c = newFakeChain(t, f, rec)
		c.progress = 900 + 2 + 100 // the cutoff is inclusive: still sent
		res, err = c.submitter().Submit(context.Background(), rec)
		require.NoError(t, err)
		require.Equal(t, Submitted, res.Outcome)
	})

	t.Run("a revert is classified by the contract's own error", func(t *testing.T) {
		for name, want := range map[string]Outcome{
			"EvidenceLate": TooLate, "RoundBeforeEpoch": TooLate, "DuplicateOffence": AlreadyAdmitted,
			"AssignmentNotActivated": Unresolved, "ExposureUnknown": Unresolved,
			"BadSignature": Rejected, "KeyMismatch": Rejected, "IdenticalStatements": Rejected,
		} {
			c := newFakeChain(t, f, rec)
			id := evidenceAbi.Errors[name].ID
			c.sendErr = revertErr{"0x" + ethcommon.Bytes2Hex(id[:4])}
			res, err := c.submitter().Submit(context.Background(), rec)
			require.NoError(t, err, name)
			require.Equal(t, want, res.Outcome, name)
		}
		c := newFakeChain(t, f, rec)
		c.sendErr = errors.New("connection refused")
		_, err := c.submitter().Submit(context.Background(), rec)
		require.ErrorContains(t, err, "connection refused", "an unclassified failure is the caller's to retry")
	})

	t.Run("one statement is not submitted", func(t *testing.T) {
		single := *rec
		single.Second = nil
		_, err := newFakeChain(t, f, rec).submitter().Submit(context.Background(), &single)
		require.ErrorIs(t, err, ErrBuild)
	})
}

func TestSettle(t *testing.T) {
	f := newFixture(t)
	rec := pairedRecord(t, f)
	caseID := sha256.Sum256([]byte("case"))

	t.Run("ascending batches of maxBatch from the on-chain cursor", func(t *testing.T) {
		c := newFakeChain(t, f, rec)
		c.cursor = 1 // lot 11 is already settled
		n, err := c.submitter().Settle(context.Background(), caseID)
		require.NoError(t, err)
		require.Equal(t, 2, n, "lots 12-13 and 14-15")
		for i, want := range [][]*big.Int{{big.NewInt(12), big.NewInt(13)}, {big.NewInt(14), big.NewInt(15)}} {
			require.Equal(t, evidenceAbi.Methods["settleEvidence"].ID, c.sent[i][:4])
			in, err := evidenceAbi.Methods["settleEvidence"].Inputs.Unpack(c.sent[i][4:])
			require.NoError(t, err)
			require.Equal(t, caseID, in[0])
			require.Equal(t, want, in[1])
		}
	})
	t.Run("a settled case sends nothing and an unknown case is refused", func(t *testing.T) {
		c := newFakeChain(t, f, rec)
		c.cursor = 5
		n, err := c.submitter().Settle(context.Background(), caseID)
		require.NoError(t, err)
		require.Zero(t, n)

		c = newFakeChain(t, f, rec) // cursor 0 and not admitted: no reporter
		_, err = c.submitter().Settle(context.Background(), caseID)
		require.ErrorContains(t, err, "unknown case")
	})
	t.Run("an interruption resumes from the cursor", func(t *testing.T) {
		c := newFakeChain(t, f, rec)
		c.cursor = 3
		c.sendErr = errors.New("node down")
		n, err := c.submitter().Settle(context.Background(), caseID)
		require.Error(t, err)
		require.Zero(t, n)
		c.sendErr, c.sent = nil, nil
		n, err = c.submitter().Settle(context.Background(), caseID)
		require.NoError(t, err)
		require.Equal(t, 1, n, "lots 14-15")
	})
}

func TestCollectMergesHalvesOfSeparateObservers(t *testing.T) {
	f := newFixture(t)
	a, b := newJournal(t, 0), newJournal(t, 0)
	_, err := a.Record(f.observe(t, "1", 2, 12, true, 1))
	require.NoError(t, err)
	_, err = b.Record(f.observe(t, "1", 2, 12, true, 2))
	require.NoError(t, err)
	// an unrelated single statement, and the same half seen by both
	_, err = a.Record(f.observe(t, "2", 2, 13, false, 1))
	require.NoError(t, err)
	_, err = b.Record(f.observe(t, "2", 2, 13, false, 1))
	require.NoError(t, err)

	for _, one := range []*Journal{a, b} {
		c, err := Collect(one)
		require.NoError(t, err)
		require.Empty(t, c.Pairs(), "neither observer alone has a pair")
	}
	c, err := Collect(a, b)
	require.NoError(t, err)
	pairs := c.Pairs()
	require.Len(t, pairs, 1)
	require.Equal(t, Slot{"1", 2, 12}, Slot{pairs[0].Author, pairs[0].Epoch, pairs[0].Round})
	require.NotEqual(t, pairs[0].First.Digest(), pairs[0].Second.Digest())
	require.Zero(t, c.Gaps)

	// the merged pair is what the submitter sends
	_, err = SubmitCalldata(netWord, f.cfg, pairs[0], exposure)
	require.NoError(t, err)

	// a pruned range of an observer is a counted gap
	require.NoError(t, a.Delete(Slot{"2", 2, 13}))
	_ = votesig.SchemeDomainBound
	c, err = Collect(a, b)
	require.NoError(t, err)
	require.Equal(t, 1, c.Gaps)
}
