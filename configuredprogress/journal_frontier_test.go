package configuredprogress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
	bolt "go.etcd.io/bbolt"
)

type frontierTestBinding struct{}

func (frontierTestBinding) VerifyCertified(frontier.Record, *archive.Record) error { return nil }

type frontierTestAvailability struct{}

func (frontierTestAvailability) VerifyAvailable(string, archive.Request, [32]byte) error { return nil }

func frontierTestContext(f *fixture) (Context, archive.Context) {
	c := f.ctx
	identity := []byte("frontier crash test execution identity")
	c.ExecutionConfigV2 = sha256.Sum256(identity)
	p := c.Origin.ProofContext()
	r := c.Origin.Record()
	a := archive.Context{NetworkID: types.NetworkID(r.NetworkID), PartitionID: types.PartitionID(r.PartitionID), ShardID: c.Observation.ShardID, ShardEpoch: p.ShardEpoch, RootEpoch: p.RootEpoch, ExecutionIdentity: identity}
	copy(a.FullShardConfHash[:], c.Origin.FullShardConfHash().Bytes())
	copy(a.RegistryAddress[:], p.RegistryAddress[:])
	copy(a.RegistryCodeHash[:], p.RegistryCodeHash[:])
	copy(a.GenesisCommitment[:], p.GenesisCommitment[:])
	copy(a.EVMGenesisHash[:], p.EVMGenesisHash[:])
	return c, a
}

func frontierTestSetup(t *testing.T, path string) (*Store, Context, frontier.Policy, frontier.Coverage, JournalLimits) {
	s, _, c, policy, item, limits := frontierTestSetupWithFixture(t, path)
	return s, c, policy, item, limits
}

func frontierTestSetupWithFixture(t *testing.T, path string) (*Store, *fixture, Context, frontier.Policy, frontier.Coverage, JournalLimits) {
	t.Helper()
	f := newFixture(t, 0)
	c, subject := frontierTestContext(f)
	limits := JournalLimits{Candidates: 3, Observations: 5, Bytes: 16 << 20}
	s, err := OpenConfiguredV2(path, Settings{Retain: 3})
	require.NoError(t, err)
	_, _, err = s.Initialize(context.Background(), c)
	require.NoError(t, err)
	require.NoError(t, s.EnableJournal(context.Background(), c, limits))
	bootstrap := f.bootstrap(1, 4)
	p, _, err := s.PrepareObservation(context.Background(), c, bootstrap)
	require.NoError(t, err)
	_, _, err = s.CommitObservation(p)
	require.NoError(t, err)
	state := common.Hash{31: 7}
	header := &gethtypes.Header{ParentHash: f.c.Blocks[0].Hash, Root: state, Number: big.NewInt(1), Difficulty: new(big.Int), BaseFee: big.NewInt(1)}
	headerRaw, err := rlp.EncodeToBytes(header)
	require.NoError(t, err)
	hash := header.Hash()
	candidate := JournalCandidate{Round: 1, Number: 1, ParentNumber: 0, Hash: hash.Bytes(), StateRoot: state.Bytes(), ParentHash: f.c.Blocks[0].Hash.Bytes(), ParentState: f.c.Blocks[0].StateRoot.Bytes(), Raw: []byte{1, 2, 3}, BlockSize: 3, AuthorizingUC: bootstrap.Certificate(), AuthorizingTR: bootstrap.TechnicalRecord()}
	require.NoError(t, s.PutJournalCandidate(context.Background(), c, limits, candidate))
	first := f.observation(&types.InputRecord{Version: 1, RoundNumber: 1, Hash: state.Bytes(), BlockHash: hash.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_001}, 2, 5)
	p, _, err = s.PrepareObservation(context.Background(), c, first)
	require.NoError(t, err)
	_, _, err = s.CommitObservation(p)
	require.NoError(t, err)
	uc0, _ := types.Cbor.Marshal(bootstrap.Certificate())
	tr0, _ := types.Cbor.Marshal(bootstrap.TechnicalRecord())
	uc1, _ := types.Cbor.Marshal(first.Certificate())
	tr1, _ := types.Cbor.Marshal(first.TechnicalRecord())
	bodyRaw, _ := rlp.EncodeToBytes(&gethtypes.Body{})
	rec := &archive.Record{Header: headerRaw, Body: bodyRaw, CanonicalRootInput: []byte{1}, OriginalUC: uc0, OriginalTR: tr0, ResultingUC: uc1, ResultingTR: tr1, Companion: []byte{1}}
	q := archive.Request{Context: subject, BlockHash: [32]byte(hash)}
	req, err := archive.EncodeRequest(q)
	require.NoError(t, err)
	digest, err := archive.ManifestDigest(q, rec)
	require.NoError(t, err)
	ack := sha256.Sum256(req)
	r := frontier.Record{Sequence: 1, Round: first.Certificate().GetRootRoundNumber(), Height: 1, StateRoot: [32]byte(state), Subject: q, Acks: [2]frontier.Acknowledgment{{Replica: "first", RequestDigest: ack, ManifestDigest: digest}, {Replica: "second", RequestDigest: ack, ManifestDigest: digest}}}
	policy := frontier.Policy{Context: subject, Replicas: [2]string{"first", "second"}, Binding: frontierTestBinding{}, Availability: frontierTestAvailability{}}
	require.NoError(t, s.EnableFrontier(context.Background(), c, limits, policy))
	return s, f, c, policy, frontier.Coverage{Anchor: r, Material: rec}, limits
}

func TestRestoreAnchorPersistsOnlyCertifiedReplayBase(t *testing.T) {
	path := t.TempDir() + "/journal.db"
	s, c, policy, item, limits := frontierTestSetup(t, path)
	anchor := RestoreAnchor{Height: item.Anchor.Height, Hash: item.Anchor.Subject.BlockHash,
		StateRoot: item.Anchor.StateRoot, RootRound: item.Anchor.Round}
	wrong := anchor
	wrong.Hash[0] ^= 1
	require.ErrorIs(t, s.InstallRestoreAnchor(context.Background(), c, limits, wrong), ErrUntrusted)
	require.NoError(t, s.InstallRestoreAnchor(context.Background(), c, limits, anchor))
	image, err := s.LoadJournal(context.Background(), c, limits)
	require.NoError(t, err)
	require.Equal(t, &anchor, image.Restored)
	require.ErrorIs(t, s.InstallRestoreAnchor(context.Background(), c, limits, anchor), ErrConflict)
	require.NoError(t, s.Close())
	restarted, err := OpenConfiguredV2(path, Settings{Retain: 3})
	require.NoError(t, err)
	defer restarted.Close()
	require.NoError(t, restarted.EnableJournal(context.Background(), c, limits))
	require.NoError(t, restarted.EnableFrontier(context.Background(), c, limits, policy))
	image, err = restarted.LoadJournal(context.Background(), c, limits)
	require.NoError(t, err)
	require.Equal(t, &anchor, image.Restored)
	require.NoError(t, restarted.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		raw := bytes.Clone(b.Get(restoreAnchorKey))
		raw[len(raw)-1] ^= 1
		return b.Put(restoreAnchorKey, raw)
	}))
	_, err = restarted.LoadJournal(context.Background(), c, limits)
	require.Error(t, err, "a damaged restore marker cannot make the journal appear healthy")
}

func TestPrunedFrontierRetainsLocalAnchorAuthorization(t *testing.T) {
	s, c, _, item, limits := frontierTestSetup(t, t.TempDir()+"/journal.db")
	defer s.Close()
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		key := journalCandidateKey(item.Anchor.Subject.BlockHash[:])
		w, err := decodeCandidate(b.Get(key))
		if err != nil {
			return err
		}
		w.LocallyBuilt = true
		raw, err := encodeCandidate(w)
		if err != nil {
			return err
		}
		return b.Put(key, raw)
	}))
	require.NoError(t, s.AdvanceFrontier(context.Background(), c, limits, []frontier.Coverage{item}))
	require.NoError(t, s.PruneFrontier(context.Background(), c, limits))
	image, err := s.LoadJournal(context.Background(), c, limits)
	require.NoError(t, err, "the retained local anchor must keep its authorizing observation")
	require.Len(t, image.Candidates, 1)
	require.True(t, image.Candidates[0].Candidate.LocallyBuilt)
	require.Len(t, image.Observations, 1, "the retained local anchor keeps its authorizing certificate")
}

func TestPruneKeepsAuthorizationForFutureLocalCandidate(t *testing.T) {
	s, c, _, item, limits := frontierTestSetup(t, t.TempDir()+"/journal.db")
	defer s.Close()
	ctx := context.Background()
	require.NoError(t, s.AdvanceFrontier(ctx, c, limits, []frontier.Coverage{item}))
	var authUC types.UnicityCertificate
	var authTR certification.TechnicalRecord
	require.NoError(t, types.Cbor.Unmarshal(item.Material.ResultingUC, &authUC))
	require.NoError(t, types.Cbor.Unmarshal(item.Material.ResultingTR, &authTR))
	future := JournalCandidate{Round: 2, Number: 2, ParentNumber: 1, Hash: bytes.Repeat([]byte{7}, 32),
		StateRoot: bytes.Repeat([]byte{8}, 32), ParentHash: item.Anchor.Subject.BlockHash[:],
		ParentState: item.Anchor.StateRoot[:], Raw: []byte{2}, BlockSize: 1, LocallyBuilt: true,
		AuthorizingUC: &authUC, AuthorizingTR: &authTR}
	require.NoError(t, s.PutJournalCandidate(ctx, c, limits, future))
	require.NoError(t, s.PruneFrontier(ctx, c, limits))
	image, err := s.LoadJournal(ctx, c, limits)
	require.NoError(t, err, "the future local proposal must keep its authorizing observation")
	require.Len(t, image.Observations, 1)
	require.EqualValues(t, authUC.GetRootRoundNumber(), image.Observations[0].UC.GetRootRoundNumber())
}

func TestFrontierCrashProcess(t *testing.T) {
	if os.Getenv("FRONTIER_CRASH_CHILD") == "" {
		return
	}
	point := os.Getenv("FRONTIER_CRASH_POINT")
	s, c, _, item, limits := frontierTestSetup(t, os.Getenv("FRONTIER_CRASH_DB"))
	s.checkpoint = func(name string) error {
		if name == point {
			return syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
		return nil
	}
	require.NoError(t, s.AdvanceFrontier(context.Background(), c, limits, []frontier.Coverage{item}))
	require.NoError(t, s.PruneFrontier(context.Background(), c, limits))
	t.Fatal("named SIGKILL point was not reached")
}

func TestFrontierSIGKILLTransactionsRecoverExactAssociation(t *testing.T) {
	for _, point := range []string{"after-frontier-transaction", "mid-prune"} {
		t.Run(point, func(t *testing.T) {
			path := t.TempDir() + "/journal.db"
			cmd := exec.Command(os.Args[0], "-test.run=^TestFrontierCrashProcess$")
			cmd.Env = append(os.Environ(), "FRONTIER_CRASH_CHILD=1", "FRONTIER_CRASH_POINT="+point, "FRONTIER_CRASH_DB="+path)
			err := cmd.Run()
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit)
			require.True(t, exit.ProcessState.Sys().(syscall.WaitStatus).Signaled())
			f := newFixture(t, 0)
			c, subject := frontierTestContext(f)
			limits := JournalLimits{Candidates: 3, Observations: 5, Bytes: 16 << 20}
			s, err := OpenConfiguredV2(path, Settings{Retain: 3})
			require.NoError(t, err)
			defer s.Close()
			require.NoError(t, s.EnableJournal(context.Background(), c, limits))
			policy := frontier.Policy{Context: subject, Replicas: [2]string{"first", "second"}, Binding: frontierTestBinding{}, Availability: frontierTestAvailability{}}
			require.NoError(t, s.EnableFrontier(context.Background(), c, limits, policy))
			image, err := s.LoadJournal(context.Background(), c, limits)
			require.NoError(t, err)
			require.NotNil(t, image.Frontier)
			require.EqualValues(t, 1, image.Frontier.Anchor.Height)
			require.Len(t, image.Candidates, 1)
			require.True(t, image.Candidates[0].Certified)
			require.True(t, bytes.Equal(image.Candidates[0].Candidate.Hash, image.Frontier.Anchor.Subject.BlockHash[:]))
			require.NoError(t, s.PruneFrontier(context.Background(), c, limits))
			image, err = s.LoadJournal(context.Background(), c, limits)
			require.NoError(t, err)
			require.Len(t, image.Candidates, 1)
			require.Equal(t, image.Frontier.Anchor.Subject.BlockHash[:], image.Candidates[0].Candidate.Hash)
			require.NotEmpty(t, image.Candidates[0].Candidate.Raw)
			require.EqualValues(t, 1, image.Frontier.Floor)
		})
	}
}

func TestPruneRetainsAnchorForRepeatObservationAcrossRestart(t *testing.T) {
	path := t.TempDir() + "/journal.db"
	s, f, c, policy, item, limits := frontierTestSetupWithFixture(t, path)
	var anchorUC types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(item.Material.ResultingUC, &anchorUC))
	repeat := f.observation(anchorUC.InputRecord, 3, 6)
	p, outcome, err := s.PrepareObservation(context.Background(), c, repeat)
	require.NoError(t, err)
	require.Equal(t, ObservationRepeated, outcome)
	_, _, err = s.CommitObservation(p)
	require.NoError(t, err)
	require.NoError(t, s.AdvanceFrontier(context.Background(), c, limits, []frontier.Coverage{item}))
	require.NoError(t, s.PruneFrontier(context.Background(), c, limits))
	image, err := s.LoadJournal(context.Background(), c, limits)
	require.NoError(t, err)
	require.Len(t, image.Observations, 1)
	require.Len(t, image.Candidates, 1)
	require.NotEmpty(t, image.Candidates[0].Candidate.Raw)
	require.NoError(t, s.Close())

	s, err = OpenConfiguredV2(path, Settings{Retain: 3})
	require.NoError(t, err)
	defer s.Close()
	require.NoError(t, s.EnableJournal(context.Background(), c, limits))
	require.NoError(t, s.EnableFrontier(context.Background(), c, limits, policy))
	image, err = s.LoadJournal(context.Background(), c, limits)
	require.NoError(t, err)
	require.Len(t, image.Observations, 1)
	require.Len(t, image.Candidates, 1)

	continued := f.observation(anchorUC.InputRecord, 4, 7)
	p, outcome, err = s.PrepareObservation(context.Background(), c, continued)
	require.NoError(t, err)
	require.Equal(t, ObservationRepeated, outcome)
	_, _, err = s.CommitObservation(p)
	require.NoError(t, err)
	image, err = s.LoadJournal(context.Background(), c, limits)
	require.NoError(t, err)
	require.Len(t, image.Observations, 2)
	require.Len(t, image.Candidates, 1)
}

func TestNewFrontierAcceptsPreviouslyCoveredBodyBeforePrune(t *testing.T) {
	s, f, c, policy, first, limits := frontierTestSetupWithFixture(t, t.TempDir()+"/journal.db")
	defer s.Close()
	ctx := context.Background()
	require.NoError(t, s.AdvanceFrontier(ctx, c, limits, []frontier.Coverage{first}))
	require.NoError(t, s.PruneFrontier(ctx, c, limits))

	state := common.Hash{31: 8}
	header := &gethtypes.Header{ParentHash: common.Hash(first.Anchor.Subject.BlockHash), Root: state, Number: big.NewInt(2), Difficulty: new(big.Int), BaseFee: big.NewInt(1)}
	headerRaw, err := rlp.EncodeToBytes(header)
	require.NoError(t, err)
	hash := header.Hash()
	var firstUC types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(first.Material.ResultingUC, &firstUC))
	var firstTR certification.TechnicalRecord
	require.NoError(t, types.Cbor.Unmarshal(first.Material.ResultingTR, &firstTR))
	candidate := JournalCandidate{Round: 2, Number: 2, ParentNumber: 1, Hash: hash.Bytes(), StateRoot: state.Bytes(),
		ParentHash: first.Anchor.Subject.BlockHash[:], ParentState: first.Anchor.StateRoot[:], Raw: []byte{4, 5, 6}, BlockSize: 3,
		AuthorizingUC: &firstUC, AuthorizingTR: &firstTR}
	require.NoError(t, s.PutJournalCandidate(ctx, c, limits, candidate))
	secondObs := f.observation(&types.InputRecord{Version: 1, RoundNumber: 2, PreviousHash: first.Anchor.StateRoot[:], Hash: state.Bytes(), BlockHash: hash.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_002}, 3, 6)
	p, _, err := s.PrepareObservation(ctx, c, secondObs)
	require.NoError(t, err)
	_, _, err = s.CommitObservation(p)
	require.NoError(t, err)
	uc2, err := types.Cbor.Marshal(secondObs.Certificate())
	require.NoError(t, err)
	tr2, err := types.Cbor.Marshal(secondObs.TechnicalRecord())
	require.NoError(t, err)
	bodyRaw, err := rlp.EncodeToBytes(&gethtypes.Body{})
	require.NoError(t, err)
	rec := &archive.Record{Header: headerRaw, Body: bodyRaw, CanonicalRootInput: []byte{2}, OriginalUC: first.Material.ResultingUC,
		OriginalTR: first.Material.ResultingTR, ResultingUC: uc2, ResultingTR: tr2, Companion: []byte{1}}
	q := archive.Request{Context: policy.Context, BlockHash: [32]byte(hash)}
	req, err := archive.EncodeRequest(q)
	require.NoError(t, err)
	digest, err := archive.ManifestDigest(q, rec)
	require.NoError(t, err)
	ack := sha256.Sum256(req)
	second := frontier.Coverage{Anchor: frontier.Record{Sequence: 2, Round: 6, Height: 2, StateRoot: [32]byte(state), Subject: q,
		Acks: [2]frontier.Acknowledgment{{Replica: "first", RequestDigest: ack, ManifestDigest: digest}, {Replica: "second", RequestDigest: ack, ManifestDigest: digest}}}, Material: rec}
	require.NoError(t, s.AdvanceFrontier(ctx, c, limits, []frontier.Coverage{second}))
	image, err := s.LoadJournal(ctx, c, limits)
	require.NoError(t, err, "covered B1 remains valid after the frontier reaches B2 and before the second prune transaction")
	require.Len(t, image.Candidates, 2)
	require.EqualValues(t, 2, image.Frontier.Anchor.Height)
}

func TestFrontierCommitAndPruneGuards(t *testing.T) {
	s, c, _, item, limits := frontierTestSetup(t, t.TempDir()+"/journal.db")
	defer s.Close()
	s.checkpoint = func(name string) error {
		if name == "before-frontier-commit" {
			return errors.New("injected")
		}
		return nil
	}
	require.ErrorContains(t, s.AdvanceFrontier(context.Background(), c, limits, []frontier.Coverage{item}), "injected")
	s.checkpoint = nil
	image, err := s.LoadJournal(context.Background(), c, limits)
	require.NoError(t, err)
	require.Nil(t, image.Frontier)
	require.NoError(t, s.AdvanceFrontier(context.Background(), c, limits, []frontier.Coverage{item}))
	s.checkpoint = func(name string) error {
		if name == "mid-prune" {
			return errors.New("injected")
		}
		return nil
	}
	require.ErrorContains(t, s.PruneFrontier(context.Background(), c, limits), "injected")
	s.checkpoint = nil
	image, err = s.LoadJournal(context.Background(), c, limits)
	require.NoError(t, err)
	require.Len(t, image.Candidates, 1)
	require.EqualValues(t, 0, image.Frontier.Floor)
	require.NoError(t, s.PruneFrontier(context.Background(), c, limits))
}

func TestFrontierRestartAdmitsCertificatesWhileReplicasAreDown(t *testing.T) {
	path := t.TempDir() + "/journal.db"
	s, f, c, policy, item, limits := frontierTestSetupWithFixture(t, path)
	require.NoError(t, s.AdvanceFrontier(context.Background(), c, limits, []frontier.Coverage{item}))
	require.NoError(t, s.Close()) // crash window before the prune transaction

	s, err := OpenConfiguredV2(path, Settings{Retain: 3})
	require.NoError(t, err)
	defer s.Close()
	require.NoError(t, s.EnableJournal(context.Background(), c, limits))
	policy.Availability = rejectingAvailability{}
	require.NoError(t, s.EnableFrontier(context.Background(), c, limits, policy))
	image, err := s.LoadJournal(context.Background(), c, limits)
	require.NoError(t, err)
	require.EqualValues(t, 1, image.Frontier.Anchor.Height)
	require.ErrorIs(t, s.VerifyFrontierCopies(context.Background(), c, limits), frontier.ErrUnavailable)

	state := bytes.Repeat([]byte{9}, 32)
	hash := bytes.Repeat([]byte{10}, 32)
	o := f.observation(&types.InputRecord{Version: 1, RoundNumber: 2, PreviousHash: item.Anchor.StateRoot[:], Hash: state, BlockHash: hash, SummaryValue: []byte{}, Timestamp: 1_700_000_002}, 3, 6)
	p, _, err := s.PrepareObservation(context.Background(), c, o)
	require.NoError(t, err)
	_, _, err = s.CommitObservation(p)
	require.NoError(t, err)
	image, err = s.LoadJournal(context.Background(), c, limits)
	require.NoError(t, err)
	require.EqualValues(t, 6, image.Observations[len(image.Observations)-1].UC.GetRootRoundNumber())
}
