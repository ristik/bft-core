package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestShardStartupRestoresHandoffLineageBeforeJournalInitialize(t *testing.T) {
	currentEpoch := uint64(1)
	var steps []string
	err := runProfile2JournalStartup(context.Background(),
		func(context.Context) error {
			steps = append(steps, "restore")
			currentEpoch = 3
			return nil
		},
		func(context.Context) error {
			steps = append(steps, "initialize")
			require.Equal(t, uint64(3), currentEpoch,
				"the startup journal replay must see the installed handoff epoch")
			return nil
		},
		func(context.Context) error { steps = append(steps, "enable"); return nil },
		func(context.Context) error { steps = append(steps, "repair"); return nil })
	require.NoError(t, err)
	require.Equal(t, []string{"restore", "initialize", "enable", "repair"}, steps,
		"shard_node_run uses this seam to order handoff restore, journal replay and terminal-certificate repair")
}

func TestProfile2RestoreCatchesUpTrustBeforeArchiveReplayAndRepairsAfterward(t *testing.T) {
	installedEpoch := uint64(1)
	restoringHandoffHistory := true
	var steps []string
	err := runProfile2ArchiveRestore(context.Background(),
		func(context.Context) error {
			require.True(t, restoringHandoffHistory)
			installedEpoch = 3
			steps = append(steps, "handoff-catch-up")
			return nil
		},
		func(context.Context) error { steps = append(steps, "archive-setup"); return nil },
		func(context.Context) error {
			require.Equal(t, uint64(3), installedEpoch, "archive replay must use the verified trust lineage")
			require.True(t, restoringHandoffHistory, "terminal observations are deferred during archive restore")
			steps = append(steps, "archive-replay")
			return nil
		},
		func(context.Context) error {
			restoringHandoffHistory = false
			steps = append(steps, "terminal-observation-repair")
			return nil
		})
	require.NoError(t, err)
	require.Equal(t, []string{"handoff-catch-up", "archive-setup", "archive-replay", "terminal-observation-repair"}, steps)
	require.False(t, restoringHandoffHistory)
}

type handoffStartupJournal struct {
	observations map[string]struct{}
}

func (j *handoffStartupJournal) BackfillJournalObservation(_ context.Context, _ configuredprogress.Context, _ configuredprogress.JournalLimits,
	uc *types.UnicityCertificate, _ *certification.TechnicalRecord) error {
	if uc == nil || uc.UnicitySeal == nil || uc.InputRecord == nil {
		return configuredprogress.ErrUntrusted
	}
	key := fmt.Sprintf("%d/%d/%d", uc.GetRootEpoch(), uc.GetRootRoundNumber(), uc.GetRoundNumber())
	j.observations[key] = struct{}{}
	return nil
}

func TestShardStartupRepairsSavedHandoffTerminalAfterCrashAndIsIdempotent(t *testing.T) {
	crash := errors.New("crash after handoff save before journal commit")
	saved := false
	journal := &handoffStartupJournal{observations: make(map[string]struct{})}
	terminal := handoffTerminalCertificate{
		uc: &types.UnicityCertificate{
			UnicitySeal: &types.UnicitySeal{Epoch: 2, RootChainRoundNumber: 41},
			InputRecord: &types.InputRecord{RoundNumber: 9},
		},
		tr: &certification.TechnicalRecord{Round: 9},
	}

	// The live follower's ordering is save bundle, then invoke OnInstalled. Inject
	// a crash at the gap before OnInstalled can commit the terminal certificate.
	firstRunOnInstalled := func() error {
		saved = true
		return crash
	}
	require.ErrorIs(t, firstRunOnInstalled(), crash)
	require.True(t, saved, "the handoff record reached disk before the injected crash")
	require.Empty(t, journal.observations)

	terminals := []handoffTerminalCertificate{}
	restore := func(context.Context) error {
		require.True(t, saved, "restart must replay the saved handoff record")
		terminals = append(terminals, terminal)
		return nil
	}
	repair := func(ctx context.Context) error {
		return reapplyHandoffTerminalCertificates(ctx, journal, configuredprogress.Context{}, configuredprogress.JournalLimits{}, terminals)
	}
	startup := func() error {
		return runProfile2JournalStartup(context.Background(), restore,
			func(context.Context) error { return nil },
			func(context.Context) error { return nil }, repair)
	}
	require.NoError(t, startup())
	require.Len(t, journal.observations, 1, "restart repairs the missing old-epoch terminal observation")
	require.NoError(t, startup(), "replaying the same saved handoff terminal must be idempotent")
	require.Len(t, journal.observations, 1)
}

type handoffRepairArchive struct {
	record *archive.Record
	err    error
}

func (a handoffRepairArchive) Get(archive.Request) (*archive.Record, error) { return a.record, a.err }

type handoffRepairJournal struct {
	candidatePut bool
	backfilled   bool
	terminal     *types.UnicityCertificate
}

func (j *handoffRepairJournal) PutHistoricalCertifiedJournalCandidate(_ context.Context, _ configuredprogress.Context, _ configuredprogress.JournalLimits,
	candidate configuredprogress.JournalCandidate, resultUC *types.UnicityCertificate, resultTR *certification.TechnicalRecord) error {
	j.candidatePut = true
	if !bytes.Equal(candidate.Hash, j.terminal.InputRecord.BlockHash) || !bytes.Equal(candidate.StateRoot, j.terminal.InputRecord.Hash) ||
		!bytes.Equal(candidate.ParentState, j.terminal.InputRecord.PreviousHash) || resultUC == nil || resultTR == nil ||
		!bytes.Equal(resultUC.InputRecord.BlockHash, j.terminal.InputRecord.BlockHash) {
		return configuredprogress.ErrConflict
	}
	return nil
}

func (j *handoffRepairJournal) BackfillJournalObservation(_ context.Context, _ configuredprogress.Context, _ configuredprogress.JournalLimits,
	uc *types.UnicityCertificate, _ *certification.TechnicalRecord) error {
	if !j.candidatePut || !bytes.Equal(uc.InputRecord.BlockHash, j.terminal.InputRecord.BlockHash) {
		return configuredprogress.ErrUnavailable
	}
	j.backfilled = true
	return nil
}

func TestHandoffTerminalRepairRecoversPrunedBodyFromArchive(t *testing.T) {
	terminal, record := archivedHandoffTerminalFixture(t)
	journal := &handoffRepairJournal{terminal: terminal.uc}
	err := reapplyHandoffTerminalCertificatesWithArchive(context.Background(), journal, journal,
		handoffRepairArchive{record: record}, archive.Context{}, configuredprogress.Context{}, configuredprogress.JournalLimits{}, []handoffTerminalCertificate{terminal})
	require.NoError(t, err)
	require.True(t, journal.candidatePut)
	require.True(t, journal.backfilled, "the recovered body lets the terminal certificate be backfilled")
}

func TestHandoffTerminalRepairRejectsTamperedArchiveBody(t *testing.T) {
	terminal, record := archivedHandoffTerminalFixture(t)
	record.Body = append(bytes.Clone(record.Body), 0xff)
	journal := &handoffRepairJournal{terminal: terminal.uc}
	err := reapplyHandoffTerminalCertificatesWithArchive(context.Background(), journal, journal,
		handoffRepairArchive{record: record}, archive.Context{}, configuredprogress.Context{}, configuredprogress.JournalLimits{}, []handoffTerminalCertificate{terminal})
	require.ErrorIs(t, err, archive.ErrInvalid)
	require.False(t, journal.backfilled)
}

func TestHandoffTerminalRepairRejectsArchiveHeaderHashMismatch(t *testing.T) {
	terminal, record := archivedHandoffTerminalFixture(t)
	var header gethtypes.Header
	require.NoError(t, rlp.DecodeBytes(record.Header, &header))
	header.Root = common.Hash{0x99}
	record.Header, _ = rlp.EncodeToBytes(&header)
	journal := &handoffRepairJournal{terminal: terminal.uc}
	err := reapplyHandoffTerminalCertificatesWithArchive(context.Background(), journal, journal,
		handoffRepairArchive{record: record}, archive.Context{}, configuredprogress.Context{}, configuredprogress.JournalLimits{}, []handoffTerminalCertificate{terminal})
	require.ErrorIs(t, err, archive.ErrInvalid)
	require.False(t, journal.backfilled)
}

func TestHandoffTerminalRepairRejectsArchiveStateRootMismatch(t *testing.T) {
	terminal, record := archivedHandoffTerminalFixture(t)
	var header gethtypes.Header
	require.NoError(t, rlp.DecodeBytes(record.Header, &header))
	header.Root = common.Hash{0x77}
	record.Header, _ = rlp.EncodeToBytes(&header)
	terminal.uc.InputRecord.BlockHash = header.Hash().Bytes()
	journal := &handoffRepairJournal{terminal: terminal.uc}
	err := reapplyHandoffTerminalCertificatesWithArchive(context.Background(), journal, journal,
		handoffRepairArchive{record: record}, archive.Context{}, configuredprogress.Context{}, configuredprogress.JournalLimits{}, []handoffTerminalCertificate{terminal})
	require.ErrorIs(t, err, configuredprogress.ErrUntrusted)
	require.False(t, journal.backfilled)
}

func TestHandoffTerminalRepairReturnsUnavailableWhenJournalAndArchiveBodyAreMissing(t *testing.T) {
	terminal, _ := archivedHandoffTerminalFixture(t)
	journal := &handoffRepairJournal{terminal: terminal.uc}
	err := reapplyHandoffTerminalCertificatesWithArchive(context.Background(), journal, journal,
		handoffRepairArchive{err: archive.ErrUnavailable}, archive.Context{}, configuredprogress.Context{}, configuredprogress.JournalLimits{}, []handoffTerminalCertificate{terminal})
	require.ErrorIs(t, err, configuredprogress.ErrUnavailable)
	require.Contains(t, err.Error(), "unavailable in both journal and archive")
}

func archivedHandoffTerminalFixture(t *testing.T) (handoffTerminalCertificate, *archive.Record) {
	t.Helper()
	const shardRound, rootRound = uint64(5), uint64(8)
	parent := common.Hash{0x11}
	state := common.Hash{0x22}
	beacon := common.Hash(evmroot.DeriveBeaconRoot(rootRound, shardRound))
	withdrawalsRoot := gethtypes.DeriveSha(gethtypes.Withdrawals{}, trie.NewStackTrie(nil))
	zero := uint64(0)
	header := &gethtypes.Header{
		ParentHash: parent, UncleHash: gethtypes.EmptyUncleHash, Root: state, TxHash: gethtypes.EmptyTxsHash,
		ReceiptHash: gethtypes.EmptyReceiptsHash, Bloom: gethtypes.Bloom{}, Difficulty: new(big.Int), Number: big.NewInt(1),
		GasLimit: 30_000_000, Time: 10, BaseFee: big.NewInt(1), WithdrawalsHash: &withdrawalsRoot,
		BlobGasUsed: &zero, ExcessBlobGas: &zero, ParentBeaconRoot: &beacon,
	}
	headerRaw, err := rlp.EncodeToBytes(header)
	require.NoError(t, err)
	bodyRaw, err := rlp.EncodeToBytes(&gethtypes.Body{Transactions: gethtypes.Transactions{}, Withdrawals: []*gethtypes.Withdrawal{}})
	require.NoError(t, err)
	companion := []byte(`{"rootInput":"0x01","witnesses":[],"provenance":"build"}`)
	originalUC := &types.UnicityCertificate{UnicitySeal: &types.UnicitySeal{Epoch: 1, RootChainRoundNumber: rootRound}}
	originalUCraw, err := types.Cbor.Marshal(originalUC)
	require.NoError(t, err)
	originalTRraw, err := types.Cbor.Marshal(&certification.TechnicalRecord{})
	require.NoError(t, err)
	blockHash := header.Hash().Bytes()
	terminalUC := &types.UnicityCertificate{UnicitySeal: &types.UnicitySeal{Epoch: 3, RootChainRoundNumber: 12},
		InputRecord: &types.InputRecord{RoundNumber: shardRound, BlockHash: blockHash, PreviousHash: common.Hash{0x33}.Bytes(), Hash: state.Bytes()}}
	terminalTR := &certification.TechnicalRecord{Round: shardRound}
	resultingUCraw, err := types.Cbor.Marshal(terminalUC)
	require.NoError(t, err)
	resultingTRraw, err := types.Cbor.Marshal(terminalTR)
	require.NoError(t, err)
	return handoffTerminalCertificate{uc: terminalUC, tr: terminalTR}, &archive.Record{
		Header: headerRaw, Body: bodyRaw, CanonicalRootInput: []byte{1}, Companion: companion, OriginalUC: originalUCraw, OriginalTR: originalTRraw,
		ResultingUC: resultingUCraw, ResultingTR: resultingTRraw,
	}
}
