package cmd

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// dischargeJournal is a journal whose authenticated discharge is a fixed answer, recording what the repair did to it.
type dischargeJournal struct {
	handoffRepairJournal
	discharge configuredprogress.TerminalDischarge
	err       error
	loads     int
}

func (j *dischargeJournal) LoadTerminalDischarge(context.Context, configuredprogress.Context, configuredprogress.JournalLimits) (configuredprogress.TerminalDischarge, error) {
	j.loads++
	return j.discharge, j.err
}

func TestUndischargedHandoffTerminalsKeepsEveryTerminalTheDischargeDoesNotCover(t *testing.T) {
	terminal, _ := archivedHandoffTerminalFixture(t)
	journal := &dischargeJournal{}
	pending, err := undischargedHandoffTerminals(context.Background(), journal, configuredprogress.Context{}, configuredprogress.JournalLimits{},
		[]handoffTerminalCertificate{terminal, terminal})
	require.NoError(t, err)
	require.Len(t, pending, 2, "a terminal no authenticated frontier or restore base covers is still repaired")
	require.Equal(t, 1, journal.loads, "the discharge is read once, not per terminal")
}

func handoffTerminalAt(rootEpoch, rootRound, partitionRound uint64) handoffTerminalCertificate {
	return handoffTerminalCertificate{
		uc: &types.UnicityCertificate{UnicitySeal: &types.UnicitySeal{Epoch: rootEpoch, RootChainRoundNumber: rootRound}, InputRecord: &types.InputRecord{RoundNumber: partitionRound}},
		tr: &certification.TechnicalRecord{Round: partitionRound},
	}
}

// Only a terminal at or below the authenticated position, in root position and in partition round, is dropped; the first one beyond it
// in either coordinate is kept for repair, in order.
func TestUndischargedHandoffTerminalsDropsExactlyTheCoveredOnes(t *testing.T) {
	journal := &dischargeJournal{discharge: configuredprogress.DischargedThrough(3, 40, 10)}
	covered := []handoffTerminalCertificate{handoffTerminalAt(1, 90, 4), handoffTerminalAt(3, 40, 10), handoffTerminalAt(2, 5, 1)}
	later := handoffTerminalAt(3, 41, 10)
	newerRound := handoffTerminalAt(3, 40, 11)
	laterEpoch := handoffTerminalAt(4, 1, 2)
	all := append(append([]handoffTerminalCertificate{}, covered...), later, newerRound, laterEpoch)
	pending, err := undischargedHandoffTerminals(context.Background(), journal, configuredprogress.Context{}, configuredprogress.JournalLimits{}, all)
	require.NoError(t, err)
	require.Equal(t, []handoffTerminalCertificate{later, newerRound, laterEpoch}, pending)
}

func TestUndischargedHandoffTerminalsKeepsATerminalWithoutCertificates(t *testing.T) {
	journal := &dischargeJournal{discharge: configuredprogress.DischargedThrough(9, 99, 99)}
	bare := handoffTerminalCertificate{}
	pending, err := undischargedHandoffTerminals(context.Background(), journal, configuredprogress.Context{}, configuredprogress.JournalLimits{}, []handoffTerminalCertificate{bare})
	require.NoError(t, err)
	require.Len(t, pending, 1, "an incomplete terminal is never discharged; the repair refuses it as untrusted")
}

func TestUndischargedHandoffTerminalsDoesNotReadTheJournalForNoTerminals(t *testing.T) {
	journal := &dischargeJournal{err: configuredprogress.ErrSettings}
	pending, err := undischargedHandoffTerminals(context.Background(), journal, configuredprogress.Context{}, configuredprogress.JournalLimits{}, nil)
	require.NoError(t, err)
	require.Empty(t, pending)
	require.Zero(t, journal.loads)
}

// A discharge that cannot be authenticated (for example a persisted frontier that is not enabled) refuses the repair and never falls
// back to inserting bodies unfiltered.
func TestHandoffTerminalRepairRefusesWhenTheDischargeCannotBeRead(t *testing.T) {
	terminal, record := archivedHandoffTerminalFixture(t)
	journal := &dischargeJournal{handoffRepairJournal: handoffRepairJournal{terminal: terminal.uc}, err: configuredprogress.ErrSettings}
	err := repairUndischargedHandoffTerminals(context.Background(), journal, handoffRepairArchive{record: record}, archive.Context{},
		configuredprogress.Context{}, configuredprogress.JournalLimits{}, []handoffTerminalCertificate{terminal})
	require.ErrorIs(t, err, configuredprogress.ErrSettings)
	require.False(t, journal.candidatePut, "no body is inserted when the discharge is unknown")
	require.False(t, journal.backfilled)
}

func TestHandoffTerminalRepairStillRepairsAnUncoveredMissingTerminal(t *testing.T) {
	terminal, record := archivedHandoffTerminalFixture(t)
	journal := &dischargeJournal{handoffRepairJournal: handoffRepairJournal{terminal: terminal.uc}}
	err := repairUndischargedHandoffTerminals(context.Background(), journal, handoffRepairArchive{record: record}, archive.Context{},
		configuredprogress.Context{}, configuredprogress.JournalLimits{}, []handoffTerminalCertificate{terminal})
	require.NoError(t, err)
	require.True(t, journal.candidatePut)
	require.True(t, journal.backfilled)
}

// The repair must run against the authenticated frontier and restore base, and every production site must filter: a plain restart
// repairs only after the archive setup that enables the frontier (inside the !flags.Restore block, after enableArchiveFrontier), the
// restore repairs through the same filtered function, the startup callback no longer repairs early, and the unfiltered reapply is
// reached only through the filter.
func TestTerminalRepairRunsFilteredAndAfterTheFrontierIsEnabled(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "shard_node_run.go", nil, 0)
	require.NoError(t, err)
	var filtered, unfiltered, startup, enable []*ast.CallExpr
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok {
				switch id.Name {
				case "repairUndischargedHandoffTerminals":
					filtered = append(filtered, call)
				case "reapplyHandoffTerminalCertificatesWithArchive":
					unfiltered = append(unfiltered, call)
				case "runProfile2JournalStartup":
					startup = append(startup, call)
				case "enableArchiveFrontier":
					enable = append(enable, call)
				}
			}
		}
		return true
	})
	require.Len(t, filtered, 2, "the plain restart and the restore both repair through the filter")
	require.Len(t, unfiltered, 1, "the unfiltered reapply is reached only from the filter")
	require.Len(t, startup, 1)
	require.Len(t, enable, 1, "the plain block calls enableArchiveFrontier; the restore passes it as a closure")
	last, ok := startup[0].Args[len(startup[0].Args)-1].(*ast.Ident)
	require.True(t, ok && last.Name == "nil", "the startup callback carries no repair: it would run before the frontier is enabled")

	var plain *ast.CallExpr
	ast.Inspect(file, func(n ast.Node) bool {
		if stmt, ok := n.(*ast.IfStmt); ok {
			if un, ok := stmt.Cond.(*ast.UnaryExpr); ok && un.Op == token.NOT {
				if sel, ok := un.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "Restore" {
					for _, call := range filtered {
						if stmt.Body.Pos() <= call.Pos() && call.End() <= stmt.Body.End() {
							plain = call
						}
					}
				}
			}
		}
		return true
	})
	require.NotNil(t, plain, "the plain-restart repair is inside the !flags.Restore block")
	require.True(t, enable[0].End() <= plain.Pos(), "the plain repair follows the frontier enablement")
}
