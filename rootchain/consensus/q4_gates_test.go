package consensus

import (
	"crypto"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

// Q4 #51 (C) gates that are cheap and deterministic: the leader-lookup call-site audit and the T2 boundary at the frozen test values.

// q4Site is one production call of the leader selector and the prerequisite that bounds the round it is asked for. A round the node
// chose itself (its own pacemaker round, a constant) needs no evidence. A round a message supplies must be justified by
// authenticated evidence BEFORE the lookup, because the weighted selector's cost grows with the distance to the round it is asked for.
type q4Site struct {
	Func, Arg string
	// Source of the round: local (the node's own pacemaker or a constant) or message.
	Source string
	// Prerequisite and the tests that show it; empty for local sites.
	Prerequisite string
	Evidence     []string
}

var q4LookupSites = []q4Site{
	{Func: "Run", Arg: "x.pacemaker.GetCurrentRound()", Source: "local"},
	{Func: "handlePacemakerEvent", Arg: "currentRound", Source: "local"}, // leaderAfter: the successor is overflow-checked
	{Func: "handlePacemakerEvent", Arg: "2", Source: "local"},
	{Func: "onPartitionIRChangeReq", Arg: "x.pacemaker.GetCurrentRound()", Source: "local"},
	{Func: "onIRChangeMsg", Arg: "x.pacemaker.GetCurrentRound()", Source: "local"},
	{Func: "onTimeoutMsg", Arg: "x.pacemaker.GetCurrentRound()", Source: "local"},
	{Func: "onProposalMsg", Arg: "x.pacemaker.GetCurrentRound()", Source: "local"},
	{Func: "leaderAfter", Arg: "round + 1", Source: "local"},      // reached only after the math.MaxUint64 refusal
	{Func: "processNewRoundEvent", Arg: "round", Source: "local"}, // round := x.pacemaker.GetCurrentRound() on the line above
	{Func: "onStateResponse", Arg: "x.pacemaker.GetCurrentRound()", Source: "local"},
	{Func: "onVoteMsg", Arg: "vote.VoteInfo.RoundNumber", Source: "message",
		Prerequisite: "a vote for a round ahead of the pacemaker is buffered and returns before the lookup; a stale one is refused; the author is verified under its epoch first",
		Evidence:     []string{"TestMessageRoundsAreEvidencedBeforeTheSelectorIsAsked", "TestQ4AdmissionAudit"}},
	{Func: "onProposalMsg", Arg: "proposal.Block.Round", Source: "message",
		Prerequisite: "ProposalMsg.IsValid binds the round to the carried certificate's round + 1 (abdrc.ErrRoundEvidence) before any signature check or lookup",
		Evidence:     []string{"TestMessageRoundsAreEvidencedBeforeTheSelectorIsAsked", "TestQ4AdmissionAudit"}},
}

func q4ParseCalls(t *testing.T, path string) (out []q4Site) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	require.NoError(t, err)
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok && len(c.Args) == 1 {
				if s, ok := c.Fun.(*ast.SelectorExpr); ok && (s.Sel.Name == "GetLeaderForRound" || s.Sel.Name == "leaderAfter") {
					var b strings.Builder
					require.NoError(t, printer.Fprint(&b, fset, c.Args[0]))
					out = append(out, q4Site{Func: fd.Name.Name, Arg: b.String()})
				}
			}
			return true
		})
	}
	return out
}

// TestQ4LookupCallSites is the audit of the #399 admission-order gate over the whole production tree: every call of the selector's
// GetLeaderForRound outside the selector's own package is in the table above, with the source of its round and, for a round a message
// supplies, the evidence-before-lookup prerequisite and the tests that exercise it. A new caller, or a changed argument, fails here until
// it is audited. Together with TestQ4AdmissionAudit (far-future messages reach the selector with distance 0) and the #489 evidence
// tests it is the "authenticate before the expensive lookup" gate; startup and restored-epoch installation build a selector at
// a known start and ask no distance (TestQ3ActivationRestartRebuildsTheScheduleFromAStar).
func TestQ4LookupCallSites(t *testing.T) {
	root, err := filepath.Abs("../..")
	require.NoError(t, err)
	var found []q4Site
	require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" || rel == filepath.Join("rootchain", "consensus", "leader") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(raw), "GetLeaderForRound(") {
			return err
		}
		for _, s := range q4ParseCalls(t, path) {
			s.Func = rel + ":" + s.Func
			found = append(found, s)
		}
		return nil
	}))
	var want []string
	for _, s := range q4LookupSites {
		want = append(want, "rootchain/consensus/consensus_manager.go:"+s.Func+"("+s.Arg+")")
	}
	var got []string
	for _, s := range found {
		got = append(got, s.Func+"("+s.Arg+")")
	}
	slices.Sort(want)
	slices.Sort(got)
	require.Equal(t, want, got, "every production lookup is audited; add the new call to q4LookupSites with its prerequisite and evidence")

	// every message-supplied site names evidence tests that exist in the tree
	tests := map[string]bool{}
	require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return err
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if rest, ok := strings.CutPrefix(line, "func Test"); ok {
				tests["Test"+rest[:strings.IndexAny(rest, "(")]] = true
			}
		}
		return nil
	}))
	messageSites := 0
	for _, s := range q4LookupSites {
		if s.Source == "message" {
			messageSites++
			require.NotEmpty(t, s.Prerequisite, s.Func)
			require.NotEmpty(t, s.Evidence, s.Func)
			for _, e := range s.Evidence {
				require.True(t, tests[e], "%s: evidence test %s exists", s.Func, e)
			}
		} else {
			require.Empty(t, s.Evidence, s.Func)
		}
	}
	require.Equal(t, 2, messageSites, "premise: a vote and a proposal are the only routes where a message supplies the lookup round")
}

// TestQ4T2Gate pins the T2 boundary at the frozen Q4 values. T2 is shard inactivity, not block cadence: a shard is eligible exactly at
// elapsed >= uint64(T2/(BlockRate/2)) + 1 root rounds since its last UC, one round below is not, shards with different T2 become
// eligible independently (F8 uses 2.5, 5 and 7.5 s), and the EVM test lane T2 is at least 5 s. The weights of the epoch never enter
// (TestT2TimeoutsUnderViewsAreElapsedRoundsOfTheViewsPreviousUC).
func TestQ4T2Gate(t *testing.T) {
	rounds := func(t2, blockRate time.Duration) uint64 { return uint64(t2/(blockRate/2)) + 1 }
	conf := func(id types.PartitionID, t2 time.Duration) *types.PartitionDescriptionRecord {
		return &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: id, T2Timeout: t2,
			Validators: []*types.NodeInfo{testutils.NewTestNode(t).NodeInfo(t)}}
	}
	t2s := []time.Duration{2500 * time.Millisecond, 5 * time.Second, 7500 * time.Millisecond}
	for _, blockRate := range []time.Duration{900 * time.Millisecond, time.Second} {
		configs := map[types.PartitionID]*types.PartitionDescriptionRecord{}
		var ucs []*types.UnicityCertificate
		for i, t2 := range t2s {
			id := types.PartitionID(41 + i)
			configs[id] = conf(id, t2)
			ucs = append(ucs, &types.UnicityCertificate{InputRecord: &types.InputRecord{}, UnicityTreeCertificate: &types.UnicityTreeCertificate{Partition: id},
				UnicitySeal: &types.UnicitySeal{RootChainRoundNumber: 100}})
		}
		state := &MockState{certificates: ucs, shardInfo: func(p types.PartitionID, _ types.ShardID) *storage.ShardInfo {
			si, err := storage.NewShardInfo(configs[p], crypto.SHA256)
			require.NoError(t, err)
			return si
		}}
		gen := &PartitionTimeoutGenerator{blockRate: blockRate, state: state}
		for i, t2 := range t2s {
			id := types.PartitionID(41 + i)
			n := rounds(t2, blockRate)
			for _, target := range []uint64{100 + n - 1, 100 + n} {
				got, err := gen.GetT2Timeouts(target)
				require.NoError(t, err)
				var due []types.PartitionID
				for _, g := range got {
					due = append(due, g.GetPartitionID())
				}
				eligible := target-100 >= n
				require.Equal(t, eligible, slices.Contains(due, id), "blockRate %s T2 %s target %d (threshold %d rounds): eligible=%v due=%v", blockRate, t2, target, n, eligible, due)
				// a shorter T2 is due no later; a longer one no earlier: eligibility is per shard
				for j, other := range t2s {
					oid := types.PartitionID(41 + j)
					require.Equal(t, target-100 >= rounds(other, blockRate), slices.Contains(due, oid), "%s", fmt.Sprint("independent shard ", oid, " at ", target))
				}
			}
		}
		// the EVM test lane T2 floor
		require.GreaterOrEqual(t, t2s[1], 5*time.Second)
	}
}
