package vradmit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/vrschema"
)

type vectorFile struct {
	Vectors []struct {
		Name   string          `json:"name"`
		Op     string          `json:"op"`
		Input  json.RawMessage `json:"input"`
		Expect json.RawMessage `json:"expect"`
	} `json:"vectors"`
}

func vectors(t *testing.T, file, op string) []struct {
	Name          string
	Input, Expect json.RawMessage
} {
	raw, err := os.ReadFile(filepath.Join("../testvectors/validator-registry", file))
	require.NoError(t, err)
	var f vectorFile
	require.NoError(t, json.Unmarshal(raw, &f))
	var out []struct {
		Name          string
		Input, Expect json.RawMessage
	}
	for _, v := range f.Vectors {
		if v.Op == op {
			out = append(out, struct {
				Name          string
				Input, Expect json.RawMessage
			}{v.Name, v.Input, v.Expect})
		}
	}
	require.NotEmpty(t, out, op)
	return out
}

func stateCode(t *testing.T, name string) uint8 {
	for k, v := range vrschema.OutputStateNames {
		if v == name {
			return k
		}
	}
	t.Fatalf("state %q", name)
	return 0
}

// TestRejectDueVectors runs reject.due through VerifyReject: a due vector is admitted with its reason, a not-due one refused. An
// admission failure is a predecessor other than the root's acknowledged result.
func TestRejectDueVectors(t *testing.T) {
	dep := Deployment{RootNetwork: 3, NetworkWord: vrschema.Keccak([]byte("net"))}
	r := vrschema.Keccak([]byte("R"))
	for _, v := range vectors(t, "statemachine.json", "reject.due") {
		var in struct {
			AdmissionFails bool   `json:"admissionFails"`
			ExpiresAt      uint64 `json:"expiresAt"`
			Progress       uint64 `json:"progress"`
			State          string `json:"state"`
		}
		var ex struct {
			Due    bool  `json:"due"`
			Reason uint8 `json:"reason"`
		}
		require.NoError(t, json.Unmarshal(v.Input, &in))
		require.NoError(t, json.Unmarshal(v.Expect, &ex))
		s := RejectState{Progress: in.Progress, Output: OutputState{ResultID: r, Network: dep.NetworkWord,
			Output: vrschema.OutputRecord{State: stateCode(t, in.State), ExpiresAtProgress: in.ExpiresAt, Predecessor: vrschema.GenesisResult}}}
		if in.AdmissionFails {
			s.Output.Output.Predecessor = vrschema.Keccak([]byte("not the acknowledged result"))
		}
		reason := ex.Reason
		if !ex.Due {
			reason = vrschema.RejExpired
		}
		err := VerifyReject(s, vrschema.OutputRejected{ResultID: r, Reason: reason}, dep, vrschema.GenesisResult, vrschema.Word{})
		if ex.Due {
			require.NoError(t, err, v.Name)
			for _, other := range []uint8{vrschema.RejExpired, vrschema.RejInvalidated, vrschema.RejInvalid} {
				if other != ex.Reason {
					require.ErrorIs(t, VerifyReject(s, vrschema.OutputRejected{ResultID: r, Reason: other}, dep, vrschema.GenesisResult, vrschema.Word{}), ErrReject,
						"%s: only the table's reason", v.Name)
				}
			}
		} else {
			require.ErrorIs(t, err, ErrReject, v.Name)
		}
	}
}

// TestViewReplayVectors runs view.replay through RootState.ApplyHandoffView: the committed view, its open time and the level come from
// the root state; derivability, a committed Prepare, the carrying block's count and time from committed history.
func TestViewReplayVectors(t *testing.T) {
	intent := vrschema.Keccak([]byte("intent"))
	for _, v := range vectors(t, "statemachine.json", "view.replay") {
		var in struct {
			BlockUCTime string                     `json:"blockUcTime"`
			Replay      vrschema.HandoffViewReplay `json:"replay"`
			View        uint64                     `json:"view"`
		}
		var ex struct {
			Error string `json:"error"`
			Valid bool   `json:"valid"`
		}
		require.NoError(t, json.Unmarshal(v.Input, &in))
		require.NoError(t, json.Unmarshal(v.Expect, &ex))
		block, err := strconv.ParseUint(in.BlockUCTime, 10, 64)
		require.NoError(t, err)
		rp := in.Replay
		require.True(t, rp.BackoffAgrees, "the vectors exercise the replay rule, not the bookkeeping")
		s := GenesisRootState(5, rp.N)
		s.Backoff.Level = rp.Level
		env := ViewEnv{IntentDerivable: rp.IntentDerivable, PrepareCommitted: rp.PrepareCommitted, InBlock: rp.InBlock, BlockUCTime: block}
		if rp.CommittedView > 0 {
			s.Backoff.Intent, s.Backoff.LastView, s.OpenUCTime = intent[:], rp.CommittedView, rp.OpenUCTime
		} else {
			env.AnchorUCTime = rp.OpenUCTime
		}
		next, err := s.ApplyHandoffView(intent[:], in.View, env)
		if ex.Valid {
			require.NoError(t, err, v.Name)
			require.Equal(t, in.View, next.Backoff.LastView, v.Name)
			require.Equal(t, block, next.OpenUCTime, v.Name)
		} else {
			require.EqualError(t, err, ex.Error, v.Name)
		}
	}
}

// TestBackoffTraceVectors runs backoff.trace through RootState: each committed control as its transition, then EndBlock's Open step.
func TestBackoffTraceVectors(t *testing.T) {
	for _, v := range vectors(t, "statemachine.json", "backoff.trace") {
		var in struct {
			Start vrschema.HandoffBackoff `json:"start"`
		}
		var ex struct {
			Trace []struct {
				Block vrschema.Block  `json:"block"`
				Error string          `json:"error"`
				State json.RawMessage `json:"state"`
			} `json:"trace"`
		}
		require.NoError(t, json.Unmarshal(v.Input, &in))
		require.NoError(t, json.Unmarshal(v.Expect, &ex))
		s := RootState{Backoff: in.Start}
		for i, step := range ex.Trace {
			next, err := s, error(nil)
			for _, e := range step.Block.Events {
				if next, err = next.event(e); err != nil {
					break
				}
			}
			if err == nil {
				next, err = next.EndBlock(step.Block.Epoch, step.Block.Round, step.Block.ControlAfter, step.Block.CommitteeSize)
			}
			if step.Error != "" {
				require.Error(t, err, "%s block %d", v.Name, i)
				require.Contains(t, err.Error(), step.Error, "%s block %d", v.Name, i)
				continue // a refused block changes nothing
			}
			require.NoError(t, err, "%s block %d", v.Name, i)
			got, _ := json.Marshal(next.Backoff)
			require.JSONEq(t, string(step.State), string(got), "%s block %d", v.Name, i)
			s = next
		}
	}
}

func TestRootStateEncoding(t *testing.T) {
	w := newWorld(t)
	s := GenesisRootState(5, 4)
	s.Backoff.Intent, s.Backoff.LastView, s.OpenUCTime = make([]byte, 32), 2, 1234
	s.Backoff.Intent[0] = 7
	var err error
	s.Support, err = s.Support.Add(w.commitment(w.k[0], vrschema.RuleID("a")))
	require.NoError(t, err)
	raw, err := s.Encode()
	require.NoError(t, err)
	back, err := DecodeRootState(raw)
	require.NoError(t, err)
	again, err := back.Encode()
	require.NoError(t, err)
	require.Equal(t, raw, again)
	_, err = DecodeRootState(append(raw, 0))
	require.ErrorIs(t, err, ErrRootState)
	g := GenesisRootState(5, 4)
	g.OpenUCTime = 9
	_, err = g.Encode()
	require.ErrorIs(t, err, ErrRootState, "an open time without a committed view")
}

func TestResidenceRule(t *testing.T) {
	// T(1, 0) = 20 s; the wait is ceil(20000 * 1.0001) = 20002 ms
	require.False(t, ResidenceEligible(1000, 1000+20001, 1, 0, 4))
	require.True(t, ResidenceEligible(1000, 1000+20002, 1, 0, 4))
	require.False(t, ResidenceEligible(5000, 4000, 1, 0, 4), "a clock before seen is never eligible")
	require.False(t, ResidenceEligible(0, ^uint64(0), 9, 1<<40, 1), "a never timeout is never met")
}

// TestPlannedAttemptAlignment is the VT-05a row "plannedAttempt alignment": p+24 and p+25 (lapsed, cooling down) plan nothing, p+48
// nothing, p+49 the next attempt, exactly where a fresh Prepare (PrepareMayFollowLapse) and a RejectResult become admissible.
func TestPlannedAttemptAlignment(t *testing.T) {
	const p = 100
	prepared := &evmroot.ControlState{Phase: "prepared", Attempt: 3, OrderedRound: p}
	for _, c := range []struct {
		round uint64
		ok    bool
	}{{p + 24, false}, {p + 25, false}, {p + 48, false}, {p + 49, true}} {
		k, ok, err := PlannedAttempt(prepared, c.round)
		require.NoError(t, err)
		require.Equal(t, c.ok, ok, "round p+%d", c.round-p)
		if ok {
			require.EqualValues(t, 4, k)
		}
	}
	k, ok, err := PlannedAttempt(&evmroot.ControlState{Phase: "idle"}, 1)
	require.True(t, ok && err == nil && k == 0)
	k, ok, _ = PlannedAttempt(&evmroot.ControlState{Phase: "aborted", Attempt: 7}, 1)
	require.True(t, ok && k == 8)
	_, ok, err = PlannedAttempt(&evmroot.ControlState{Phase: "aborted", Attempt: ^uint64(0)}, 1)
	require.False(t, ok)
	require.ErrorIs(t, err, vrschema.ErrHandoffApproval, "attempt exhaustion is checked, never a wrap")
	_, ok, _ = PlannedAttempt(&evmroot.ControlState{Phase: "committed", Attempt: 1}, 1)
	require.False(t, ok, "a running handoff plans nothing")
	_, ok, _ = PlannedAttempt(&evmroot.ControlState{Phase: "prepared", OrderedRound: ^uint64(0) - 10}, ^uint64(0))
	require.False(t, ok, "the cooldown comparison never overflows")
}
