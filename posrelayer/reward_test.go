package posrelayer

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

type revertError struct{ msg string }

func (e revertError) Error() string  { return e.msg }
func (e revertError) ErrorCode() int { return 3 }

// scripted answers each simulated call by its selector.
type scripted struct {
	byMethod map[string]error
	calls    []string
}

func (s *scripted) Call(_ context.Context, _ [20]byte, data []byte) ([]byte, error) {
	for name, m := range rewards.Methods {
		if string(data[:4]) == string(m.ID) {
			s.calls = append(s.calls, name)
			return nil, s.byMethod[name]
		}
	}
	return nil, errors.New("unexpected selector")
}

// The selectors are the contracts' (`cast sig`): a drift of the ABI string would send a call that does not exist.
func TestRewardSelectorsAreTheContractsOwn(t *testing.T) {
	want := map[string]string{
		"advanceRecords": "12631591", "closeInterval": "f0deeda6", "claim": "ddd5e1b2", "fund": "b60d4288",
		"credits": "fe5ff468", "available": "48a0d754", "totalCredits": "b5bd3eb9", "nextStart": "25ce3eee", "recordCursor": "ca01c983",
	}
	require.Len(t, rewards.Methods, len(want))
	for name, id := range want {
		require.Equal(t, id, hex.EncodeToString(rewards.Methods[name].ID), name)
	}
}

func TestRewardCalldata(t *testing.T) {
	_, err := AdvanceRecordsCalldata(0)
	require.Error(t, err)
	_, err = AdvanceRecordsCalldata(MaxRecordsPerAdvance + 1)
	require.Error(t, err)
	data, err := AdvanceRecordsCalldata(2)
	require.NoError(t, err)
	require.Equal(t, rewards.Methods["advanceRecords"].ID, data[:4])
	_, err = ClaimCalldata(big.NewInt(0), [20]byte{1})
	require.Error(t, err)
	data, err = ClaimCalldata(big.NewInt(5), [20]byte{1})
	require.NoError(t, err)
	require.Equal(t, rewards.Methods["claim"].ID, data[:4])
	require.Len(t, data, 4+64)
}

func TestNextRewardStepPrefersReadingRecordsThenClosing(t *testing.T) {
	pool := [20]byte{9}
	revert := revertError{"execution reverted"}

	s := &scripted{byMethod: map[string]error{}}
	step, err := NextRewardStep(context.Background(), s, pool)
	require.NoError(t, err)
	require.Equal(t, "advance", step.Kind)
	require.Equal(t, []string{"advanceRecords"}, s.calls, "a due read is first; nothing else is simulated")

	s = &scripted{byMethod: map[string]error{"advanceRecords": revert}}
	step, err = NextRewardStep(context.Background(), s, pool)
	require.NoError(t, err)
	require.Equal(t, "close", step.Kind)

	s = &scripted{byMethod: map[string]error{"advanceRecords": revert, "closeInterval": revert}}
	step, err = NextRewardStep(context.Background(), s, pool)
	require.NoError(t, err)
	require.Equal(t, RewardStep{}, step, "idle pool")
}

func TestNextRewardStepDoesNotMistakeAnUnreachableNodeForAnIdlePool(t *testing.T) {
	down := errors.New("connection refused")
	for _, by := range []map[string]error{
		{"advanceRecords": down},
		{"advanceRecords": revertError{"execution reverted"}, "closeInterval": down},
	} {
		_, err := NextRewardStep(context.Background(), &scripted{byMethod: by}, [20]byte{9})
		require.ErrorIs(t, err, down)
	}
}
