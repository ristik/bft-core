package shardnode

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

type epochAdmissionStub struct{ ready bool }

func (a epochAdmissionStub) Submit(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error {
	return nil
}
func (a epochAdmissionStub) RootEpoch() uint64         { return 2 }
func (a epochAdmissionStub) Close() error              { return nil }
func (a epochAdmissionStub) Profile2Ready(uint64) bool { return a.ready }

// uc builds a minimal UnicityCertificate sufficient for ClassifyUC, which
// only inspects InputRecord and UnicitySeal.RootChainRoundNumber — no
// signatures, shard tree, or unicity tree needed.
func uc(round, rootRound uint64, prevHash, hash, blockHash []byte) *types.UnicityCertificate {
	return &types.UnicityCertificate{
		Version: 1,
		InputRecord: &types.InputRecord{
			Version:      1,
			RoundNumber:  round,
			PreviousHash: prevHash,
			Hash:         hash,
			BlockHash:    blockHash,
			SummaryValue: []byte{},
			Timestamp:    1000,
		},
		UnicitySeal: &types.UnicitySeal{
			Version:              1,
			RootChainRoundNumber: rootRound,
			Timestamp:            1000,
		},
	}
}

func TestClassifyUC(t *testing.T) {
	h0 := []byte{0x00}
	h1 := []byte{0x01}
	h2 := []byte{0x02}
	blk1 := []byte{0xb1}
	blk2 := []byte{0xb2}

	t.Run("first UC ever seen is valid", func(t *testing.T) {
		class, err := ClassifyUC(nil, uc(1, 10, h0, h1, blk1))
		require.NoError(t, err)
		require.Equal(t, UCValid, class)
	})

	t.Run("next round extending certified state is valid", func(t *testing.T) {
		prev := uc(1, 10, h0, h1, blk1)
		next := uc(2, 11, h1, h2, blk2)
		class, err := ClassifyUC(prev, next)
		require.NoError(t, err)
		require.Equal(t, UCValid, class)
	})

	t.Run("same root round is a duplicate", func(t *testing.T) {
		prev := uc(1, 10, h0, h1, blk1)
		dup := uc(1, 10, h0, h1, blk1)
		class, err := ClassifyUC(prev, dup)
		require.NoError(t, err)
		require.Equal(t, UCDuplicate, class)
	})

	t.Run("same input record, later root round is a repeat (timeout)", func(t *testing.T) {
		prev := uc(1, 10, h0, h1, blk1)
		repeat := uc(1, 11, h0, h1, blk1) // T2 fired, root chain re-issued the same IR
		class, err := ClassifyUC(prev, repeat)
		require.NoError(t, err)
		require.Equal(t, UCRepeat, class)
	})

	t.Run("repeat after repeat (root chain still not hearing from this shard) is still a repeat", func(t *testing.T) {
		prev := uc(1, 10, h0, h1, blk1)
		repeat1 := uc(1, 11, h0, h1, blk1)
		repeat2 := uc(1, 12, h0, h1, blk1)

		class, err := ClassifyUC(prev, repeat1)
		require.NoError(t, err)
		require.Equal(t, UCRepeat, class)

		class, err = ClassifyUC(repeat1, repeat2)
		require.NoError(t, err)
		require.Equal(t, UCRepeat, class)
	})

	t.Run("an older certificate is stale, not equivocating", func(t *testing.T) {
		// This test asserted the OPPOSITE until issue #93. A node subscribed to several root
		// nodes receives the certified sequence more than once, and retransmissions do not
		// arrive in issue order, so an authentic certificate for a round already passed is
		// routine — not a fault, and not something to report at ERROR.
		prev := uc(2, 11, h1, h2, blk2)
		older := uc(1, 10, h0, h1, blk1)
		class, err := ClassifyUC(prev, older)
		require.NoError(t, err)
		require.Equal(t, UCStale, class)
	})

	t.Run("different input record for the same round is equivocating", func(t *testing.T) {
		prev := uc(1, 10, h0, h1, blk1)
		conflicting := uc(1, 11, h0, []byte{0xEE}, []byte{0xEF})
		_, err := ClassifyUC(prev, conflicting)
		require.ErrorIs(t, err, ErrEquivocatingUC)
	})

	t.Run("next round that does not extend the certified state is equivocating", func(t *testing.T) {
		prev := uc(1, 10, h0, h1, blk1)
		disconnected := uc(2, 11, []byte{0xDE, 0xAD}, h2, blk2) // PreviousHash != prev.Hash
		_, err := ClassifyUC(prev, disconnected)
		require.ErrorIs(t, err, ErrEquivocatingUC)
	})
}

func TestClassifyUCEpochUsesEpochBeforeRootRound(t *testing.T) {
	old := uc(1, 100, []byte{0}, []byte{1}, []byte{0xb1})
	old.UnicitySeal.Epoch = 1
	next := uc(2, 1, []byte{1}, []byte{2}, []byte{0xb2})
	next.UnicitySeal.Epoch = 2
	class, err := ClassifyUCEpoch(old, next)
	require.NoError(t, err)
	require.Equal(t, UCValid, class)
	class, err = ClassifyUCEpoch(next, old)
	require.NoError(t, err)
	require.Equal(t, UCStale, class)
	other := uc(1, 1, []byte{0}, []byte{9}, []byte{0xb1})
	other.UnicitySeal.Epoch = 2
	_, err = ClassifyUCEpoch(old, other)
	require.ErrorIs(t, err, ErrEquivocatingUC)
}

func TestConfiguredClientSelectsInstalledEpochClassifier(t *testing.T) {
	old := uc(1, 100, []byte{0}, []byte{1}, []byte{0xb1})
	old.UnicitySeal.Epoch = 1
	next := uc(2, 1, []byte{1}, []byte{2}, []byte{0xb2})
	next.UnicitySeal.Epoch = 2
	client := &BFTClient{admission: epochAdmissionStub{ready: true}}
	class, err := client.classifyUC(old, next)
	require.NoError(t, err)
	require.Equal(t, UCValid, class)
	client.admission = epochAdmissionStub{ready: false}
	_, err = client.classifyUC(old, next)
	require.ErrorIs(t, err, ErrImpossibleUCOrder, "an uninstalled successor stays on the current-only path")
}

func TestClassifyUCEpochBoundaryMatrix(t *testing.T) {
	makeUC := func(epoch, round, root uint64, previous, hash byte) *types.UnicityCertificate {
		value := uc(round, root, []byte{previous}, []byte{hash}, []byte{hash})
		value.UnicitySeal.Epoch = epoch
		return value
	}
	old := makeUC(1, 5, 100, 4, 5)
	for _, tc := range []struct {
		name    string
		next    *types.UnicityCertificate
		want    UCClass
		wantErr error
	}{
		{"repeat at handoff", makeUC(2, 5, 1, 4, 5), UCRepeat, nil},
		{"stale repeat", makeUC(0, 5, 1, 4, 5), UCStale, nil},
		{"skipped epoch repeat", makeUC(3, 5, 1, 4, 5), UCValid, ErrImpossibleUCOrder},
		{"older epoch and older partition round", makeUC(0, 4, 1, 3, 4), UCStale, nil},
		{"older epoch with newer partition round", makeUC(0, 6, 1, 5, 6), UCValid, ErrImpossibleUCOrder},
		{"new epoch with older partition round", makeUC(2, 4, 1, 3, 4), UCValid, ErrImpossibleUCOrder},
		{"skipped epoch with newer partition round", makeUC(3, 6, 1, 5, 6), UCValid, ErrImpossibleUCOrder},
	} {
		t.Run(tc.name, func(t *testing.T) {
			class, err := ClassifyUCEpoch(old, tc.next)
			require.Equal(t, tc.want, class)
			if tc.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.wantErr)
			}
		})
	}
}
