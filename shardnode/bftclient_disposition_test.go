package shardnode

import (
	"context"
	"crypto"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

/*
TestHandlerDisposition drives the REAL message handler, not just the classifier.

#93 asks for both, and they can disagree: ClassifyUC returning UCStale is only useful if
handleCertificationResponse then leaves the cursor alone, keeps the driver out of it, and reports at
DEBUG rather than ERROR. Every certificate here is genuinely signed and verified through the same
path production uses.
*/

// recordingDriver captures whether the round driver was reached at all.
type recordingDriver struct {
	mu    sync.Mutex
	calls []uint64 // partition rounds handed to HandleCertificate
}

func (d *recordingDriver) HandleCertificate(_ context.Context, uc *types.UnicityCertificate, _ *certification.TechnicalRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, uc.GetRoundNumber())
	return nil
}

func (d *recordingDriver) rounds() []uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]uint64(nil), d.calls...)
}

// capturingHandler keeps every record so a test can assert on level as well as message.
type capturingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}
func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(string) slog.Handler      { return h }

func (h *capturingHandler) atLevel(l slog.Level) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, r := range h.records {
		if r.Level == l {
			out = append(out, r.Message)
		}
	}
	return out
}

func (h *capturingHandler) anyMentions(substr string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if strings.Contains(strings.ToLower(r.Message), strings.ToLower(substr)) {
			return true
		}
	}
	return false
}

func TestHandlerDisposition(t *testing.T) {
	ctx := context.Background()
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb, ok := testtrustbase.NewTrustBase(t, signer).(*types.RootTrustBaseV1)
	require.True(t, ok)
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID}
	zero := make([]byte, 32)

	// technicalFor is the TechnicalRecord that accompanies a certificate for `round`. It is built
	// before the certificate because CertificationResponse.IsValid compares its hash against
	// UC.TRHash — the handler checks that before anything else, so a fixture that skips it never
	// reaches classification at all.
	technicalFor := func(round uint64) *certification.TechnicalRecord {
		return &certification.TechnicalRecord{
			Round: round + 1, Epoch: 0, Leader: "test-node", StatHash: zero, FeeHash: zero,
		}
	}

	// sign produces a genuinely signed certificate; the handler verifies it before classifying.
	sign := func(round, rootRound uint64, prev, hash, block []byte) *types.UnicityCertificate {
		t.Helper()
		ir := &types.InputRecord{
			Version: 1, RoundNumber: round, PreviousHash: prev, Hash: hash,
			BlockHash: block, SummaryValue: []byte{}, Timestamp: 1,
		}
		trHash, err := technicalFor(round).Hash()
		require.NoError(t, err)
		uc := testcertificates.CreateUnicityCertificate(t, signer, ir, pdr, rootRound, zero, trHash)
		require.NoError(t, uc.Verify(tb, crypto.SHA256, authPartitionID, types.ShardID{}, uc.ShardConfHash))
		return uc
	}

	newClient := func(held *types.UnicityCertificate) (*BFTClient, *recordingDriver, *capturingHandler) {
		drv := &recordingDriver{}
		h := &capturingHandler{}
		c := &BFTClient{
			partitionID:    authPartitionID,
			shardID:        types.ShardID{},
			nodeID:         "test-node",
			trustBaseStore: stubTrustBaseStore{tb: tb},
			driver:         drv,
			log:            slog.New(h),
		}
		c.SeedLUC(held)
		return c, drv, h
	}

	respond := func(uc *types.UnicityCertificate) *certification.CertificationResponse {
		return &certification.CertificationResponse{
			Partition: authPartitionID,
			Shard:     types.ShardID{},
			Technical: *technicalFor(uc.GetRoundNumber()),
			UC:        *uc,
		}
	}

	t.Run("a delayed certificate is ignored without touching anything", func(t *testing.T) {
		held := sign(9, 70, zero, []byte{0x02}, []byte{0xb2})
		delayed := sign(8, 67, zero, []byte{0x01}, []byte{0xb1})

		c, drv, logs := newClient(held)
		require.NoError(t, c.handleCertificationResponse(ctx, respond(delayed)),
			"the handler must not return an error for a routine stale certificate")

		// The cursor is the thing that must not move: Submit selects root nodes from it, and
		// non-equivocation is judged against it.
		require.Same(t, held, c.luc, "c.luc must neither advance nor revert")
		require.Empty(t, drv.rounds(), "the round driver must not be reached")

		require.Empty(t, logs.atLevel(slog.LevelError), "a delayed certificate is not an error")
		require.Contains(t, logs.atLevel(slog.LevelDebug), "stale UC, ignoring")
		require.False(t, logs.anyMentions("equivocat"),
			"the harness treats that word as fatal; a routine class must not produce it")
	})

	t.Run("a genuine conflict is still refused, in both arrival orders", func(t *testing.T) {
		a := sign(5, 40, zero, []byte{0x01}, []byte{0xb1})
		b := sign(5, 44, zero, []byte{0xEE}, []byte{0xEF})

		for _, tc := range []struct {
			name         string
			held, second *types.UnicityCertificate
		}{
			{"newer arrives second", a, b},
			{"older arrives second", b, a},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c, drv, logs := newClient(tc.held)
				err := c.handleCertificationResponse(ctx, respond(tc.second))
				require.ErrorIs(t, err, ErrEquivocatingUC)

				require.Same(t, tc.held, c.luc, "a rejected certificate must not become authority")
				require.Empty(t, drv.rounds())
				require.NotEmpty(t, logs.atLevel(slog.LevelError),
					"a real conflict must still be reported at ERROR with its comparison")
			})
		}
	})

	t.Run("a valid successor still advances and reaches the driver", func(t *testing.T) {
		// The control: without it, the two cases above could be passing because the handler
		// stopped doing anything at all.
		held := sign(5, 40, zero, []byte{0x01}, []byte{0xb1})
		next := sign(6, 41, []byte{0x01}, []byte{0x02}, []byte{0xb2})

		c, drv, logs := newClient(held)
		require.NoError(t, c.handleCertificationResponse(ctx, respond(next)))
		require.Equal(t, uint64(6), c.luc.GetRoundNumber(), "the cursor advances")
		require.Equal(t, []uint64{6}, drv.rounds(), "and the driver runs the round")
		require.Empty(t, logs.atLevel(slog.LevelError))
	})

	t.Run("an exact duplicate is still ignored", func(t *testing.T) {
		held := sign(5, 40, zero, []byte{0x01}, []byte{0xb1})
		c, drv, logs := newClient(held)
		require.NoError(t, c.handleCertificationResponse(ctx, respond(held)))
		require.Same(t, held, c.luc)
		require.Empty(t, drv.rounds())
		require.Contains(t, logs.atLevel(slog.LevelDebug), "duplicate UC, ignoring")
	})

	t.Run("an impossible ordering is refused and named distinctly", func(t *testing.T) {
		held := sign(5, 40, zero, []byte{0x01}, []byte{0xb1})
		impossible := sign(6, 33, []byte{0x01}, []byte{0x02}, []byte{0xb2})

		c, drv, _ := newClient(held)
		err := c.handleCertificationResponse(ctx, respond(impossible))
		require.ErrorIs(t, err, ErrImpossibleUCOrder)
		require.NotErrorIs(t, err, ErrEquivocatingUC)
		require.Same(t, held, c.luc)
		require.Empty(t, drv.rounds())
	})
}
