package rootchain

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

type weightsStub map[string]uint64

func (w weightsStub) MemberCount() int { return len(w) }
func (w weightsStub) TotalWeight() uint64 {
	var t uint64
	for _, v := range w {
		t += v
	}
	return t
}
func (w weightsStub) Threshold() uint64 { return w.TotalWeight()/2 + 1 }
func (w weightsStub) SignerWeight(id string) (uint64, error) {
	v, ok := w[id]
	if !ok {
		return 0, errUnknown
	}
	return v, nil
}

var errUnknown = bytes.ErrTooLarge // any sentinel: the helper only needs a non-nil error

// The weight of each counted request, and their sum, are what the root records beside the node ids of a collected quorum: a heavy signer alone
// reaches the EVM threshold, three light ones do not, and the line is machine-readable (the lane's checker parses it).
func TestRequestWeightEvidenceIsTheWeightOfEachCountedRequest(t *testing.T) {
	view := weightsStub{"heavy": 6, "l1": 1, "l2": 1, "l3": 1}
	req := func(id string) *certification.BlockCertificationRequest {
		return &certification.BlockCertificationRequest{NodeID: id}
	}

	ws, sum := requestWeightEvidence(view, []*certification.BlockCertificationRequest{req("heavy")})
	require.Equal(t, []uint64{6}, ws)
	require.EqualValues(t, 6, sum)
	require.GreaterOrEqual(t, sum, view.Threshold(), "the heavy signer alone")

	ws, sum = requestWeightEvidence(view, []*certification.BlockCertificationRequest{req("l1"), req("l2"), req("l3")})
	require.Equal(t, []uint64{1, 1, 1}, ws)
	require.EqualValues(t, 3, sum)
	require.Less(t, sum, view.Threshold(), "three light signers")

	ws, sum = requestWeightEvidence(view, []*certification.BlockCertificationRequest{req("heavy"), req("stranger"), req("l1")})
	require.Equal(t, []uint64{6, 0, 1}, ws, "a request that is not a member carries no weight")
	require.EqualValues(t, 7, sum)

	var out bytes.Buffer
	slog.New(slog.NewTextHandler(&out, nil)).LogAttrs(context.Background(), slog.LevelInfo, "partition 00000008 reached consensus",
		slog.Any("requestWeights", ws), slog.Uint64("matchingWeight", sum), slog.Uint64("threshold", view.Threshold()), slog.Uint64("totalWeight", view.TotalWeight()))
	require.Contains(t, out.String(), `requestWeights="[6 0 1]" matchingWeight=7 threshold=5 totalWeight=9`, "the format the lane parses")
}
