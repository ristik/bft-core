package consensus

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	testobservability "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	testnetwork "github.com/unicitynetwork/bft-core/internal/testutils/network"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

// timeoutScale is one receiving root of an n-member committee (unit weights, the legacy scheme of the 128-root host runs) in a stall: it
// entered round 3 by a TC of round 2 that a quorum signed, and every other member has signed its round 3 timeout vote, which carries the
// genesis QC as its high QC and the round 2 TC as its last TC: the full-size message of a timeout storm (#982).
type timeoutScale struct {
	n, quorum int
	receiver  *ConsensusManager
	votes     []*abdrc.TimeoutMsg // round 3 votes of the other members, in member order
	wire      [][]byte            // their encodings: every delivery is a fresh decode, as from the network
}

func newTimeoutScale(t *testing.T, n int) *timeoutScale {
	t.Helper()
	nodes, infos := testutils.CreateTestNodes(t, n)
	trust, err := types.NewTrustBase(5, infos)
	require.NoError(t, err)
	signers := make(map[string]abcrypto.Signer, n)
	for _, node := range nodes {
		signers[node.PeerConf.ID.String()] = node.Signer
		require.NoError(t, trust.Sign(node.PeerConf.ID.String(), node.Signer))
	}
	quorum := int(trust.GetQuorumThreshold())
	// the genesis QC is signed by a quorum, as a high QC of a live network is
	qcSigners := make(map[string]abcrypto.Signer, quorum)
	for _, node := range nodes[:quorum] {
		qcSigners[node.PeerConf.ID.String()] = node.Signer
	}
	_, shardInfos := testutils.CreateTestNodes(t, 1)
	shardConf := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: partitionID, ShardID: shardID, PartitionTypeID: 999,
		TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 2500 * time.Millisecond, Validators: shardInfos, EpochStart: 1}
	obs := testobservability.NOPObservability()
	store, err := tbstore.NewTrustBaseStore(memorydb.New(), obs.Logger())
	require.NoError(t, err)
	require.NoError(t, store.Store(trust))
	db, orchestration := createStorage(t, shardConf, qcSigners, obs)
	params := NewConsensusParams()
	params.LocalTimeout = time.Hour // the round clock never fires during a measurement
	receiver := nodes[0]
	cm, err := NewConsensusManager(receiver.PeerConf.ID, store, orchestration, testnetwork.NewRootMockNetwork(), receiver.Signer, db, obs, WithConsensusParams(*params))
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { // the certificate batches every processed QC hands over (Run's sendCertificates is not running)
		for {
			select {
			case <-cm.ucSink:
			case <-ctx.Done():
				return
			}
		}
	}()
	cm.pacemaker.Reset(ctx, cm.blockStore.GetHighQc().GetRound(), nil, nil)
	t.Cleanup(cm.pacemaker.Stop)
	require.EqualValues(t, 2, cm.pacemaker.GetCurrentRound())

	hqc := cm.blockStore.GetHighQc()
	sign := func(node *testutils.TestNode, round uint64, lastTC *drctypes.TimeoutCert) *abdrc.TimeoutMsg {
		msg := abdrc.NewTimeoutMsg(drctypes.NewTimeout(round, trust.Epoch, hqc), node.PeerConf.ID.String(), lastTC)
		require.NoError(t, msg.Sign(node.Signer))
		return msg
	}
	// a quorum of round 2 timeouts gives the receiver its TC and round 3
	for _, node := range nodes[1 : quorum+1] {
		require.NoError(t, cm.onTimeoutMsg(ctx, sign(node, 2, nil)))
		if cm.pacemaker.GetCurrentRound() == 3 {
			break
		}
	}
	require.EqualValues(t, 3, cm.pacemaker.GetCurrentRound())
	tc := cm.pacemaker.LastRoundTC()
	require.NotNil(t, tc)
	s := &timeoutScale{n: n, quorum: quorum, receiver: cm}
	for _, node := range nodes[1:] {
		v := sign(node, 3, tc)
		raw, err := types.Cbor.Marshal(v)
		require.NoError(t, err)
		s.votes, s.wire = append(s.votes, v), append(s.wire, raw)
	}
	return s
}

func (s *timeoutScale) decode(t testing.TB, i int) *abdrc.TimeoutMsg {
	m := &abdrc.TimeoutMsg{}
	if err := types.Cbor.Unmarshal(s.wire[i], m); err != nil {
		t.Fatal(err)
	}
	return m
}

// countFirst delivers one first copy of the votes of members [from, to) of the round 3 stall.
func (s *timeoutScale) countFirst(t testing.TB, msgs []*abdrc.TimeoutMsg) {
	for _, m := range msgs {
		if err := s.receiver.onTimeoutMsg(context.Background(), m); err != nil {
			t.Fatal(err)
		}
	}
}

var timeoutScaleFlag = flag.String("timeout-scale", "", "committee sizes for TestTimeoutVoteScaling, e.g. 4,16,64,128 (or UBFT_TIMEOUT_SCALE)")

func scaleSizes(t *testing.T) []int {
	env := *timeoutScaleFlag
	if env == "" {
		env = os.Getenv("UBFT_TIMEOUT_SCALE")
	}
	if env == "" {
		return nil
	}
	var sizes []int
	for _, f := range strings.Split(env, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		require.NoError(t, err)
		sizes = append(sizes, n)
	}
	return sizes
}

// TestTimeoutVoteScaling measures the consensus loop's handling of timeout votes for committees of the sizes in UBFT_TIMEOUT_SCALE (e.g.
// "4,16,64,128"); it is skipped without it. Per member count it reports, per message: a first copy of a round's vote (verified and
// counted), a retransmission of a counted vote (the stall's steady state: every live root resends its vote every local timeout), and a
// vote of a round the receiver already left (the tail of every TC wave), and per round: the whole quorum of first copies.
func TestTimeoutVoteScaling(t *testing.T) {
	sizes := scaleSizes(t)
	if len(sizes) == 0 {
		t.Skip("set UBFT_TIMEOUT_SCALE=4,16,64,128 to measure")
	}
	for _, n := range sizes {
		s := newTimeoutScale(t, n)
		stalled := s.quorum - 2 // the receiver's own vote is missing too: the round stays open whatever is delivered
		pm := s.receiver.pacemaker

		// first copies: a fresh register for every pass over the stalled set (the verified-certificate cache is warm, as in a live round)
		first := testing.Benchmark(func(b *testing.B) {
			msgs := make([]*abdrc.TimeoutMsg, stalled)
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				pm.pendingVotes.Reset()
				for j := range msgs {
					msgs[j] = s.decode(b, j)
				}
				b.StartTimer()
				s.countFirst(b, msgs)
			}
		})
		// retransmissions of counted votes
		pm.pendingVotes.Reset()
		msgs := make([]*abdrc.TimeoutMsg, stalled)
		for j := range msgs {
			msgs[j] = s.decode(t, j)
		}
		s.countFirst(t, msgs)
		const pool = 512
		dup := testing.Benchmark(func(b *testing.B) {
			copies := make([]*abdrc.TimeoutMsg, pool)
			for j := range copies {
				copies[j] = s.decode(b, j%stalled)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if i%pool == 0 && i > 0 {
					b.StopTimer()
					for j := range copies {
						copies[j] = s.decode(b, j%stalled)
					}
					b.StartTimer()
				}
				_ = s.receiver.onTimeoutMsg(context.Background(), copies[i%pool])
			}
		})
		// a vote of round 2 arriving in round 3
		stale := testing.Benchmark(func(b *testing.B) {
			old := s.decode(b, 0)
			old.Timeout = drctypes.NewTimeout(2, old.Timeout.Epoch, old.Timeout.HighQc)
			old.LastTC = nil
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = s.receiver.onTimeoutMsg(context.Background(), old)
			}
		})
		perFirst := time.Duration(first.NsPerOp() / int64(stalled))
		t.Logf("n=%d quorum=%d msg=%dB: first copy %v/msg (%d allocs/msg), round of %d first copies %v; retransmission %v/msg (%d allocs/msg); stale %v/msg",
			n, s.quorum, len(s.wire[0]), perFirst, first.AllocsPerOp()/int64(stalled), stalled, time.Duration(first.NsPerOp()),
			time.Duration(dup.NsPerOp()), dup.AllocsPerOp(), time.Duration(stale.NsPerOp()))
		fmt.Printf("SCALE n=%d first_ns=%d dup_ns=%d stale_ns=%d first_allocs=%d dup_allocs=%d bytes=%d\n", n, int64(perFirst), dup.NsPerOp(),
			stale.NsPerOp(), first.AllocsPerOp()/int64(stalled), dup.AllocsPerOp(), len(s.wire[0]))
	}
}
