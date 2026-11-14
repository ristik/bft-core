package consensus

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network"
)

// #982, the 128-root host runs: with exactly a quorum live every proposal, vote and timeout vote of a round has to arrive, and on a loaded host
// the production transport lost 11-30% of the sends to live roots to its per-message deadline. Nothing repaired a lost proposal or vote, and a
// lost timeout vote waited a whole local timeout: rounds then advanced only by TC, about one per three local timeouts, no proposal was handled
// for minutes, and neither the 86-live progress nor the resume after the quorum was restored certified. Here four equal roots run on the
// production libp2p transport; one stops, leaving exactly the quorum of 3, and from then on every root loses the first attempt of every
// consensus send to another root: commits must go on over the lossy links. The control loses the same attempts without the transport's
// retry and commits nothing.
func TestExactQuorumCommitsOverLinksThatLoseSends(t *testing.T) {
	for _, tc := range []struct {
		name    string
		repair  bool
		commits bool
	}{
		{name: "lost attempts are retried", repair: true, commits: true},
		{name: "control: lost attempts are not retried", repair: false, commits: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q4Slot(t)
			transport := newLiveTransport(t)
			c := newEqualLiveRate(t, 2*time.Second, phaseLockBlockRate, q3fixture.Options{}, transport.install, "H", "a", "b", "c")
			all := c.all()
			transport.up(c, all...)
			c.start(all...)
			c.warm(3, all...)

			var lost atomic.Int64
			fault := func(protocolID string, _ peer.ID, attempt int) error {
				switch protocolID {
				case network.ProtocolRootProposal, network.ProtocolRootVote, network.ProtocolRootTimeout:
				default:
					return nil
				}
				if attempt > 1 {
					return nil
				}
				lost.Add(1)
				if tc.repair {
					return errors.Join(network.ErrNotDelivered, errors.New("lossy link: first attempt lost"))
				}
				return errors.New("lossy link: first attempt lost, not reported as undelivered") // the transport does not repeat it
			}
			c.stop("c") // H, a and b are exactly the quorum of 3
			live := c.except("c")
			for _, name := range live {
				transport.roots[c.id(name)].consensus.SetSendFault(fault)
			}
			committed := c.committedRound(live[0])
			progressed := func() bool { return c.committedRound(live[0]) >= committed+3 }
			if tc.commits {
				require.Eventually(t, progressed, q4bDeadline, 50*time.Millisecond, "commits go on at exactly the quorum over the lossy links")
				t.Logf("from committed %d to %d (round %d), %d first attempts lost", committed, c.committedRound(live[0]), c.state(live[0]).Round, lost.Load())
			} else {
				time.Sleep(2 * 2 * time.Second) // what was in flight lands
				committed = c.committedRound(live[0])
				time.Sleep(10 * 2 * time.Second) // ten local timeouts
				require.Equal(t, committed, c.committedRound(live[0]), "without the retry every message is lost: nothing commits")
				t.Logf("control: from committed %d to %d (round %d), %d first attempts lost", committed, c.committedRound(live[0]), c.state(live[0]).Round, lost.Load())
			}
			for _, name := range live {
				transport.roots[c.id(name)].consensus.SetSendFault(nil)
			}
		})
	}
}
