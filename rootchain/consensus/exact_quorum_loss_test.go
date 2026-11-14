package consensus

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/rootevidence"
)

// #982, the 128-root host runs: with exactly a quorum live every proposal, vote and timeout vote of a round has to arrive, and on a loaded host
// the production transport lost 11-30% of the sends to live roots to its per-message deadline. Nothing repaired a lost proposal or vote, and a
// lost timeout vote waited a whole local timeout: rounds then advanced only by TC, about one per three local timeouts, no proposal was handled
// for minutes, and neither the 86-live progress nor the resume after the quorum was restored certified. Here four equal roots run on the
// production libp2p transport; one stops, leaving exactly the quorum of 3, and from then on every root loses the first attempt of every
// consensus send to another root: commits must go on over the lossy links. In the second case the first attempt is delivered and still
// reported lost (a failed write does not prove non-delivery), so every receiver gets each message twice: the repeat must create no
// equivocation evidence and count no signer twice. The control loses the same attempts without the transport's retry and commits nothing.
func TestExactQuorumCommitsOverLinksThatLoseSends(t *testing.T) {
	for _, tc := range []struct {
		name string
		// deliver: the first attempt reaches the receiver and is still reported as not delivered (a write that fails after the receiver read
		// the message), so the repeat is a second copy; otherwise the first attempt is lost
		deliver, repair, commits bool
	}{
		{name: "lost attempts are retried", repair: true, commits: true},
		{name: "delivered attempts reported lost are repeated", deliver: true, repair: true, commits: true},
		{name: "control: lost attempts are not retried", repair: false, commits: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q4Slot(t)
			transport := newLiveTransport(t)
			c := newEqualLiveRate(t, 2*time.Second, phaseLockBlockRate, q3fixture.Options{}, transport.install, "H", "a", "b", "c")
			all := c.all()
			// every root keeps the votes it receives as evidence: two different signed statements of one slot would be paired
			var journals []*rootevidence.Journal
			observers := map[string]*rootevidence.Observer{}
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			for _, name := range all {
				m := c.nodes[c.idx(name)].r.manager
				journal, err := rootevidence.NewJournal(memorydb.New(), 0)
				require.NoError(t, err)
				obs := rootevidence.NewObserver(journal, m.trustBaseStore, nil, 0)
				go obs.Run(ctx)
				m.evidence = obs
				journals, observers[name] = append(journals, journal), obs
			}
			transport.up(c, all...)
			c.start(all...)
			c.warm(3, all...)

			var faulted atomic.Int64
			fault := func(protocolID string, _ peer.ID, attempt int) (bool, error) {
				switch protocolID {
				case network.ProtocolRootProposal, network.ProtocolRootVote, network.ProtocolRootTimeout:
				default:
					return true, nil
				}
				if attempt > 1 {
					return true, nil
				}
				faulted.Add(1)
				if !tc.repair {
					return false, errors.New("lossy link: first attempt lost, not reported as undelivered") // the transport does not repeat it
				}
				return tc.deliver, errors.Join(network.ErrNotDelivered, errors.New("lossy link: first attempt reported lost"))
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
				t.Logf("from committed %d to %d (round %d), %d first attempts faulted", committed, c.committedRound(live[0]), c.state(live[0]).Round, faulted.Load())
			} else {
				time.Sleep(2 * 2 * time.Second) // what was in flight lands
				committed = c.committedRound(live[0])
				time.Sleep(10 * 2 * time.Second) // ten local timeouts
				require.Equal(t, committed, c.committedRound(live[0]), "without the retry every message is lost: nothing commits")
				t.Logf("control: from committed %d to %d (round %d), %d first attempts lost", committed, c.committedRound(live[0]), c.state(live[0]).Round, faulted.Load())
			}
			for _, name := range live {
				transport.roots[c.id(name)].consensus.SetSendFault(nil)
			}
			c.stopAll()

			// A repeated message is the same statement: no slot holds two different signed statements, and no certificate counts a signer
			// twice or one that was down (with c down, any certificate needs all of H, a and b: a doubly counted vote could make one without).
			for name, obs := range observers {
				require.True(t, obs.Healthy(), "%s captured every vote", name)
			}
			collected, err := rootevidence.Collect(journals...)
			require.NoError(t, err)
			require.Zero(t, collected.Gaps)
			require.Empty(t, collected.Pairs(), "no equivocation evidence")
			if tc.commits {
				require.NotEmpty(t, collected.Slots, "votes were kept as evidence")
			}
			down := c.id("c").String()
			for _, name := range live {
				m := c.nodes[c.idx(name)].r.manager
				threshold := m.trustBase.Load().GetQuorumThreshold()
				if qc := m.blockStore.GetHighQc(); qc != nil && qc.GetRound() > committed {
					require.NotContains(t, qc.Signatures, down, "%s: the high QC of round %d", name, qc.GetRound())
					require.GreaterOrEqual(t, uint64(len(qc.Signatures)), threshold, "%s: the high QC of round %d", name, qc.GetRound())
				}
				if last := m.pacemaker.LastRoundTC(); last != nil && last.GetRound() > committed {
					require.NotContains(t, last.Signatures, down, "%s: the TC of round %d", name, last.GetRound())
					require.GreaterOrEqual(t, uint64(len(last.Signatures)), threshold, "%s: the TC of round %d", name, last.GetRound())
				}
			}
		})
	}
}
