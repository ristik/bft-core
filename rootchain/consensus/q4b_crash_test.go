package consensus

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

// Q4 #51 (B) crash cuts. The node dies at an exact point of one signing decision of the real manager and safety module: before it
// signs, between the paired signatures of a committing vote (PV made, the seal signature not), after every signature is made and
// before the decision is on disk, and after the decision is on disk and before the message left. Dead means the node's signer and its
// store refuse everything from that instant and it is off the network; the restart reopens the fsynced stores. A timeout has one
// signature, so the pair cut is a vote cut only. In-process close and reopen: not a SIGKILL and not a power loss.

type q4bCut struct {
	node  string
	kind  storage.DecisionKind
	point string
}

func (k q4bCut) String() string {
	return fmt.Sprintf("%s %s %s", k.node, map[storage.DecisionKind]string{storage.DecisionVote: "vote", storage.DecisionTimeout: "timeout"}[k.kind], k.point)
}

// recordedStatement is the statement a recorded decision names in the trace's terms: PV for a vote (the first element of the stored
// [PV, seal] pair), PT for a timeout.
func recordedStatement(t *testing.T, kind storage.DecisionKind, statement []byte) []byte {
	t.Helper()
	if kind == storage.DecisionTimeout {
		return statement
	}
	var pair [][]byte
	require.NoError(t, types.Cbor.Unmarshal(statement, &pair))
	require.Len(t, pair, 2)
	return pair[0]
}

func runQ4BCut(t *testing.T, k q4bCut) {
	c := newQ4BLiveA(t)
	c.start(c.all()...)
	c.warm(3, c.all()...)
	n := c.nodes[c.idx(k.node)]
	n.crash.arm(q4bCutSpec{Point: k.point, Kind: k.kind})

	// a timeout needs a round that cannot complete: a light that is not the crashing node goes away, and the rounds it leads time out
	var away []string
	if k.kind == storage.DecisionTimeout {
		victim := "b"
		if k.node == "b" {
			victim = "c"
		}
		c.stop(victim)
		away = append(away, victim)
	}
	select {
	case <-n.crash.fired:
	case <-time.After(q4bDeadline):
		require.FailNow(t, errQ4BCutMissing.Error(), k.String())
	}
	c.stop(k.node)
	t.Logf("cut fired: %s", k)

	// what the dead node had on disk
	var dec struct{ statement, message []byte }
	n.crash.mu.Lock()
	epoch, round, wantStatement, wantMessage, hadKey := n.crash.epoch, n.crash.round, n.crash.statement, n.crash.msg, n.crash.statement != nil
	n.crash.mu.Unlock()
	if hadKey {
		var err error
		dec.statement, dec.message, err = n.r.db.SignedDecision(k.kind, epoch, round)
		require.NoError(t, err)
		switch k.point {
		case cutBeforeRecord:
			require.Nil(t, dec.statement, "signed in memory, never recorded: the disk holds no decision")
		case cutBeforeSend:
			require.Equal(t, wantStatement, dec.statement, "recorded before the node died")
			require.Equal(t, wantMessage, dec.message)
		}
	} else {
		require.Contains(t, []string{cutBeforeSign, cutBetweenPair}, k.point, "only a signer cut leaves no record key")
	}

	var alive []string
	for _, name := range c.all() {
		if name != k.node && !contains(away, name) {
			alive = append(alive, name)
		}
	}
	if k.node == "H" {
		c.requireStalled(alive...) // 3 (or 2) of 9 cannot certify
	} else {
		c.requireRecovery(c.mark(), q4RecoverRound, alive...) // H plus the others stay above 7: the cluster moves on without the crashed light
	}

	m := c.mark()
	c.restart(k.node)
	for _, a := range away {
		c.restart(a)
	}
	c.requireRecovery(m, q4RecoverRound, c.all()...)
	c.requireChainsAgree(c.all()...)
	tr := c.finish()
	require.NoError(t, tr.Verify(c.views()))
	c.requireNoHonestDoubleSign(tr)
	require.Empty(t, tr.Equivocators(c.views()))

	if hadKey && k.point == cutBeforeSend {
		// the decision survived the restart, and nothing of the author for that round carries any other statement
		stmt, msg, err := c.nodes[c.idx(k.node)].r.db.SignedDecision(k.kind, epoch, round)
		require.NoError(t, err)
		require.Equal(t, wantStatement, stmt)
		require.Equal(t, wantMessage, msg)
		want := recordedStatement(t, k.kind, wantStatement)
		author := n.r.id().String()
		class := map[storage.DecisionKind]q4Class{storage.DecisionVote: q4Vote, storage.DecisionTimeout: q4Timeout}[k.kind]
		sent := 0
		for _, ev := range tr {
			if ev.Kind == "attempt" && ev.Msg.Class == class && ev.Msg.Author == author && ev.Msg.Epoch == epoch && ev.Msg.Round == round {
				require.Equal(t, want, ev.Msg.Statement, "the only statement of the author for the cut round is the recorded one")
				if bytes.Equal(ev.Msg.Raw, wantMessage) {
					sent++
				}
			}
		}
		if k.node == "H" && k.kind == storage.DecisionTimeout {
			// the cluster is stalled at this round, so the restarted heavy node must say what it recorded, byte for byte
			sum := sha256.Sum256(wantMessage)
			require.Positive(t, sent, "the recorded timeout %s was rebroadcast after the restart", hex.EncodeToString(sum[:8]))
		}
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func TestQ4BCrash(t *testing.T) {
	var cuts []q4bCut
	for _, p := range []string{cutBeforeSign, cutBetweenPair, cutBeforeRecord, cutBeforeSend} {
		cuts = append(cuts, q4bCut{"H", storage.DecisionVote, p})
	}
	for _, p := range []string{cutBeforeSign, cutBeforeRecord, cutBeforeSend} {
		cuts = append(cuts, q4bCut{"H", storage.DecisionTimeout, p})
	}
	cuts = append(cuts,
		q4bCut{"a", storage.DecisionVote, cutBeforeSign},
		q4bCut{"a", storage.DecisionVote, cutBeforeSend},
		q4bCut{"a", storage.DecisionTimeout, cutBeforeSend}, // the cluster advances its HighQC while the light is down
	)
	for _, k := range cuts {
		t.Run(k.String(), func(t *testing.T) {
			t.Parallel()
			q4Slot(t)
			runQ4BCut(t, k)
		})
	}
}
