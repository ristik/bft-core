package consensus

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
)

type shadowCert struct {
	Name string `cbor:"1,keyasint"`
}

func (c *certShadow) stat(msg, kind string, scheme uint64) shadowStat {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s := c.stats[shadowKey{msg: msg, kind: kind, scheme: scheme}]; s != nil {
		return *s
	}
	return shadowStat{}
}

// A repeat is classified by where the previous sighting was: the same message, the same round (another message), or an earlier round.
func TestCertShadowClassifiesRepeats(t *testing.T) {
	c := newCertShadow()
	a, b := &shadowCert{Name: "a"}, &shadowCert{Name: "b"}
	c.begin(&abdrc.TimeoutMsg{}, 1, 10)
	c.ObserveCert("QC", a, 1, 9, 1, 3, 4*time.Millisecond) // first sighting
	c.ObserveCert("QC", a, 1, 9, 1, 3, 4*time.Millisecond) // same message
	c.end()
	c.begin(&abdrc.TimeoutMsg{}, 2, 10)
	c.ObserveCert("QC", a, 1, 9, 1, 3, 4*time.Millisecond) // another message, same round
	c.end()
	c.begin(&abdrc.TimeoutMsg{}, 3, 11)
	c.ObserveCert("QC", a, 1, 9, 1, 3, 4*time.Millisecond) // a later round
	c.ObserveCert("QC", b, 1, 9, 1, 3, 4*time.Millisecond) // a different certificate
	c.ObserveCert("QC", a, 2, 9, 1, 3, 4*time.Millisecond) // same bytes, other epoch: another verification context
	c.end()
	s := c.stat("*abdrc.TimeoutMsg", "QC", 1)
	require.Equal(t, 6, s.calls)
	require.Equal(t, 1, s.intraMsg)
	require.Equal(t, 1, s.sameRound)
	require.Equal(t, 1, s.crossRound)
	require.Equal(t, 4*time.Millisecond, s.saveIntra)
	require.Equal(t, 18, s.signatures)
}

func TestCertShadowRetentionIsBounded(t *testing.T) {
	c := newCertShadow()
	c.begin(&abdrc.TimeoutMsg{}, 1, 1)
	for i := 0; i < certShadowCapacity+10; i++ {
		c.ObserveCert("QC", &shadowCert{Name: string(rune('a')) + time.Duration(i).String()}, 1, 1, 1, 1, 0)
	}
	require.Equal(t, certShadowCapacity, c.lru.Len())
	require.Equal(t, 10, c.evicted)
}

// Only successful verifications are reported, nested certificates are separate calls, and the shadow changes no result.
func TestCertShadowSeesOnlySuccessfulVerificationsAndChangesNothing(t *testing.T) {
	replicas, votes, round := realQCTimeouts(t)
	ctx := context.Background()
	rx := replicas[0]
	shadow := newCertShadow()
	rx.manager.shadow = shadow
	rx.manager.trustBaseStore.SetCertObserver(shadow)
	tc := timeoutCertOf(t, replicas, votes)
	shadow.mu.Lock()
	shadow.stats = map[shadowKey]*shadowStat{}
	shadow.mu.Unlock()

	v := votes[1]
	err := rx.manager.onTimeoutMsg(ctx, v)
	require.NoError(t, err)
	qc := shadow.stat("other", "QC", 1)
	require.GreaterOrEqual(t, qc.calls, 1, "the vote's high QC verified successfully")

	bad := recodeTimeout(t, v)
	bad.Timeout.HighQc.VoteInfo.Timestamp++
	before := shadow.stat("other", "QC", 1).calls
	require.Error(t, rx.manager.onTimeoutMsg(ctx, bad))
	require.Equal(t, before, shadow.stat("other", "QC", 1).calls, "a failed verification is never reported")

	// a vote carrying a valid later TC: the TC is one call, its own high QC another; the same QC as the vote's is a repeat within the message
	withTC := recodeTimeout(t, v)
	withTC.LastTC = tc
	shadow.begin(withTC, 77, round)
	_ = rx.manager.onTimeoutMsg(ctx, withTC)
	shadow.end()
	require.Equal(t, 1, shadow.stat("*abdrc.TimeoutMsg", "TC", 1).calls)
	q := shadow.stat("*abdrc.TimeoutMsg", "QC", 1)
	require.GreaterOrEqual(t, q.calls, 2, "the vote's QC and the TC's nested QC")
	require.GreaterOrEqual(t, q.intraMsg, 1, "the same QC verified twice within one message")
}
