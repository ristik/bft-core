package consensus

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQ4BSmoke(t *testing.T) {
	for name, mk := range map[string]func(*testing.T) *q4bLive{"A": newQ4BLiveA, "B": newQ4BLiveB} {
		t.Run(name, func(t *testing.T) {
			c := mk(t)
			c.start(c.all()...)
			c.warm(4, c.all()...)
			m := c.mark()
			c.requireRecovery(m, 3, c.all()...)
			c.requireChainsAgree(c.all()...)
			for k, ev := range c.trace() {
				if ev.Kind == "attempt" && k < 400 {
					if err := q4VerifyMsg(ev.Msg, c.views()); err != nil {
						t.Logf("DBG %v ep=%d r=%d %v", ev.Msg.Class, ev.Msg.Epoch, ev.Msg.Round, err)
						break
					}
				}
			}
			tr := c.finish()
			require.NoError(t, tr.Verify(c.views()))
		})
	}
}
