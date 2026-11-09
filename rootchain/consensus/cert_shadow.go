package consensus

import (
	"container/list"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/unicitynetwork/bft-go-base/types"
)

// certShadowEnv switches the shadow certificate counters on (measurement runs only). Nothing is skipped or changed: the recorder only reads
// certificates whose verification already succeeded.
const certShadowEnv = "UBFT_SHADOW_CERT"

const (
	certShadowCapacity = 4096 // retention model: an LRU of this many distinct verified certificates
	certShadowInterval = 30 * time.Second
)

// certShadow counts, for every successful QC/TC verification, whether the same complete certificate (same encoding, same epoch and scheme)
// was verified before — within the same message, in the same round by another message, or in an earlier round still in the LRU — and the
// verification time such a repeat would have saved. It is a trustbase.CertObserver installed on the manager's trust base store.
type certShadow struct {
	mu       sync.Mutex
	msg      string // type of the message the consensus loop is handling ("other" outside a handler)
	seq      uint64 // ordinal of that message
	round    uint64 // the pacemaker round when the message handling began
	lru      *list.List
	index    map[string]*list.Element
	stats    map[shadowKey]*shadowStat
	overhead time.Duration
	evicted  int
	start    time.Time
}

type shadowKey struct {
	msg, kind string
	scheme    uint64
}

type shadowStat struct {
	calls, signatures                   int
	intraMsg, sameRound, crossRound     int
	verify                              time.Duration
	saveIntra, saveSameRound, saveCross time.Duration
}

type shadowEntry struct {
	key        string
	seq, round uint64
}

func newCertShadow() *certShadow {
	return &certShadow{msg: "other", lru: list.New(), index: map[string]*list.Element{}, stats: map[shadowKey]*shadowStat{}}
}

// shadowFromEnv returns a recorder when the environment asks for one, else nil.
func shadowFromEnv() *certShadow {
	if os.Getenv(certShadowEnv) == "1" {
		return newCertShadow()
	}
	return nil
}

func (c *certShadow) begin(msg any, seq, round uint64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.msg, c.seq, c.round = reflect.TypeOf(msg).String(), seq, round
	c.mu.Unlock()
}

func (c *certShadow) end() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.msg = "other"
	c.mu.Unlock()
}

// ObserveCert implements trustbase.CertObserver.
func (c *certShadow) ObserveCert(kind string, cert any, epoch, round, scheme uint64, signatures int, selfDur time.Duration) {
	began := time.Now()
	raw, err := types.Cbor.Marshal(cert)
	if err != nil {
		return // no key, no record
	}
	sum := sha256.Sum256(raw)
	key := fmt.Sprintf("%x|%d|%d", sum, epoch, scheme)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.start.IsZero() {
		c.start = began
	}
	sk := shadowKey{msg: c.msg, kind: kind, scheme: scheme}
	st := c.stats[sk]
	if st == nil {
		st = &shadowStat{}
		c.stats[sk] = st
	}
	st.calls++
	st.signatures += signatures
	st.verify += selfDur
	if el, ok := c.index[key]; ok {
		e := el.Value.(*shadowEntry)
		switch {
		case e.seq == c.seq && c.msg != "other":
			st.intraMsg++
			st.saveIntra += selfDur
		case e.round == c.round:
			st.sameRound++
			st.saveSameRound += selfDur
		default:
			st.crossRound++
			st.saveCross += selfDur
		}
		e.seq, e.round = c.seq, c.round // the latest sighting classifies the next repeat
		c.lru.MoveToFront(el)
	} else {
		c.index[key] = c.lru.PushFront(&shadowEntry{key: key, seq: c.seq, round: c.round})
		if c.lru.Len() > certShadowCapacity {
			old := c.lru.Back()
			c.lru.Remove(old)
			delete(c.index, old.Value.(*shadowEntry).key)
			c.evicted++
		}
	}
	c.overhead += time.Since(began)
}

// report logs the counters of the period and resets them (the LRU stays).
func (c *certShadow) report(log *slog.Logger, now time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.start.IsZero() || now.Sub(c.start) < certShadowInterval || len(c.stats) == 0 {
		return
	}
	wall := now.Sub(c.start)
	for k, s := range c.stats {
		log.Info("consensus shadow cert", "msg", k.msg, "kind", k.kind, "scheme", k.scheme, "calls", s.calls, "signatures", s.signatures,
			"intraMsgHits", s.intraMsg, "sameRoundHits", s.sameRound, "crossRoundHits", s.crossRound,
			"verifyMs", s.verify.Milliseconds(), "wouldSaveIntraMs", s.saveIntra.Milliseconds(),
			"wouldSaveSameRoundMs", s.saveSameRound.Milliseconds(), "wouldSaveCrossRoundMs", s.saveCross.Milliseconds(), "intervalMs", wall.Milliseconds())
	}
	log.Info("consensus shadow cert overhead", "overheadUs", c.overhead.Microseconds(), "entries", c.lru.Len(), "capacity", certShadowCapacity,
		"evicted", c.evicted, "intervalMs", wall.Milliseconds())
	c.stats, c.overhead, c.evicted, c.start = map[shadowKey]*shadowStat{}, 0, 0, now
}
