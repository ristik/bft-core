package q3install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/keyvaluedb"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/q3format"
)

var errCrash = errors.New("injected crash")

// crasher kills "the process" at its n-th event: that event and every later one fails, as if the process had died. n < 0 never crashes.
type crasher struct {
	mu     sync.Mutex
	n, at  int
	events int
}

func (c *crasher) event() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n < 0 {
		c.events++
		return nil
	}
	if c.at >= c.n {
		return errCrash
	}
	c.at++
	c.events++
	return nil
}

// crashDB gives the journal a view of the shared durable db that dies at the crasher's event, and counts deletes.
type crashDB struct {
	keyvaluedb.KeyValueDB
	c       *crasher
	deletes *int
}

func (d crashDB) Write(k []byte, v any) error {
	if err := d.c.event(); err != nil {
		return err
	}
	return d.KeyValueDB.Write(k, v)
}
func (d crashDB) Delete(k []byte) error { *d.deletes++; return d.KeyValueDB.Delete(k) }
func (d crashDB) StartTx() (keyvaluedb.DBTransaction, error) {
	return nil, errors.New("the journal must not use transactions it cannot name")
}

// stores is the durable state of the five participants, shared across simulated restarts.
type stores struct {
	mu       sync.Mutex
	held     map[heldKey][]byte
	installs map[Step]int
	// verifyErr, installErr force a refusal for one step.
	verifyErr, installErr map[Step]error
	db                    *memorydb.MemoryDB
	deletes               int
	order                 []Step
}

func newStores() *stores {
	return &stores{held: map[heldKey][]byte{}, installs: map[Step]int{}, verifyErr: map[Step]error{}, installErr: map[Step]error{}, db: memorydb.New()}
}

type heldKey struct {
	step  Step
	epoch uint64
}

type fakeComponent struct {
	s *stores
	c *crasher
	k Step
}

// errHoldsAnother is the fake participant's refusal to install over another activation's decisions.
var errHoldsAnother = errors.New("holds another activation")

func (f fakeComponent) Install(_ context.Context, a Activation) error {
	if err := f.c.event(); err != nil {
		return err
	}
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	f.s.order = append(f.s.order, f.k)
	if err := f.s.installErr[f.k]; err != nil {
		return err
	}
	if cur := f.s.held[heldKey{f.k, a.Claim.Epoch}]; len(cur) != 0 && !bytes.Equal(cur, a.ID[:]) {
		return fmt.Errorf("%s: %w", f.k, errHoldsAnother)
	}
	if f.k > StepRoot { // each step runs only after the previous step's marker is durable
		var v []byte
		ok, err := f.s.db.Read(key(a.Claim.Epoch, "step/"+strconv.Itoa(int(f.k)-1)), &v)
		if err != nil || !ok {
			return fmt.Errorf("%s installed before %s was recorded", f.k, f.k-1)
		}
	}
	f.s.installs[f.k]++
	f.s.held[heldKey{f.k, a.Claim.Epoch}] = bytes.Clone(a.ID[:])
	if err := f.c.event(); err != nil { // the install is durable; the process dies before the journal records it
		return err
	}
	return nil
}

func (f fakeComponent) Verify(_ context.Context, a Activation) error {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	if err := f.s.verifyErr[f.k]; err != nil {
		return err
	}
	if !bytes.Equal(f.s.held[heldKey{f.k, a.Claim.Epoch}], a.ID[:]) {
		return errors.New("store does not hold the activation")
	}
	return nil
}

func claim(epoch uint64) q3format.Claim {
	c := q3format.Claim{Epoch: epoch, Start: 100 * epoch, PriorVersion: 2}
	for i := range c.BodyID {
		c.BodyID[i], c.CommitID[i], c.PriorID[i] = byte(1+i), byte(2+i), byte(3+i)
	}
	c.BodyID[0], c.CommitID[0] = byte(epoch), byte(epoch)
	return c
}

func bundleFor(c q3format.Claim) []byte {
	return []byte(fmt.Sprintf("bundle/%d/%d/%x", c.Epoch, c.Start, c.BodyID[:4]))
}

// acceptBundle accepts exactly the canonical test bundle of the committed claim.
func acceptBundle(b []byte, c q3format.Claim) error {
	if !bytes.Equal(b, bundleFor(c)) {
		return errors.New("bundle is not the committed record's")
	}
	return nil
}

func (s *stores) open(t *testing.T, c *crasher, v BundleVerifier) (*Journal, error) {
	t.Helper()
	comps := map[Step]Component{}
	for _, k := range Steps {
		comps[k] = fakeComponent{s, c, k}
	}
	return Open(Config{DB: crashDB{s.db, c, &s.deletes}, Components: comps, Bundles: v})
}

func (s *stores) mustOpen(t *testing.T) *Journal {
	t.Helper()
	j, err := s.open(t, &crasher{n: -1}, acceptBundle)
	require.NoError(t, err)
	return j
}

func lookup(cs ...q3format.Claim) func(uint64) (q3format.Claim, bool) {
	return func(e uint64) (q3format.Claim, bool) {
		for _, c := range cs {
			if c.Epoch == e {
				return c, true
			}
		}
		return q3format.Claim{}, false
	}
}

func (s *stores) keys(t *testing.T) []string {
	t.Helper()
	it := s.db.First()
	defer it.Close()
	var out []string
	for ; it.Valid(); it.Next() {
		out = append(out, string(it.Key()))
	}
	return out
}

func (s *stores) snapshot() map[heldKey]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[heldKey]string{}
	for k, v := range s.held {
		out[k] = fmt.Sprintf("%x", v)
	}
	return out
}

func newDBWith(t *testing.T, kv map[string][]byte) *memorydb.MemoryDB {
	t.Helper()
	db := memorydb.New()
	for k, v := range kv {
		require.NoError(t, db.Write([]byte(k), v))
	}
	return db
}

func (s *stores) has(t *testing.T, k []byte) bool {
	t.Helper()
	var v []byte
	ok, err := s.db.Read(k, &v)
	require.NoError(t, err)
	return ok
}
