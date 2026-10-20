package rootevidence

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/keyvaluedb"
)

// Export limits: a page is clamped to them before anything is read or allocated.
const (
	MaxPageRecords = 64
	MaxPageBytes   = 256 << 10
	// DefaultBudget is the journal's local size budget (the sum of its record encodings).
	DefaultBudget = 1 << 30
)

// ErrBudget is returned when a new record would exceed the journal's budget. The journal then stops accepting new slots and reports
// incomplete coverage; it never evicts an actionable record to make room.
var ErrBudget = errors.New("rootevidence: journal budget exhausted")

// Result is what Record did with an observation.
type Result int

const (
	// Stored is the first statement of a slot.
	Stored Result = iota + 1
	// Duplicate is a statement already held (the same preimage, possibly another signature encoding).
	Duplicate
	// Paired is the first different statement of a slot: the pair now exists.
	Paired
	// AlreadyPaired is a further variant of a slot that already has its pair; it adds no new offence and is not kept.
	AlreadyPaired
)

// SlotRecord is what the journal holds for a slot: the first authenticated statement and, once one arrives, the first different one.
type SlotRecord struct {
	_        struct{} `cbor:",toarray"`
	Author   string
	Key      []byte
	Epoch    uint64
	Round    uint64
	First    Statement
	Second   *Statement
	FirstSeq uint64 // the event sequence of the first statement
	PairSeq  uint64 // the event sequence of the pair, 0 while there is none
}

// Paired reports whether the slot holds two different statements.
func (r *SlotRecord) Paired() bool { return r.Second != nil }

// Page is one bounded page of the export. NextSeq is the cursor to pass back; More says the page stopped at a limit. Gap says that the
// requested range contains events that were pruned: an empty or short page is not proof that nothing happened there. (Votes the observer
// never captured are reported by Observer.Gaps, not here.)
type Page struct {
	OldestSeq uint64
	NextSeq   uint64
	Records   []*SlotRecord
	More      bool
	Gap       bool
}

// Journal is the durable observer journal. Every accepted observation and pair transition is committed before Record returns.
type Journal struct {
	db     keyvaluedb.KeyValueDB
	budget uint64
	m      sync.Mutex
}

var (
	keySeq   = []byte("m/seq")
	keyBytes = []byte("m/bytes")
	keyFloor = []byte("m/floor") // the highest event sequence ever pruned
)

// NewJournal opens the journal on db. budget is the local size budget in bytes (0 selects DefaultBudget).
func NewJournal(db keyvaluedb.KeyValueDB, budget uint64) (*Journal, error) {
	if db == nil {
		return nil, errors.New("rootevidence: no database")
	}
	if budget == 0 {
		budget = DefaultBudget
	}
	return &Journal{db: db, budget: budget}, nil
}

func slotKey(s Slot) []byte {
	k := make([]byte, 0, 18+len(s.Author))
	k = append(k, 's', '/')
	k = binary.BigEndian.AppendUint64(k, s.Epoch)
	k = binary.BigEndian.AppendUint64(k, s.Round)
	return append(k, s.Author...)
}

func seqKey(seq uint64) []byte { return binary.BigEndian.AppendUint64([]byte("q/"), seq) }

func readCounter(tx keyvaluedb.DBTransaction, key []byte) (uint64, error) {
	var v uint64
	if _, err := tx.Read(key, &v); err != nil {
		return 0, err
	}
	return v, nil
}

// Record commits the observation. The slot's first statement, the pair, the event index and the size account are written in one transaction;
// replaying an observation is idempotent.
func (j *Journal) Record(o *Observation) (Result, error) {
	raw, err := types.Cbor.Marshal(o)
	if err != nil {
		return 0, err
	}
	if len(raw) > MaxStatementBytes {
		return 0, ErrTooLarge
	}
	j.m.Lock()
	defer j.m.Unlock()
	tx, err := j.db.StartTx()
	if err != nil {
		return 0, err
	}
	res, err := j.record(tx, o, uint64(len(raw)))
	if err != nil || res == Duplicate || res == AlreadyPaired {
		_ = tx.Rollback()
		return res, err
	}
	return res, tx.Commit()
}

func (j *Journal) record(tx keyvaluedb.DBTransaction, o *Observation, size uint64) (Result, error) {
	key := slotKey(o.Slot())
	var rec SlotRecord
	found, err := tx.Read(key, &rec)
	if err != nil {
		return 0, err
	}
	seq, err := readCounter(tx, keySeq)
	if err != nil {
		return 0, err
	}
	used, err := readCounter(tx, keyBytes)
	if err != nil {
		return 0, err
	}
	d := o.S.Digest()
	if found {
		if !bytes.Equal(rec.Key, o.Key) {
			return 0, fmt.Errorf("rootevidence: key of %s in epoch %d differs from the held one", o.Author, o.Epoch)
		}
		if d == rec.First.Digest() || (rec.Second != nil && d == rec.Second.Digest()) {
			return Duplicate, nil
		}
		if rec.Second != nil {
			return AlreadyPaired, nil
		}
	}
	if used+size > j.budget {
		return 0, ErrBudget
	}
	seq++
	if found {
		st := o.S
		rec.Second, rec.PairSeq = &st, seq
	} else {
		rec = SlotRecord{Author: o.Author, Key: o.Key, Epoch: o.Epoch, Round: o.Round, First: o.S, FirstSeq: seq}
	}
	for _, w := range []struct {
		k []byte
		v any
	}{{key, &rec}, {seqKey(seq), key}, {keySeq, seq}, {keyBytes, used + size}} {
		if err := tx.Write(w.k, w.v); err != nil {
			return 0, err
		}
	}
	if found {
		return Paired, nil
	}
	return Stored, nil
}

// Get returns the record of a slot.
func (j *Journal) Get(s Slot) (*SlotRecord, error) {
	var rec SlotRecord
	found, err := j.db.Read(slotKey(s), &rec)
	if err != nil || !found {
		return nil, err
	}
	return &rec, nil
}

// Export returns the records of the events after afterSeq, at most limit of them (clamped to MaxPageRecords) and MaxPageBytes. A slot appears
// at each of its events with its state at the time of the read; a consumer merges by slot.
func (j *Journal) Export(afterSeq uint64, limit int) (*Page, error) {
	if limit <= 0 || limit > MaxPageRecords {
		limit = MaxPageRecords
	}
	next, err := j.NextSeq()
	if err != nil {
		return nil, err
	}
	page := &Page{NextSeq: afterSeq}
	it := j.db.Find(seqKey(0))
	defer func() { _ = it.Close() }()
	first := true
	size := 0
	for ; it.Valid(); it.Next() {
		k := it.Key()
		if !bytes.HasPrefix(k, []byte("q/")) || len(k) != 10 {
			break
		}
		seq := binary.BigEndian.Uint64(k[2:])
		if first {
			page.OldestSeq, first = seq, false
		}
		if seq <= afterSeq {
			continue
		}
		if len(page.Records) >= limit {
			page.More = true
			break
		}
		var sk []byte
		if err := it.Value(&sk); err != nil {
			return nil, err
		}
		var rec SlotRecord
		if found, err := j.db.Read(sk, &rec); err != nil {
			return nil, err
		} else if !found {
			continue
		}
		raw, err := types.Cbor.Marshal(&rec)
		if err != nil {
			return nil, err
		}
		if size+len(raw) > MaxPageBytes && len(page.Records) > 0 {
			page.More = true
			break
		}
		size += len(raw)
		page.Records = append(page.Records, &rec)
		page.NextSeq = seq
	}
	if first {
		page.OldestSeq = next + 1 // nothing is held
	}
	var floor uint64
	if _, err := j.db.Read(keyFloor, &floor); err != nil {
		return nil, err
	}
	page.Gap = afterSeq < floor
	if page.Gap {
		page.NextSeq = max(page.NextSeq, page.OldestSeq-1)
	}
	if !page.More && !page.Gap {
		page.NextSeq = max(page.NextSeq, next)
	}
	return page, nil
}

// NextSeq is the highest event sequence assigned so far (monotone across restarts).
func (j *Journal) NextSeq() (uint64, error) {
	var v uint64
	if _, err := j.db.Read(keySeq, &v); err != nil {
		return 0, err
	}
	return v, nil
}

// Used is the sum of the record encodings held, the quantity the budget bounds.
func (j *Journal) Used() (uint64, error) {
	var v uint64
	if _, err := j.db.Read(keyBytes, &v); err != nil {
		return 0, err
	}
	return v, nil
}

// Delete removes a slot and its events. It is the pruning primitive: the caller (Prune) decides, from certified state, that no obligation
// needs the record any more.
func (j *Journal) Delete(s Slot) error {
	j.m.Lock()
	defer j.m.Unlock()
	tx, err := j.db.StartTx()
	if err != nil {
		return err
	}
	var rec SlotRecord
	found, err := tx.Read(slotKey(s), &rec)
	if err != nil || !found {
		_ = tx.Rollback()
		return err
	}
	used, err := readCounter(tx, keyBytes)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	size := recordSize(&rec)
	for _, seq := range []uint64{rec.FirstSeq, rec.PairSeq} {
		if seq != 0 {
			if err := tx.Delete(seqKey(seq)); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
	}
	if err := tx.Delete(slotKey(s)); err != nil {
		_ = tx.Rollback()
		return err
	}
	floor, err := readCounter(tx, keyFloor)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, w := range []struct {
		k []byte
		v uint64
	}{{keyBytes, used - min(used, size)}, {keyFloor, max(floor, rec.FirstSeq, rec.PairSeq)}} {
		if err := tx.Write(w.k, w.v); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// recordSize is the account of a slot record: what Record added for its statements.
func recordSize(r *SlotRecord) uint64 {
	n := uint64(0)
	o := Observation{Author: r.Author, Key: r.Key, Epoch: r.Epoch, Round: r.Round, S: r.First}
	if raw, err := types.Cbor.Marshal(&o); err == nil {
		n += uint64(len(raw))
	}
	if r.Second != nil {
		o.S = *r.Second
		if raw, err := types.Cbor.Marshal(&o); err == nil {
			n += uint64(len(raw))
		}
	}
	return n
}
