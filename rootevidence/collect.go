package rootevidence

import (
	"bytes"
	"fmt"
	"sort"
)

// Collection is the merge of what several observers hold: one half of an offence may sit in one journal and the other in another, and neither
// observer alone has a pair. Gaps counts the export ranges that were declared incomplete: a collection with gaps is not proof that no other pair exists.
type Collection struct {
	Slots map[Slot]*SlotRecord
	Gaps  int
}

// Collect reads every record of the journals through the bounded export and merges them by slot. Statements are identified by the digest of
// their preimage; the first two different ones of a slot make its pair. It reads signed data only: no key is needed.
func Collect(journals ...*Journal) (*Collection, error) {
	c := &Collection{Slots: map[Slot]*SlotRecord{}}
	for _, j := range journals {
		var after uint64
		for {
			page, err := j.Export(after, MaxPageRecords)
			if err != nil {
				return nil, err
			}
			if page.Gap {
				c.Gaps++
			}
			for _, rec := range page.Records {
				if err := c.add(rec); err != nil {
					return nil, err
				}
			}
			if !page.More {
				break
			}
			after = page.NextSeq
		}
	}
	return c, nil
}

func (c *Collection) add(rec *SlotRecord) error {
	s := Slot{rec.Author, rec.Epoch, rec.Round}
	have := c.Slots[s]
	if have == nil {
		cp := *rec
		cp.FirstSeq, cp.PairSeq = 0, 0 // sequence numbers are the source journal's
		c.Slots[s] = &cp
		return nil
	}
	if !bytes.Equal(have.Key, rec.Key) {
		return fmt.Errorf("rootevidence: observers disagree on the key of %s in epoch %d", rec.Author, rec.Epoch)
	}
	for _, st := range []*Statement{&rec.First, rec.Second} {
		if st == nil || have.Second != nil {
			continue
		}
		d := st.Digest()
		if d == have.First.Digest() {
			continue
		}
		cp := *st
		have.Second = &cp
	}
	return nil
}

// Pairs are the collected slots that hold two different statements, ordered by epoch, round and author.
func (c *Collection) Pairs() []*SlotRecord {
	var out []*SlotRecord
	for _, r := range c.Slots {
		if r.Paired() {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, k int) bool {
		a, b := out[i], out[k]
		if a.Epoch != b.Epoch {
			return a.Epoch < b.Epoch
		}
		if a.Round != b.Round {
			return a.Round < b.Round
		}
		return a.Author < b.Author
	})
	return out
}
