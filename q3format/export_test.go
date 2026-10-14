package q3format

import "encoding/binary"

// Synthesize extends a history with n copies of its last epoch's committee and configuration under consecutive epoch numbers and increasing starts (ten
// rounds apart), so that tests can ask what the registry projection costs at a long permanent history. The copies are not activations: nothing
// verifies them, and only the B1 projection reads them.
func Synthesize(h *History, n int) *History {
	last := h.entries[len(h.entries)-1]
	out := &History{network: h.network, genesis: h.genesis, entries: append(make([]Entry, 0, len(h.entries)+n), h.entries...)}
	for i := 1; i <= n; i++ {
		e := last
		e.epoch = last.epoch + uint64(i)
		e.start = last.start + uint64(10*i)
		binary.BigEndian.PutUint64(e.bodyID[:8], e.epoch)
		binary.BigEndian.PutUint64(e.commitID[:8], e.epoch)
		out.entries = append(out.entries, e)
	}
	return out
}
