package frontiertransport

import "sync"

const (
	MaxReceiveBudget = uint64(1 << 20)
	MaxExchanges     = uint32(4)
)

// ReceiveBudget is shared by every exchange in one future acquisition. Body
// reservations and malformed/partial reads are never refunded.
type ReceiveBudget struct {
	mu        sync.Mutex
	limit     uint64
	attempts  uint32
	active    uint32
	committed uint64
	consumed  uint64
}

type BudgetSnapshot struct {
	Limit, Committed, Consumed uint64
	Attempts, Active           uint32
}

func NewReceiveBudget(limit uint64) (*ReceiveBudget, error) {
	if limit == 0 || limit > MaxReceiveBudget {
		return nil, ErrBounds
	}
	return &ReceiveBudget{limit: limit}, nil
}

func (b *ReceiveBudget) begin() error {
	if b == nil {
		return ErrBudget
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.limit == 0 {
		return ErrBudget
	}
	if b.committed >= b.limit {
		return ErrBudget
	}
	if b.active >= MaxExchanges {
		return ErrNotAdmitted
	}
	b.active++
	b.attempts++
	return nil
}

func (b *ReceiveBudget) end() {
	b.mu.Lock()
	b.active--
	b.mu.Unlock()
}

func (b *ReceiveBudget) reserve(n uint64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n > b.limit-b.committed {
		return ErrBudget
	}
	b.committed += n
	return nil
}

func (b *ReceiveBudget) reserveBody(n uint64) error {
	if n == 0 || n > uint64(MaxResponseBytes) {
		return ErrBudget
	}
	return b.reserve(n)
}

func (b *ReceiveBudget) consume(n uint64) {
	b.mu.Lock()
	b.consumed += n
	b.mu.Unlock()
}

func (b *ReceiveBudget) Snapshot() BudgetSnapshot {
	if b == nil {
		return BudgetSnapshot{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return BudgetSnapshot{Limit: b.limit, Committed: b.committed, Consumed: b.consumed, Attempts: b.attempts, Active: b.active}
}
