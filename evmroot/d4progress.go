package evmroot

import "time"

type D4ProgressEvent struct {
	Name string
	At   time.Duration
}
type D4PauseMeasurement struct{ LastOldUC, HProof, SnapshotReady, FirstNewQC, FirstNewUC, EVMAck time.Duration }

func (m D4PauseMeasurement) Valid() bool {
	return m.LastOldUC <= m.HProof && m.HProof <= m.SnapshotReady && m.SnapshotReady <= m.FirstNewQC && m.FirstNewQC <= m.FirstNewUC && m.FirstNewUC <= m.EVMAck
}
func (m D4PauseMeasurement) Pause() time.Duration { return m.FirstNewUC - m.LastOldUC }

// Old suffix liveness is driven by timeout and consecutive-QC events, not
// the numeric A* boundary. Losing the old quorum before proof stalls safely.
type D4OldProgress struct {
	Order, Start    uint64
	Live, Delivered bool
	Timeouts        []uint64
	Certified       map[uint64]bool
	Seal            uint64
}

func (p *D4OldProgress) Timeout(round uint64) error {
	if !p.Live || round <= p.Order {
		return ErrD4Epoch
	}
	p.Timeouts = append(p.Timeouts, round)
	return nil
}
func (p *D4OldProgress) CertifyEmpty(round uint64) error {
	if !p.Live || round <= p.Order {
		return ErrD4Epoch
	}
	if p.Certified == nil {
		p.Certified = map[uint64]bool{}
	}
	p.Certified[round] = true
	if round > 0 && p.Certified[round-1] {
		p.Seal = round - 1
	}
	return nil
}
func (p *D4OldProgress) DeliverProof() error {
	if p.Seal == 0 {
		return ErrD4Proof
	}
	p.Delivered = true
	return nil
}
func (p *D4OldProgress) NewMayBootstrap() bool { return p.Delivered }
