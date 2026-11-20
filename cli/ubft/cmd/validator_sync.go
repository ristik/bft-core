package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/rpc"

	"github.com/unicitynetwork/bft-core/seed"
)

// syncView is the sync part of `ubft validator status` (VT-11): the node's height, how fast it closes the gap to the head, the time that takes, and
// the sources its data came from.
type syncView struct {
	LocalHead  *uint64 `json:"localHead,omitempty"`
	PublicHead uint64  `json:"publicHead"`
	Behind     *int64  `json:"behind,omitempty"`
	// RateBlocksPerSec is how fast the local head moved over the sample window; HeadRateBlocksPerSec how fast the public head did.
	RateBlocksPerSec     *float64 `json:"rateBlocksPerSec,omitempty"`
	HeadRateBlocksPerSec *float64 `json:"headRateBlocksPerSec,omitempty"`
	// ETA is the time to the head at the net closing rate: "caught up", a duration, or "not closing" (the node is not catching up).
	ETA string `json:"eta,omitempty"`
	// Sources are where the node's chain data comes from: the seed it started from and the public endpoint it is measured against.
	Sources []string           `json:"sources"`
	Seed    *seed.ImportRecord `json:"seed,omitempty"`
}

// etaOf is the time to close behind blocks at the net rate (own rate minus the head's); the empty string when no rate is known.
func etaOf(behind int64, rate, headRate float64) string {
	switch {
	case behind <= 2:
		return "caught up"
	case rate-headRate <= 0:
		return "not closing"
	}
	return (time.Duration(float64(behind)/(rate-headRate)) * time.Second).Round(time.Second).String()
}

func headOf(ctx context.Context, url string) (uint64, error) {
	c, err := rpc.DialContext(ctx, url)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	n, _, err := blockInfo(ctx, c, "latest")
	return n, err
}

func buildSyncView(ctx context.Context, v *loadedValidator, r *validatorStatusReport, sample time.Duration) *syncView {
	s := &syncView{LocalHead: r.LocalHead, PublicHead: r.PublicHead, Sources: []string{"public RPC " + v.cfg.RPC}}
	if rec, err := seed.ReadImportRecord(v.home); err != nil {
		r.Unknown = append(r.Unknown, "seed import record: "+err.Error())
	} else if rec != nil {
		s.Seed = rec
		s.Sources = append(s.Sources, fmt.Sprintf("seed %s (%s)", rec.ManifestDigest, strings.Join(rec.Sources, ", ")))
	}
	if r.LocalHead == nil {
		return s
	}
	behind := int64(r.PublicHead) - int64(*r.LocalHead)
	s.Behind = &behind
	if sample > 0 && v.cfg.LocalRPC != "" {
		s.ETA = "unknown (a head sample was unavailable)"
		l0, p0, t0 := *r.LocalHead, r.PublicHead, time.Now()
		select {
		case <-ctx.Done():
			return s
		case <-time.After(sample):
		}
		sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		l1, lerr := headOf(sctx, v.cfg.LocalRPC)
		p1, perr := headOf(sctx, v.cfg.RPC)
		if lerr == nil && perr == nil {
			dt := time.Since(t0).Seconds()
			rate, hrate := float64(int64(l1)-int64(l0))/dt, float64(int64(p1)-int64(p0))/dt
			s.RateBlocksPerSec, s.HeadRateBlocksPerSec = &rate, &hrate
			s.LocalHead, s.PublicHead = &l1, p1
			b := int64(p1) - int64(l1)
			s.Behind = &b
			s.ETA = etaOf(b, rate, hrate)
		}
	}
	return s
}

func (s *syncView) text(w io.Writer) {
	if s == nil {
		return
	}
	line := fmt.Sprintf("catch-up: public head %d", s.PublicHead)
	if s.LocalHead != nil {
		line += fmt.Sprintf(", local head %d", *s.LocalHead)
	}
	if s.Behind != nil {
		line += fmt.Sprintf(", behind %d", *s.Behind)
	}
	if s.RateBlocksPerSec != nil {
		line += fmt.Sprintf(", rate %.2f blocks/s (head %.2f/s)", *s.RateBlocksPerSec, *s.HeadRateBlocksPerSec)
	}
	if s.ETA != "" {
		line += ", time to head: " + s.ETA
	}
	fmt.Fprintln(w, line)
	fmt.Fprintf(w, "sources: %s\n", strings.Join(s.Sources, "; "))
	if s.Seed != nil {
		fmt.Fprintf(w, "seed: imported %s, trust-base tip epoch %d, checkpoint root epoch %d round %d, shard round %d\n", s.Seed.ImportedAt, s.Seed.UTBTipEpoch,
			s.Seed.RootEpoch, s.Seed.RootRound, s.Seed.ShardRound)
	}
}
