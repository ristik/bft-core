package cmd

import "testing"

func TestETA(t *testing.T) {
	for _, c := range []struct {
		behind     int64
		rate, head float64
		want       string
	}{{0, 0, 0, "caught up"}, {2, 0, 0, "caught up"}, {100, 0, 0.1, "not closing"}, {100, 5.1, 0.1, "20s"}, {600, 11, 1, "1m0s"}} {
		if got := etaOf(c.behind, c.rate, c.head); got != c.want {
			t.Errorf("etaOf(%d, %v, %v) = %q, want %q", c.behind, c.rate, c.head, got, c.want)
		}
	}
}
