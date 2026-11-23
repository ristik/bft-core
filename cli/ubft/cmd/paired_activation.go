package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

// pairedActivation receives availability hints from this validator's own root.
// Only consumers of the complete bundle can install an activation.
type pairedActivation struct {
	origin string
	wake   chan struct{}
	tip    atomic.Uint64
	ready  atomic.Bool
}

func validatePairedActivationOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || !net.ParseIP(u.Hostname()).IsLoopback() ||
		u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("activation root RPC must be a loopback HTTP origin with an explicit port")
	}
	return nil
}

func newPairedActivation(origin string) *pairedActivation {
	return &pairedActivation{origin: origin, wake: make(chan struct{}, 1)}
}

func pairedActivationHTTP(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (p *pairedActivation) run(ctx context.Context) {
	client := pairedActivationHTTP(5 * time.Second)
	defer client.CloseIdleConnections()
	for ctx.Err() == nil {
		after := p.tip.Load()
		body, _ := json.Marshal(q3EpochRequest{Epoch: after})
		var hint q3EpochRequest
		if err := handoffPost(ctx, client, p.origin+"/api/v1/q3/wait-activation", body, &hint); err != nil {
			p.ready.Store(false)
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
			continue
		}
		p.ready.Store(true)
		if hint.Epoch > after {
			p.tip.Store(hint.Epoch)
			select {
			case p.wake <- struct{}{}:
			default:
			}
		}
	}
}

func fetchPairedActivationBundle(ctx context.Context, client *http.Client, origin string, epoch uint64, limit int) ([]byte, error) {
	body, _ := json.Marshal(q3EpochRequest{Epoch: epoch})
	var bundle q3BundleResponse
	if err := handoffPost(ctx, client, origin+"/api/v1/q3/bundle", body, &bundle); err != nil {
		return nil, err
	}
	if bundle.Epoch != epoch || bundle.Bundle == "" || len(bundle.Bundle) > 2*limit {
		return nil, fmt.Errorf("invalid activation bundle response for epoch %d", epoch)
	}
	return hex.DecodeString(bundle.Bundle)
}
