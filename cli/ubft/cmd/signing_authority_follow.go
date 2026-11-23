package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/signingauthority/service"
)

func (f *signingAuthorityRunFlags) validateActivationFollower() error {
	if f.FollowRootRPC == "" && f.FollowCredential == "" {
		return nil
	}
	if f.LineageGenesis == "" || f.FollowRootRPC == "" || f.FollowCredential == "" {
		return errors.New("automatic activation requires a root RPC, a client credential path and a lineage pin")
	}
	if filepath.Clean(f.FollowCredential) == filepath.Clean(f.OperatorCredential) {
		return errors.New("automatic activation must write a separate client credential file")
	}
	u, err := url.Parse(f.FollowRootRPC)
	if err != nil || u.Scheme != "http" || !net.ParseIP(u.Hostname()).IsLoopback() ||
		u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("activation root RPC must be a loopback HTTP origin with an explicit port")
	}
	return nil
}

type authorityActivationFollower struct {
	operator      advanceOperator
	fetch         func(context.Context, uint64) ([]byte, error)
	ensureSession func(context.Context, signingauthority.Status) error
	// Keep the obligation to publish the new credential even if the local
	// call failed after advancing or replacing the session.
	pendingEpoch uint64
}

func (f *authorityActivationFollower) step(ctx context.Context) (signingauthority.AdvanceResult, error) {
	status, err := f.operator.Status(ctx)
	if err != nil {
		return signingauthority.AdvanceResult{}, err
	}
	if status.Faulted || status.KeyLost || !status.LineagePinned {
		return signingauthority.AdvanceResult{}, nil
	}
	if f.pendingEpoch != 0 && status.RootEpoch >= f.pendingEpoch {
		if !status.Retired {
			if err := f.ensureSession(ctx, status); err != nil {
				return signingauthority.AdvanceResult{}, err
			}
		}
		f.pendingEpoch = 0
	}
	// Enrollment and the first session are explicitly provisioned by the operator.
	// A retired authority can still follow lineage to a verified recovery.
	if !status.SessionIssued && !status.Retired {
		return signingauthority.AdvanceResult{}, nil
	}
	next := status.LineageEpoch + 1
	raw, err := f.fetch(ctx, next)
	if err != nil || len(raw) == 0 {
		return signingauthority.AdvanceResult{}, err
	}
	if next > status.RootEpoch {
		f.pendingEpoch = next
	}
	result, err := f.operator.AdvanceWithProof(ctx, raw)
	if err != nil {
		return result, err
	}
	if result.Retired {
		f.pendingEpoch = 0
	} else if result.Advanced {
		current, err := f.operator.Status(ctx)
		if err != nil {
			return result, err
		}
		if err := f.ensureSession(ctx, current); err != nil {
			return result, err
		}
		f.pendingEpoch = 0
	}
	return result, nil
}

func (f *authorityActivationFollower) run(ctx context.Context, log *slog.Logger) {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	var lastFailure time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			result, err := f.step(ctx)
			if err != nil && ctx.Err() == nil && time.Since(lastFailure) >= 5*time.Second {
				log.WarnContext(ctx, "following root activation", "error", err)
				lastFailure = time.Now()
			}
			if err == nil && (result.Advanced || result.Retired && !result.Replay) {
				log.InfoContext(ctx, "followed root activation", "epoch", result.Epoch, "retired", result.Retired)
			}
		}
	}
}

func fetchAuthorityActivation(origin string) func(context.Context, uint64) ([]byte, error) {
	client := &http.Client{
		Timeout:       time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return func(ctx context.Context, next uint64) ([]byte, error) {
		var status q3StatusResponse
		if err := handoffPost(ctx, client, origin+"/api/v1/q3/status", []byte("{}"), &status); err != nil {
			return nil, err
		}
		if status.ActiveEpoch < next {
			return nil, nil
		}
		body, err := json.Marshal(q3EpochRequest{Epoch: next})
		if err != nil {
			return nil, err
		}
		var bundle q3BundleResponse
		if err := handoffPost(ctx, client, origin+"/api/v1/q3/bundle", body, &bundle); err != nil {
			return nil, err
		}
		if bundle.Epoch != next || bundle.Bundle == "" || len(bundle.Bundle) > 2*service.MaxAdvanceProofBytes {
			return nil, fmt.Errorf("invalid activation bundle response for epoch %d", next)
		}
		return hex.DecodeString(bundle.Bundle)
	}
}
