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

// sessionPublicationTarget identifies a file relative to its operator socket. Use
// its parent because atomic publication replaces the last component itself.
func sessionPublicationTarget(socket, path string) (string, error) {
	socketPath, err := filepath.Abs(socket)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(socketPath); err == nil {
		socketPath = resolved
	} else if parent, err := filepath.EvalSymlinks(filepath.Dir(socketPath)); err == nil {
		socketPath = filepath.Join(parent, filepath.Base(socketPath))
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if parent, err := filepath.EvalSymlinks(filepath.Dir(path)); err == nil {
		path = filepath.Join(parent, filepath.Base(path))
	}
	return filepath.Rel(filepath.Dir(socketPath), path)
}

type authorityActivationFollower struct {
	operator      advanceOperator
	fetch         func(context.Context, uint64) ([]byte, error)
	provisioned   func() bool
	ensureSession func() error
}

func (f *authorityActivationFollower) step(ctx context.Context) (signingauthority.AdvanceResult, error) {
	status, err := f.operator.Status(ctx)
	if err != nil {
		return signingauthority.AdvanceResult{}, err
	}
	if status.Faulted || status.KeyLost || !status.LineagePinned || (!status.Retired && !f.provisioned()) {
		return signingauthority.AdvanceResult{}, nil
	}
	// A verified exclusion fences locally even when the credential cannot be
	// written. Follow the lineage before attempting to repair the latest session.
	raw, proofErr := f.fetch(ctx, status.LineageEpoch+1)
	var result signingauthority.AdvanceResult
	if proofErr == nil && len(raw) != 0 {
		result, proofErr = f.operator.AdvanceWithProof(ctx, raw)
	}
	return result, errors.Join(proofErr, f.ensureSession())
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
			if result.Advanced || result.Retired && !result.Replay {
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
