package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
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
	return validatePairedActivationOrigin(f.FollowRootRPC)
}

// physicalPath preserves the input components until symlinks and parent
// traversals have been evaluated in filesystem order.
func physicalPath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		path = cwd + string(os.PathSeparator) + path
	}
	return filepath.EvalSymlinks(path)
}

// sessionPublicationTarget returns the exact rename destination and its name
// relative to the physical operator socket. The final component is replaced,
// so only the output's parent is resolved.
func sessionPublicationTarget(socket, path string) (destination, target string, err error) {
	parent, base := filepath.Split(path)
	if base == "" || base == "." || base == ".." {
		return "", "", fmt.Errorf("invalid credential destination %q", path)
	}
	socketPath, err := physicalPath(socket)
	if err != nil {
		return "", "", fmt.Errorf("resolving operator socket %q: %w", socket, err)
	}
	parent, err = physicalPath(parent)
	if err != nil {
		return "", "", fmt.Errorf("resolving parent of credential %q: %w", path, err)
	}
	info, err := os.Stat(parent)
	if err != nil {
		return "", "", err
	}
	if !info.IsDir() {
		return "", "", fmt.Errorf("credential parent %q is not a directory", parent)
	}
	destination = filepath.Join(parent, base)
	target, err = filepath.Rel(filepath.Dir(socketPath), destination)
	return destination, target, err
}

type authorityActivationFollower struct {
	operator      advanceOperator
	fetch         func(context.Context, uint64) ([]byte, error)
	provisioned   func() bool
	ensureSession func() error
	wake          <-chan struct{}
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
		case <-f.wake:
		}
		for {
			result, err := f.step(ctx)
			if err != nil && ctx.Err() == nil && time.Since(lastFailure) >= 5*time.Second {
				log.WarnContext(ctx, "following root activation", "error", err)
				lastFailure = time.Now()
			}
			if result.Advanced || result.Retired && !result.Replay {
				log.InfoContext(ctx, "followed root activation", "epoch", result.Epoch, "retired", result.Retired)
			}
			if err != nil || result.Epoch == 0 || result.Replay {
				break
			}
		}
	}
}

func fetchAuthorityActivation(origin string, notifications ...*pairedActivation) func(context.Context, uint64) ([]byte, error) {
	client := pairedActivationHTTP(time.Second)
	return func(ctx context.Context, next uint64) ([]byte, error) {
		if len(notifications) != 0 && notifications[0].ready.Load() {
			if notifications[0].tip.Load() < next {
				return nil, nil
			}
		} else {
			var status q3StatusResponse
			if err := handoffPost(ctx, client, origin+"/api/v1/q3/status", []byte("{}"), &status); err != nil {
				return nil, err
			}
			if status.ActiveEpoch < next {
				return nil, nil
			}
		}
		return fetchPairedActivationBundle(ctx, client, origin, next, service.MaxAdvanceProofBytes)
	}
}
