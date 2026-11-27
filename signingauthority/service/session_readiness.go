package service

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/unicitynetwork/bft-core/signingauthority"
)

// WatchCredentialFile configures the filesystem notification used when the
// shard already has a successor certificate but its local signer is catching up.
// Set it before using the client.
func (r *ReloadingClient) WatchCredentialFile(path string) { r.credentialPath = path }

// WaitRootEpoch waits for the local credential to authenticate in this epoch.
// It does not reserve a round or wait for any remote validator.
func (r *ReloadingClient) WaitRootEpoch(ctx context.Context, epoch uint64) error {
	if r.credentialPath == "" || r.readyRootEpoch.Load() == epoch {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	check := func() (bool, error) {
		status, err := r.RestoreStatus(ctx)
		if errors.Is(err, signingauthority.ErrFenced) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		switch {
		case status.KeyLost:
			return false, signingauthority.ErrKeyLost
		case status.Faulted:
			return false, signingauthority.ErrStateUntrusted
		case status.Retired:
			return false, signingauthority.ErrRetired
		case status.RootEpoch > epoch:
			return false, signingauthority.ErrFenced
		case status.RootEpoch == epoch && status.SessionIssued:
			r.readyRootEpoch.Store(epoch)
			return true, nil
		default:
			return false, nil
		}
	}
	if ready, err := check(); ready || err != nil {
		return err
	}
	path, err := filepath.Abs(r.credentialPath)
	if err != nil {
		return err
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()
	if err := watcher.Add(filepath.Dir(path)); err != nil {
		return err
	}
	// Check again after registering, so an atomic rename between the first
	// check and Add cannot be missed.
	for {
		if ready, err := check(); ready || err != nil {
			return err
		}
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case err, open := <-watcher.Errors:
				if !open {
					return errors.New("credential watcher stopped")
				}
				return fmt.Errorf("watching local credential: %w", err)
			case event, open := <-watcher.Events:
				if !open {
					return errors.New("credential watcher stopped")
				}
				if filepath.Clean(event.Name) != path {
					continue
				}
			}
			break
		}
	}
}
