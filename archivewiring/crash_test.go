package archivewiring

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/unicitynetwork/bft-core/archive"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
)

func TestSIGKILLAfterArchivePublishAndAcknowledgement(t *testing.T) {
	t.Parallel()
	for _, point := range []string{"after-publish", "after-acknowledgement"} {
		t.Run(point, func(t *testing.T) {
			dir := t.TempDir()
			cmd := exec.Command(os.Args[0], "-test.run=^TestArchiveCrashChild$")
			cmd.Env = append(os.Environ(), "ARCHIVE_CRASH_POINT="+point, "ARCHIVE_CRASH_DIR="+dir)
			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ProcessState == nil || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("child was not killed at %s: %v", point, err)
			}
			q, rec := transportFixture()
			local, err := archive.Open(filepath.Join(dir, "local"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := local.Get(q)
			if err != nil || !equalRecord(q, rec, got) {
				t.Fatalf("local association after kill: %v", err)
			}
			replica, err := archive.Open(filepath.Join(dir, "replica"))
			if err != nil {
				t.Fatal(err)
			}
			got, err = replica.Get(q)
			if point == "after-publish" {
				if !errors.Is(err, archive.ErrUnavailable) {
					t.Fatalf("premature replica record: %v", err)
				}
			} else if err != nil || !equalRecord(q, rec, got) {
				t.Fatalf("acknowledged association after kill: %v", err)
			}
		})
	}
}

func TestArchiveCrashChild(t *testing.T) {
	point := os.Getenv("ARCHIVE_CRASH_POINT")
	if point == "" {
		return
	}
	dir := os.Getenv("ARCHIVE_CRASH_DIR")
	q, rec := transportFixture()
	local, err := archive.Open(filepath.Join(dir, "local"))
	if err != nil {
		t.Fatal(err)
	}
	if err := local.Put(q, rec); err != nil {
		t.Fatal(err)
	}
	if point == "after-publish" {
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		t.Fatal("SIGKILL returned")
	}
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	receiver := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	sender.Network().Peerstore().AddAddrs(receiver.ID(), receiver.MultiAddresses(), peerstore.PermanentAddrTTL)
	replica, err := archive.Open(filepath.Join(dir, "replica"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(replica, q.Context, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{sender.ID()}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	server.Register(context.Background(), receiver)
	if err := PutAndReadBack(context.Background(), sender, receiver.ID(), q, rec, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if point == "after-acknowledgement" {
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		t.Fatal("SIGKILL returned")
	}
	t.Fatalf("unknown crash point %q", point)
}

func equalRecord(q archive.Request, a, b *archive.Record) bool {
	if a == nil || b == nil {
		return false
	}
	x, err := archive.ManifestDigest(q, a)
	if err != nil {
		return false
	}
	y, err := archive.ManifestDigest(q, b)
	return err == nil && x == y
}
