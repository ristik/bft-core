package archivewiring

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

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
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ProcessState == nil || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("child was not killed at %s: %v\nchild output:\n%s", point, err, out)
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
		killSelf(t)
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
		killSelf(t)
	}
	t.Fatalf("unknown crash point %q", point)
}

// killSelf SIGKILLs this process and does not return normally. kill(2) on oneself only queues the signal: under load the process can
// keep running for a while before the kernel delivers it, and a child that fell through to t.Fatal in that window exited with status 1
// instead of dying by SIGKILL (the parent then reported "child was not killed"). Wait for the signal to land instead.
func killSelf(t *testing.T) {
	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	time.Sleep(30 * time.Second)
	t.Fatal("SIGKILL was not delivered within 30s")
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
