package archive

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// TestMetadataFootprintProfile measures what the archive's on-disk layout costs the kernel per archived block (bft-core#1018, #1049): the inodes
// a record takes and the slab its creation charges to this process's memory cgroup (ext4 inode and dentry cache, which a container's memory
// limit counts), for the directory layout an earlier binary wrote and for the packed layout PutBatch writes now; then what migrating the
// directory archive costs and releases, and what one BundleEpochs call costs (the publisher calls it every two seconds). Records have the
// production shape, nine fields and two extensions. ARCHIVE_FOOTPRINT_RECORDS selects how many records (unset: skipped); run it in a cgroup of
// its own (systemd-run --user --scope) for the slab figures to be this test's alone.
func TestMetadataFootprintProfile(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("ARCHIVE_FOOTPRINT_RECORDS"))
	if n == 0 {
		t.Skip("set ARCHIVE_FOOTPRINT_RECORDS")
	}
	qs, recs := make([]Request, n), make([]*Record, n)
	for i := range qs {
		q, r := fixture()
		r.Header = binary.BigEndian.AppendUint32(bytes.Clone(r.Header), uint32(i)) // batchFixture's headers repeat after 256
		q.BlockHash = [32]byte(crypto.Keccak256(r.Header))
		uc, err := types.Cbor.Marshal(&types.UnicityCertificate{Version: 1, InputRecord: &types.InputRecord{Version: 1, RoundNumber: uint64(i + 1), BlockHash: q.BlockHash[:]}})
		if err != nil {
			t.Fatal(err)
		}
		r.ResultingUC, r.Body = uc, make([]byte, 8<<10)
		r.Extensions["ext-01"] = []byte("extension")
		qs[i], recs[i] = q, r
	}
	fields, err := allFields(recs[0])
	if err != nil {
		t.Fatal(err)
	}
	_, cgroup := cgroupSlab(t)
	if cgroup != "" {
		t.Logf("cgroup %s", cgroup)
	}
	inodes := func(dir string) (dirs, files int) {
		if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if path == dir {
				return nil
			}
			if d.IsDir() {
				dirs++
			} else {
				files++
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return dirs, files
	}
	measure := func(label string, write func(dir string)) string {
		dir := t.TempDir()
		before, _ := cgroupSlab(t)
		start := time.Now()
		write(dir)
		took := time.Since(start)
		after, _ := cgroupSlab(t)
		d, f := inodes(dir)
		t.Logf("%-34s %d records of %d chunks: %d directories and %d files, %.2f inodes per record; slab %.0f bytes per record; written in %.2f ms per record",
			label+":", n, len(fields), d, f, float64(d+f)/float64(n), float64(after-before)/float64(n), float64(took.Microseconds())/1000/float64(n))
		return dir
	}
	legacy := measure("directory layout (before #1049)", func(dir string) {
		for i := range qs {
			putLegacy(t, dir, qs[i], recs[i], false) // as the earlier store published it, without its syncs
		}
	})
	packed := measure("packed layout (#1049, PutBatch)", func(dir string) {
		s, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < n; i += 16 {
			end := min(i+16, n)
			if err := s.PutBatch(qs[i:end], recs[i:end]); err != nil {
				t.Fatal(err)
			}
		}
	})

	// migrating the directory archive: what it costs, and the slab it gives back
	s, err := Open(legacy)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := cgroupSlab(t)
	start := time.Now()
	migrated := 0
	for {
		res, err := s.MigrateLegacy(MaxPutBatch)
		if err != nil {
			t.Fatal(err)
		}
		migrated += res.Migrated
		if res.Done {
			break
		}
	}
	took := time.Since(start)
	after, _ := cgroupSlab(t)
	d, f := inodes(legacy)
	t.Logf("migration of the directory archive: %d records in %.2f ms per record; slab %+.0f bytes per record; %.2f inodes per record left",
		migrated, float64(took.Microseconds())/1000/float64(n), float64(after-before)/float64(n), float64(d+f)/float64(n))

	ps, err := Open(packed)
	if err != nil {
		t.Fatal(err)
	}
	for epoch := uint64(1); epoch <= 4; epoch++ {
		if _, err := ps.PutBundle(BundleRequest{Context: qs[0].Context, Epoch: epoch}, []byte("bundle"), nil); err != nil {
			t.Fatal(err)
		}
	}
	top, err := os.ReadDir(packed)
	if err != nil {
		t.Fatal(err)
	}
	const calls = 50
	var mb, ma runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&mb)
	start = time.Now()
	for range calls {
		epochs, err := ps.BundleEpochs(qs[0].Context)
		if err != nil || len(epochs) != 4 {
			t.Fatal(epochs, err)
		}
	}
	elapsed := time.Since(start)
	runtime.ReadMemStats(&ma)
	t.Logf("BundleEpochs, packed archive (%d store-directory entries): %.3f ms and %d bytes allocated per call", len(top), float64(elapsed.Microseconds())/1000/calls, (ma.TotalAlloc-mb.TotalAlloc)/calls)
}

// cgroupSlab is the slab memory charged to this process's cgroup (v2), and the cgroup's path; zero and "" where it cannot be read.
func cgroupSlab(t *testing.T) (int64, string) {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return 0, ""
	}
	path, ok := strings.CutPrefix(strings.TrimSpace(string(raw)), "0::")
	if !ok {
		return 0, ""
	}
	f, err := os.Open(filepath.Join("/sys/fs/cgroup", path, "memory.stat"))
	if err != nil {
		return 0, ""
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		var v int64
		if _, err := fmt.Sscanf(scan.Text(), "slab %d", &v); err == nil {
			return v, path
		}
	}
	return 0, ""
}
