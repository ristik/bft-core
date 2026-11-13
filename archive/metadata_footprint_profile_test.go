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

// TestMetadataFootprintProfile measures what the archive's on-disk layout costs the kernel per archived block (bft-core#1018): the inodes a
// record takes, the slab its creation charges to this process's memory cgroup (ext4 inode and dentry cache, which a container's memory
// limit counts), and what one BundleEpochs call costs at that archive size (the publisher calls it every two seconds). Records have the
// production shape, nine fields and two extensions. ARCHIVE_FOOTPRINT_RECORDS selects how many records (unset: skipped); run it in a
// cgroup of its own (systemd-run --user --scope) for the slab figure to be this test's alone.
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
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for epoch := uint64(1); epoch <= 4; epoch++ {
		if _, err := s.PutBundle(BundleRequest{Context: qs[0].Context, Epoch: epoch}, []byte("bundle"), nil); err != nil {
			t.Fatal(err)
		}
	}
	slabBefore, cgroup := cgroupSlab(t)
	start := time.Now()
	for i := 0; i < n; i += 16 {
		end := min(i+16, n)
		if err := s.PutBatch(qs[i:end], recs[i:end]); err != nil {
			t.Fatal(err)
		}
	}
	putTime := time.Since(start)
	slabAfter, _ := cgroupSlab(t)
	var dirs, files int
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
	top, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d records of %d chunks: %d directories and %d files (%.2f inodes per record), %d entries in the store directory; put %.2f ms per record",
		n, len(fields), dirs, files, float64(dirs+files)/float64(n), len(top), float64(putTime.Microseconds())/1000/float64(n))
	if cgroup != "" {
		t.Logf("slab charged to %s: %d -> %d bytes, %.0f bytes per record", cgroup, slabBefore, slabAfter, float64(slabAfter-slabBefore)/float64(n))
	}
	const calls = 50
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start = time.Now()
	for range calls {
		epochs, err := s.BundleEpochs(qs[0].Context)
		if err != nil || len(epochs) != 4 {
			t.Fatal(epochs, err)
		}
	}
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	t.Logf("BundleEpochs at %d store entries: %.3f ms and %d bytes allocated per call", len(top), float64(elapsed.Microseconds())/1000/calls, (after.TotalAlloc-before.TotalAlloc)/calls)

	// For comparison, the same bytes as ONE file per record in 256 fan-out directories. This is a cost model only; nothing reads it.
	model := t.TempDir()
	payload := make([]byte, 0, 16<<10)
	for _, v := range fields {
		payload = append(payload, v...)
	}
	slabBefore, _ = cgroupSlab(t)
	for i := range n {
		sub := filepath.Join(model, fmt.Sprintf("%02x", i%256))
		if err := os.MkdirAll(sub, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sub, fmt.Sprintf("%064x", i)), payload, 0600); err != nil {
			t.Fatal(err)
		}
	}
	slabAfter, _ = cgroupSlab(t)
	if cgroup != "" {
		t.Logf("one file per record in 256 directories (model): %.2f inodes per record, %.0f bytes of slab per record", float64(n+256)/float64(n), float64(slabAfter-slabBefore)/float64(n))
	}
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
