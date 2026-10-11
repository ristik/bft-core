package archive

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestPutCostProfile measures where a put's time goes, per record, through the store's own disk seam: how many files and
// directories it syncs and how long each stage takes, for single puts and for batches; and, for comparison, what the same bytes
// would cost if a record were one file. ARCHIVE_PROFILE_RECORDS selects how many records (unset: skipped).
func TestPutCostProfile(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("ARCHIVE_PROFILE_RECORDS"))
	if n == 0 {
		t.Skip("set ARCHIVE_PROFILE_RECORDS")
	}
	for _, extensions := range []int{1, 16} {
		qs, recs := batchFixture(t, n)
		for _, r := range recs {
			r.Body = make([]byte, 8<<10) // a body of realistic size; the cost is the syncs, not the bytes
			for i := 1; i < extensions; i++ {
				r.Extensions[fmt.Sprintf("ext-%02d", i)] = []byte("extension")
			}
		}
		fields, err := allFields(recs[0])
		if err != nil {
			t.Fatal(err)
		}
		files := len(fields) + 1
		for _, batch := range []int{1, 16} {
			s, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			var fileSyncs, dirSyncs, storeSyncs, renames atomic.Int64
			var fileWall, dirWall, storeWall, renameWall time.Duration // wall time of each stage, measured around the stage
			var mu sync.Mutex
			var stageStart time.Time
			var stage string
			enter := func(name string) { // the stages run one after another; within a stage the calls overlap
				mu.Lock()
				defer mu.Unlock()
				now := time.Now()
				if stage != name {
					switch stage {
					case "file":
						fileWall += now.Sub(stageStart)
					case "dir":
						dirWall += now.Sub(stageStart)
					case "rename":
						renameWall += now.Sub(stageStart)
					case "store":
						storeWall += now.Sub(stageStart)
					}
					stage, stageStart = name, now
				}
			}
			s.disk = &diskOps{
				syncFile: func(f *os.File) error { enter("file"); fileSyncs.Add(1); return f.Sync() },
				syncDir: func(dir string) error {
					if dir == s.dir {
						enter("store")
						storeSyncs.Add(1)
					} else {
						enter("dir")
						dirSyncs.Add(1)
					}
					return syncDir(dir)
				},
				rename: func(from, to string) error { enter("rename"); renames.Add(1); return os.Rename(from, to) },
			}
			start := time.Now()
			for i := 0; i < n; i += batch {
				end := min(i+batch, n)
				if err := s.PutBatch(qs[i:end], recs[i:end]); err != nil {
					t.Fatal(err)
				}
				enter("idle")
			}
			total := time.Since(start)
			per := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 / float64(n) }
			t.Logf("%2d files per record, batch %2d: %7.2f ms per record | syncs per record: %d file, %d dir, %.2f store | ms per record: file stage %.2f, dir stage %.2f, renames %.2f, store sync %.2f",
				files, batch, per(total), fileSyncs.Load()/int64(n), dirSyncs.Load()/int64(n), float64(storeSyncs.Load())/float64(n),
				per(fileWall), per(dirWall), per(renameWall), per(storeWall))
		}
		// the same bytes as ONE file per record: written to a temporary name, synced, renamed into the store directory, and the
		// directory synced once per batch. This is a cost model only; nothing reads these files.
		for _, batch := range []int{1, 16} {
			dir := t.TempDir()
			payload := make([]byte, 0, 16<<10)
			for _, v := range fields {
				payload = append(payload, v...)
			}
			start := time.Now()
			for i := 0; i < n; i += batch {
				end := min(i+batch, n)
				var wg sync.WaitGroup
				for j := i; j < end; j++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						f, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf(".writing-%d", j)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
						if err == nil {
							_, err = f.Write(payload)
						}
						if err == nil {
							err = f.Sync()
						}
						if err == nil {
							err = f.Close()
						}
						if err != nil {
							t.Error(err)
						}
					}()
				}
				wg.Wait()
				for j := i; j < end; j++ {
					if err := os.Rename(filepath.Join(dir, fmt.Sprintf(".writing-%d", j)), filepath.Join(dir, fmt.Sprintf("record-%d", j))); err != nil {
						t.Fatal(err)
					}
				}
				if err := syncDir(dir); err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("   one file per record (model), batch %2d: %7.2f ms per record | syncs per record: 1 file, %.2f directory", batch,
				float64(time.Since(start).Microseconds())/1000/float64(n), 1/float64(batch))
		}
	}
}
