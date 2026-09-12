// fsyncprobe measures bbolt commit latency on this host, the way the consensus test fixtures open
// their stores (default options: every commit syncs), against NoSync, for one database and for four
// committing concurrently (one per root node in the fixtures). Investigation tooling for #127.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

func run(dir string, dbs, commits int, noSync bool) []time.Duration {
	var mu sync.Mutex
	var all []time.Duration
	var wg sync.WaitGroup
	for d := 0; d < dbs; d++ {
		db, err := bolt.Open(filepath.Join(dir, fmt.Sprintf("n%d-%v.db", d, noSync)), 0600, &bolt.Options{Timeout: 3 * time.Second})
		if err != nil {
			panic(err)
		}
		db.NoSync = noSync
		wg.Add(1)
		go func(db *bolt.DB) {
			defer wg.Done()
			defer db.Close()
			for i := 0; i < commits; i++ {
				t0 := time.Now()
				if err := db.Update(func(tx *bolt.Tx) error {
					b, err := tx.CreateBucketIfNotExists([]byte("b"))
					if err != nil {
						return err
					}
					return b.Put([]byte(fmt.Sprintf("k%d", i)), make([]byte, 512))
				}); err != nil {
					panic(err)
				}
				mu.Lock()
				all = append(all, time.Since(t0))
				mu.Unlock()
			}
		}(db)
	}
	wg.Wait()
	return all
}

func stats(d []time.Duration) string {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	var sum time.Duration
	for _, x := range d {
		sum += x
	}
	return fmt.Sprintf("n=%d mean=%v p50=%v p95=%v max=%v", len(d), (sum / time.Duration(len(d))).Round(10*time.Microsecond),
		d[len(d)/2].Round(10*time.Microsecond), d[len(d)*95/100].Round(10*time.Microsecond), d[len(d)-1].Round(10*time.Microsecond))
}

func main() {
	dir, err := os.MkdirTemp("", "fsyncprobe")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	fmt.Println("dir", dir)
	fmt.Println("1 db,  sync   :", stats(run(dir, 1, 60, false)))
	fmt.Println("1 db,  NoSync :", stats(run(dir, 1, 60, true)))
	fmt.Println("4 dbs, sync   :", stats(run(dir, 4, 30, false)))
	fmt.Println("4 dbs, NoSync :", stats(run(dir, 4, 30, true)))
}
