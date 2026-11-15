package archivewiring

import (
	"context"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// ReadBackCache holds the replica read-backs one frontier advance made in batches (bft-core#1071): which representation (manifest digest)
// each replica served for each block, read back complete in a chain read (opChain) moments before. An advance reads its planned blocks
// back from the replicas in a few chain reads instead of four single reads per block (the worker's choice of holders, then the journal's
// plan, each read every acknowledging replica once): at 50 ms RTT those single reads held a late joiner's frontier at about 4 blocks/s,
// and with it the whole catch-up, which cannot run more than a journal ahead of it.
//
// What a hit stands for is exactly what VerifyAvailable establishes by itself: the replica returned a complete record whose recomputed
// manifest digest is the expected one. Only a batched read-back of the running advance enters the cache, and the advance clears it when it
// ends, so a hit is never older than that advance (and never older than readBackFresh in any case). A miss, or a representation other than
// the expected one, is read back singly as before. The zero value is ready to use; a nil cache holds nothing.
type ReadBackCache struct {
	mu   sync.Mutex
	seen map[readBackKey]readBack
	now  func() time.Time // tests
}

type readBackKey struct {
	replica peer.ID
	request string // the encoded request
}

type readBack struct {
	digest [32]byte
	at     time.Time
}

const (
	// readBackFresh bounds how old a batched read-back may be when it stands for one: about the longest an advance of a catch-up page
	// takes. The advance clears the cache when it ends; this bound only covers an advance that never got there.
	readBackFresh = 30 * time.Second
	// maxReadBacks bounds the cache: two replicas' read-backs of the largest advance (a catch-up page) several times over.
	maxReadBacks = 4096
)

func (c *ReadBackCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// note records that replica served q's record with the given manifest digest, read back complete.
func (c *ReadBackCache) note(replica peer.ID, q archive.Request, digest [32]byte) {
	if c == nil {
		return
	}
	raw, err := archive.EncodeRequest(q)
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = make(map[readBackKey]readBack)
	}
	if len(c.seen) >= maxReadBacks {
		return // a miss costs a single read, as before
	}
	c.seen[readBackKey{replica: replica, request: string(raw)}] = readBack{digest: digest, at: c.clock()}
}

// holds reports whether replica served exactly the expected representation of q in a read-back of the running advance.
func (c *ReadBackCache) holds(replica peer.ID, q archive.Request, expected [32]byte) bool {
	if c == nil {
		return false
	}
	raw, err := archive.EncodeRequest(q)
	if err != nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.seen[readBackKey{replica: replica, request: string(raw)}]
	return ok && r.digest == expected && c.clock().Sub(r.at) <= readBackFresh
}

// clear forgets every read-back: the advance that made them has ended.
func (c *ReadBackCache) clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen = nil
}

// readBackRun reads blocks (consecutive, oldest first: each the parent of the next) back from each replica, newest first, in chain reads
// of up to MaxChainRecords records, the replicas in parallel, and notes the manifest digest of every record each returned. stop is the
// block below the run (the frontier anchor), zero when unknown. A replica that fails or ends its chain early simply contributes fewer
// read-backs: what is missing is read singly by VerifyAvailable. Nothing here is a verdict; it only spares the single reads.
func readBackRun(ctx context.Context, cache *ReadBackCache, host shardnode.EvidenceHost, replicas []peer.ID, subject archive.Context, blocks [][32]byte, stop [32]byte, limits Limits) {
	if cache == nil || host == nil || len(blocks) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, id := range replicas {
		if id == "" {
			continue
		}
		wg.Add(1)
		go func(id peer.ID) {
			defer wg.Done()
			for done := 0; done < len(blocks) && ctx.Err() == nil; {
				top := blocks[len(blocks)-1-done]
				chain, err := FetchChain(ctx, host, id, archive.Request{Context: subject, BlockHash: top}, stop, min(len(blocks)-done, MaxChainRecords), limits)
				if err != nil || len(chain) == 0 {
					return
				}
				for _, c := range chain {
					if digest, err := archive.ManifestDigest(c.Request, c.Record); err == nil {
						cache.note(id, c.Request, digest)
					}
				}
				done += len(chain)
			}
		}(id)
	}
	wg.Wait()
}
