// Command h3-pdr prints, as JSON, the EVM shard configuration a root orchestration database holds for one
// shard epoch. It reads a copy of the database and is used only by the H3 acceptance lane to give the
// offline F7 extractor the PDR a certificate commits to.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-go-base/types"
)

func main() {
	db := flag.String("orchestration", "", "orchestration.db of a root node")
	epoch := flag.Uint64("epoch", 0, "shard epoch")
	partition := flag.Uint("partition", 8, "partition id")
	network := flag.Uint("network", 3, "network id")
	flag.Parse()
	dir, err := os.MkdirTemp("", "h3-pdr")
	if err != nil {
		fatal(err)
	}
	defer os.RemoveAll(dir)
	copyPath := filepath.Join(dir, "orchestration.db")
	if err := copyFile(*db, copyPath); err != nil {
		fatal(err)
	}
	o, err := partitions.NewOrchestration(types.NetworkID(*network), copyPath, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		fatal(err)
	}
	defer o.Close()
	pdr, err := o.ShardConfigByEpoch(types.PartitionID(*partition), types.ShardID{}, *epoch)
	if err != nil || pdr == nil {
		fatal(fmt.Errorf("no configuration for shard epoch %d: %v", *epoch, err))
	}
	_ = json.NewEncoder(os.Stdout).Encode(pdr)
}

func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(to)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "h3-pdr:", err)
	os.Exit(1)
}
