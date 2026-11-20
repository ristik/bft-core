package cmd

// `ubft seed`: the public sync seed (VT-11, bft-core#1151). A synced validator exports a seed (the trust-base history, the certified checkpoint,
// the archive frontier, the execution head), serves it read-only or hands the directory to any web server; a new validator fetches it from one or
// more sources, verifies it against the pinned genesis EntryID alone, and imports it. Nothing in a seed is trusted: see package seed.
//
//	export  read the node's own state (root RPC, archive directory, shard status, execution client) and write a verified seed directory
//	serve   read-only HTTP over a seed directory (loopback by default)
//	fetch   take a seed from several sources, refuse on disagreement, verify, write the verified directory
//	import  verify a seed directory and place it in a validator home (and load its trust-base history into the entry stores)

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"

	"github.com/unicitynetwork/bft-core/gettrustbase"
	"github.com/unicitynetwork/bft-core/seed"
)

const seedHTTPTimeout = 30 * time.Second

func newSeedCmd(base *baseFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "seed", Short: "Export, serve, fetch and import the public sync seed of a validator network"}
	cmd.AddCommand(seedExportCmd(), seedServeCmd(), seedFetchCmd(), seedImportCmd(base), seedPinEpochCmd())
	return cmd
}

func httpGetBounded(ctx context.Context, rawURL string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: seedHTTPTimeout}).Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", rawURL, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: more than %d bytes", rawURL, max)
	}
	return b, nil
}

func seedExportCmd() *cobra.Command {
	var rootRPC, utbFile, genesisID, archiveDir, shardStatus, ethRPC, out string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Write a verified seed from this validator's own state (run on a synced validator)",
		Long: "Reads the signed trust-base history (the root's GET /api/v1/utb/bundle, or --utb-bundle), the newest certified record of the shard node's archive " +
			"directory (immutable files, readable while the node runs), optionally the shard node's frontier pins and the execution client's head, and writes " +
			"manifest.json and the payload files to --out. The seed is verified from the same bytes before anything is written.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			pin, err := seed.ParseGenesisID(genesisID)
			if err != nil {
				return err
			}
			if (rootRPC == "") == (utbFile == "") {
				return errors.New("give exactly one of --root-rpc and --utb-bundle")
			}
			in := seed.ExportInput{GenesisID: pin, ArchiveDir: archiveDir, Now: time.Now()}
			if utbFile != "" {
				if in.UTBBundle, err = os.ReadFile(utbFile); err != nil {
					return err
				}
			} else if in.UTBBundle, err = httpGetBounded(ctx, strings.TrimRight(rootRPC, "/")+"/api/v1/utb/bundle", seed.MaxUTBBytes); err != nil {
				return fmt.Errorf("reading the root's trust-base history (is --utb-genesis set on the root?): %w", err)
			}
			if shardStatus != "" {
				if in.StatusJSON, err = httpGetBounded(ctx, strings.TrimRight(shardStatus, "/")+"/api/v1/operator/status", 1<<20); err != nil {
					return err
				}
			}
			if ethRPC != "" {
				in.Ureth = func(height uint64, hash string) (*seed.UrethRef, error) { return urethRef(ctx, ethRPC, height, hash) }
			}
			v, err := seed.Export(in, out)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), v.Summary())
			fmt.Fprintf(cmd.OutOrStdout(), "written to %s (serve it with `ubft seed serve --dir %s`, or give the directory to any web server)\n", out, out)
			return nil
		}}
	cmd.Flags().StringVar(&rootRPC, "root-rpc", "", "the root's RPC base URL (its --utb-genesis profile serves the history)")
	cmd.Flags().StringVar(&utbFile, "utb-bundle", "", "a trust-base history bundle file instead of --root-rpc (`ubft trust-base utb-export`)")
	cmd.Flags().StringVar(&genesisID, "utb-genesis-id", "", "the pinned EntryID of the UTB genesis entry (0x-prefixed): the export is checked against it")
	cmd.Flags().StringVar(&archiveDir, "archive", "", "the shard node's archive directory")
	cmd.Flags().StringVar(&shardStatus, "shard-status", "", "the shard node's status server base URL (adds the archive frontier pins)")
	cmd.Flags().StringVar(&ethRPC, "eth-rpc", "", "the execution client's RPC (records its head, and refuses an export when it lacks the archive tip's block)")
	cmd.Flags().StringVar(&out, "out", "seed", "the seed directory to write")
	_ = cmd.MarkFlagRequired("utb-genesis-id")
	_ = cmd.MarkFlagRequired("archive")
	return cmd
}

// urethRef asks the execution client for the archive tip's block (by number, then compares its hash) and for its head.
func urethRef(ctx context.Context, endpoint string, height uint64, hash string) (*seed.UrethRef, error) {
	c, err := rpc.DialContext(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	var at struct {
		Hash string `json:"hash"`
	}
	if err := c.CallContext(ctx, &at, "eth_getBlockByNumber", hexutil.EncodeUint64(height), false); err != nil {
		return nil, err
	}
	if !strings.EqualFold(at.Hash, hash) {
		return nil, fmt.Errorf("block %d is %s, the certified archive tip says %s", height, at.Hash, hash)
	}
	var head struct {
		Number hexutil.Uint64 `json:"number"`
		Hash   string         `json:"hash"`
	}
	if err := c.CallContext(ctx, &head, "eth_getBlockByNumber", "latest", false); err != nil {
		return nil, err
	}
	return &seed.UrethRef{HeadNumber: uint64(head.Number), HeadHash: head.Hash, Mode: "engine-resync"}, nil
}

func seedServeCmd() *cobra.Command {
	var dir, listen, genesisID string
	var allowNonLoopback bool
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve a seed directory read-only over HTTP (off unless run; loopback unless --listen says otherwise)",
		Long: "GET and HEAD of manifest.json and the three payload files, nothing else. The seed is public data that every importer verifies, so the server holds no " +
			"secret; bind a non-loopback address only deliberately (--allow-non-loopback), or give the directory to a web server of your choice.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			host, _, err := net.SplitHostPort(listen)
			if err != nil {
				return fmt.Errorf("--listen: %w", err)
			}
			if ip := net.ParseIP(host); (ip == nil || !ip.IsLoopback()) && host != "localhost" && !allowNonLoopback {
				return fmt.Errorf("--listen %s is not loopback: pass --allow-non-loopback to serve the seed on that address", listen)
			}
			if genesisID != "" { // verify what is about to be served
				pin, err := seed.ParseGenesisID(genesisID)
				if err != nil {
					return err
				}
				v, err := seed.VerifyDir(dir, seed.Pins{GenesisID: pin})
				if err != nil {
					return fmt.Errorf("refusing to serve a seed that does not verify: %w", err)
				}
				fmt.Fprintln(cmd.ErrOrStderr(), "verified:", v.Summary())
			} else if _, err := seed.DecodeManifestFile(dir); err != nil {
				return err
			}
			srv := &http.Server{Addr: listen, Handler: seed.Handler(dir), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
				WriteTimeout: 10 * time.Minute, IdleTimeout: 30 * time.Second}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			go func() {
				<-ctx.Done()
				sctx, c := context.WithTimeout(context.Background(), 5*time.Second)
				defer c()
				_ = srv.Shutdown(sctx)
			}()
			fmt.Fprintf(cmd.ErrOrStderr(), "serving %s read-only on http://%s\n", dir, listen)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		}}
	cmd.Flags().StringVar(&dir, "dir", "seed", "the seed directory (from `seed export` or `seed fetch`)")
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:8480", "the address to serve on")
	cmd.Flags().BoolVar(&allowNonLoopback, "allow-non-loopback", false, "allow a non-loopback --listen address")
	cmd.Flags().StringVar(&genesisID, "utb-genesis-id", "", "verify the directory against this pinned genesis EntryID before serving")
	return cmd
}

type seedPinFlags struct {
	genesisID, shardConf string
	minEpoch             uint64
}

func (f *seedPinFlags) add(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.genesisID, "utb-genesis-id", "", "the pinned EntryID of the UTB genesis entry (0x-prefixed): the only trust anchor of the seed")
	cmd.Flags().StringVar(&f.shardConf, "full-shard-conf", "", "this node's own shard configuration: the checkpoint must be of its partition and shard")
	cmd.Flags().Uint64Var(&f.minEpoch, "min-epoch", 0, "refuse a seed whose trust-base history ends before this epoch")
	_ = cmd.MarkFlagRequired("utb-genesis-id")
}

func (f *seedPinFlags) pins() (seed.Pins, error) {
	pin, err := seed.ParseGenesisID(f.genesisID)
	if err != nil {
		return seed.Pins{}, err
	}
	p := seed.Pins{GenesisID: pin, MinTipEpoch: f.minEpoch}
	if f.shardConf != "" {
		pdr, err := util.ReadJsonFile(f.shardConf, &types.PartitionDescriptionRecord{})
		if err != nil {
			return seed.Pins{}, fmt.Errorf("reading --full-shard-conf: %w", err)
		}
		p.Partition, p.Shard = &pdr.PartitionID, &pdr.ShardID
	}
	return p, nil
}

func seedFetchCmd() *cobra.Command {
	var from []string
	var out string
	var minSources int
	var pf seedPinFlags
	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch a seed from one or more sources, refuse on disagreement, verify it, write the verified directory",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pins, err := pf.pins()
			if err != nil {
				return err
			}
			if len(from) == 0 {
				return errors.New("--from is required")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Minute)
			defer cancel()
			got, err := seed.Fetch(ctx, from, seed.FetchOptions{Pins: pins, MinSources: minSources})
			if err != nil {
				return err
			}
			if err := writeVerifiedSeed(got.Verified, out); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), got.Summary())
			fmt.Fprintf(cmd.OutOrStdout(), "agreeing sources: %s\n", strings.Join(got.Sources, ", "))
			for _, u := range got.Unreachable {
				fmt.Fprintf(cmd.ErrOrStderr(), "unreachable: %s\n", u)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "written to %s; import it with `ubft seed import --dir %s`\n", out, out)
			return nil
		}}
	cmd.Flags().StringArrayVar(&from, "from", nil, "a seed source base URL (repeat for several: they are compared, and any disagreement refuses)")
	cmd.Flags().StringVar(&out, "out", "seed", "the directory to write the verified seed to")
	cmd.Flags().IntVar(&minSources, "min-sources", 1, "how many sources must answer with the same manifest")
	pf.add(cmd)
	return cmd
}

func writeVerifiedSeed(v *seed.Verified, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, n := range seed.PayloadFiles {
		if err := os.WriteFile(dir+"/"+n, v.Files[n], 0o644); err != nil {
			return err
		}
	}
	return os.WriteFile(dir+"/"+seed.ManifestName, v.ManifestRaw, 0o644) // last
}

func seedImportCmd(base *baseFlags) *cobra.Command {
	var dir, home, genesisFile, rootDB, shardDB string
	var sources []string
	var replace bool
	var pf seedPinFlags
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Verify a seed directory and place it in a validator home (the node then starts as a follower and catches up from its peers)",
		Long: "Verifies the directory exactly as `seed fetch` does (the directory is never trusted), writes <home>/seed/{manifest.json, payload, import.json}, and, when " +
			"--utb-genesis and --root-utb-db/--shard-utb-db are given, loads the verified trust-base history into those entry stores through the store's own authenticated " +
			"append. Archive records and the execution state are not in the seed: the follower fetches and replays them from its peers, authenticating each step.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pins, err := pf.pins()
			if err != nil {
				return err
			}
			v, err := seed.VerifyDir(dir, pins)
			if err != nil {
				return err
			}
			if genesisFile == "" && (rootDB != "" || shardDB != "") {
				return errors.New("--root-utb-db and --shard-utb-db need --utb-genesis")
			}
			rec, err := seed.Import(v, home, sources, replace, time.Now())
			if err != nil {
				return err
			}
			for _, db := range []struct{ path, def string }{{rootDB, rootUTBEntriesDBFileName}, {shardDB, shardUTBEntriesDBFileName}} {
				if db.path == "" {
					continue
				}
				store, closeStore, err := openUTBEntryStore(base, genesisFile, pf.genesisID, db.path, db.def, nil)
				if err != nil {
					return err
				}
				added, err := gettrustbase.InstallBundle(store, v.Bundle)
				tip := store.Tip().Epoch
				closeStore()
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s: added %d trust-base entries; tip epoch %d\n", db.path, added, tip)
			}
			fmt.Fprintln(cmd.OutOrStdout(), v.Summary())
			fmt.Fprintf(cmd.OutOrStdout(), "imported into %s/seed (seed %s)\n", home, rec.ManifestDigest)
			fmt.Fprintf(cmd.OutOrStdout(), "next: start the root with --utb-genesis and the shard node with --follow-source; `ubft validator status` shows the catch-up\n")
			return nil
		}}
	cmd.Flags().StringVar(&dir, "dir", "seed", "the seed directory (from `seed fetch` or `seed export`)")
	cmd.Flags().StringVar(&home, "home", "", "the validator home to import into")
	cmd.Flags().StringArrayVar(&sources, "source", nil, "where the seed came from (recorded for `validator status`)")
	cmd.Flags().BoolVar(&replace, "replace", false, "replace an earlier import")
	cmd.Flags().StringVar(&genesisFile, "utb-genesis", "", "the canonical UTB genesis entry file (to load the history into entry stores)")
	cmd.Flags().StringVar(&rootDB, "root-utb-db", "", "the root's UTB entries database to load the history into")
	cmd.Flags().StringVar(&shardDB, "shard-utb-db", "", "the shard node's UTB entries database to load the history into")
	_ = cmd.MarkFlagRequired("home")
	pf.add(cmd)
	return cmd
}

// seedPinEpochCmd prints the root epoch of a verified seed's checkpoint (for scripts that restore from the seed's pin).
func seedPinEpochCmd() *cobra.Command {
	var dir, genesisID string
	cmd := &cobra.Command{Use: "pin-epoch", Short: "Verify a seed directory and print the root epoch of its checkpoint", Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pin, err := seed.ParseGenesisID(genesisID)
			if err != nil {
				return err
			}
			v, err := seed.VerifyDir(dir, seed.Pins{GenesisID: pin})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), v.Manifest.Checkpoint.RootEpoch)
			return err
		}}
	cmd.Flags().StringVar(&dir, "dir", "seed", "the seed directory")
	cmd.Flags().StringVar(&genesisID, "utb-genesis-id", "", "the pinned genesis EntryID")
	_ = cmd.MarkFlagRequired("utb-genesis-id")
	return cmd
}
