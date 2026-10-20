// utb-evidence is the independent side of the combined UTB lane (briefs/utb-signed-entries-design.md §11.4): it reads the signed trust-base history the way a
// client does (from the aggregator's HTTP range, or from a file), authenticates it from the pinned genesis with the shared strict verifier, and prints what it
// checked. It trusts no node: a root's log saying "signed" is not evidence, the numbers printed here are.
//
//	utb-evidence fetch    --url U --out FILE                       the complete history as one tagged bundle (pages followed to the end)
//	utb-evidence verify   --bundle FILE --pin 0x..                 every record verified from its predecessor; one line per record
//	utb-evidence extract  --bundle FILE --epoch N --out FILE       the canonical signed bytes of one record
//	utb-evidence client   --url U --store DB --genesis FILE --pin 0x..   a reference client with its own durable store: syncs the missing suffix
//	utb-evidence ucresp   --file FILE --entry FILE                 a captured version 2 certification response whose attachment is exactly the entry
//	utb-evidence uc-verify --token FILE --bundle FILE [--shard-conf FILE]  every certificate in a saved token verified under its own epoch's committee
package main

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/gettrustbase"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/keyvaluedb/boltdb"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/utbstore"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: utb-evidence fetch|verify|extract|client|ucresp|uc-verify ...")
	}
	var err error
	switch os.Args[1] {
	case "fetch":
		err = cmdFetch(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "extract":
		err = cmdExtract(os.Args[2:])
	case "client":
		err = cmdClient(os.Args[2:])
	case "ucresp":
		err = cmdUCResp(os.Args[2:])
	case "uc-verify":
		err = cmdUCVerify(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) { fmt.Fprintln(os.Stderr, "utb-evidence: "+msg); os.Exit(1) }

func parsePin(s string) ([32]byte, error) {
	var pin [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
	if err != nil || len(b) != 32 {
		return pin, fmt.Errorf("the pin %q is not a 0x-prefixed 32-byte hex string", s)
	}
	copy(pin[:], b)
	return pin, nil
}

// fetchRange reads the aggregator's history from epoch `from` to its tip, following the cursor with a frozen snapshot, and returns the canonical bytes.
func fetchRange(base string, from uint64) ([][]byte, error) {
	var raw [][]byte
	var snapEnd uint64
	var snapID []byte
	httpc := &http.Client{Timeout: 15 * time.Second}
	for page := 0; page < 10000; page++ {
		q := url.Values{"from": {fmt.Sprint(from)}}
		if snapID != nil {
			q.Set("snapshotEnd", fmt.Sprint(snapEnd))
			q.Set("snapshotEntryId", "0x"+hex.EncodeToString(snapID))
		}
		resp, err := httpc.Get(base + "?" + q.Encode())
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("GET %s: HTTP %d: %s", base, resp.StatusCode, strings.TrimSpace(string(body)))
		}
		r, _, err := gettrustbase.DecodeResponse(body, gettrustbase.PageLimits)
		if err != nil {
			return nil, fmt.Errorf("page %d: %w", page, err)
		}
		if r.Status != gettrustbase.StatusOK {
			if r.Status == gettrustbase.StatusNotYetAvailable && len(raw) == 0 {
				return nil, nil // the server holds nothing at or after `from`
			}
			return nil, fmt.Errorf("page %d: status %s", page, r.Status)
		}
		for _, e := range r.Entries {
			raw = append(raw, bytes.Clone(e))
		}
		if r.NextEpoch == nil {
			return raw, nil
		}
		from, snapEnd, snapID = *r.NextEpoch, r.EffectiveEnd, r.EndEntryID
	}
	return nil, errors.New("too many pages")
}

func cmdFetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	u := fs.String("url", "", "the aggregator's history range endpoint")
	out := fs.String("out", "", "bundle file")
	_ = fs.Parse(args)
	if *u == "" || *out == "" {
		return errors.New("fetch needs --url and --out")
	}
	raw, err := fetchRange(*u, 1)
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		return errors.New("the endpoint returned no entries")
	}
	bundle, err := gettrustbase.EncodeBundle(raw)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, bundle, 0o644); err != nil {
		return err
	}
	b, _ := gettrustbase.DecodeBundle(bundle, gettrustbase.BundleLimits{MaxBytes: len(bundle), MaxEntries: len(raw)})
	fmt.Printf("fetched %d entries: epochs %d..%d (%d bytes)\n", len(raw), b.Entries[0].Epoch, b.Tip().Epoch, len(bundle))
	return nil
}

func readBundle(path string) (*gettrustbase.Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return gettrustbase.DecodeBundle(data, gettrustbase.BundleLimits{MaxBytes: len(data), MaxEntries: len(data)/16 + 1})
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	path := fs.String("bundle", "", "bundle file")
	pinS := fs.String("pin", "", "the genesis EntryID")
	_ = fs.Parse(args)
	pin, err := parsePin(*pinS)
	if err != nil {
		return err
	}
	b, err := readBundle(*path)
	if err != nil {
		return err
	}
	if err := gettrustbase.VerifyBundle(b, pin); err != nil {
		return err
	}
	gid, _ := b.Entries[0].EntryID()
	fmt.Printf("genesis epoch %d entryId 0x%x (the pin)\n", b.Entries[0].Epoch, gid)
	for i := 1; i < len(b.Entries); i++ {
		e, prev := b.Entries[i], b.Entries[i-1]
		id, _ := e.EntryID()
		pid, _ := prev.EntryID()
		var ids []string
		for id := range e.Signatures {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		weights := map[string]uint64{}
		var total uint64
		for _, m := range prev.RootNodes {
			weights[m.NodeID] = m.Stake
			total += m.Stake
		}
		var signed uint64
		for _, id := range ids {
			signed += weights[id]
		}
		fmt.Printf("epoch %d entryId 0x%x predecessor-epoch %d predecessor-entryId 0x%x start %d members %d signers %d signed-weight %d total-weight %d threshold %d ok\n",
			e.Epoch, id, prev.Epoch, pid, e.EpochStart, len(e.RootNodes), len(ids), signed, total, prev.QuorumThreshold)
	}
	tid, _ := b.Tip().EntryID()
	fmt.Printf("ok: epochs %d..%d, tip 0x%x\n", b.Entries[0].Epoch, b.Tip().Epoch, tid)
	return nil
}

func cmdExtract(args []string) error {
	fs := flag.NewFlagSet("extract", flag.ExitOnError)
	path := fs.String("bundle", "", "bundle file")
	epoch := fs.Uint64("epoch", 0, "epoch")
	out := fs.String("out", "", "output file")
	_ = fs.Parse(args)
	b, err := readBundle(*path)
	if err != nil {
		return err
	}
	for i, e := range b.Entries {
		if e.Epoch == *epoch {
			return os.WriteFile(*out, b.Raw[i], 0o644)
		}
	}
	return fmt.Errorf("the bundle holds no epoch %d", *epoch)
}

func cmdClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	u := fs.String("url", "", "the aggregator's history range endpoint")
	storePath := fs.String("store", "", "the client's own durable store")
	genesisPath := fs.String("genesis", "", "the genesis entry file")
	pinS := fs.String("pin", "", "the genesis EntryID")
	export := fs.String("export", "", "write the client's complete history here as a tagged bundle")
	_ = fs.Parse(args)
	pin, err := parsePin(*pinS)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*genesisPath)
	if err != nil {
		return err
	}
	genesis, err := types.DecodeRootTrustBaseV2(raw)
	if err != nil {
		return err
	}
	db, err := boltdb.New(*storePath)
	if err != nil {
		return err
	}
	defer db.Close()
	store, err := utbstore.Open(db, genesis, pin)
	if err != nil {
		return err
	}
	before := store.Tip().Epoch
	var entries [][]byte
	if *u != "" { // an empty URL only exports what the client holds
		if entries, err = fetchRange(*u, before+1); err != nil {
			return err
		}
	}
	var added []uint64
	for _, e := range entries {
		isNew, err := store.Append(e)
		if err != nil {
			return fmt.Errorf("an entry of the server did not authenticate from the client's tip: %w", err)
		}
		if isNew {
			d, _ := types.DecodeRootTrustBaseV2(e)
			added = append(added, d.Epoch)
		}
	}
	id := store.Tip()
	fmt.Printf("client: tip before %d, appended %v, tip now %d entryId 0x%x\n", before, added, id.Epoch, id.EntryID)
	if *export != "" {
		bundle, err := gettrustbase.ExportStore(store)
		if err != nil {
			return err
		}
		return os.WriteFile(*export, bundle, 0o644)
	}
	return nil
}

func cmdUCResp(args []string) error {
	fs := flag.NewFlagSet("ucresp", flag.ExitOnError)
	file := fs.String("file", "", "a captured version 3 response")
	entry := fs.String("entry", "", "the entry file the attachment must equal")
	_ = fs.Parse(args)
	raw, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	want, err := os.ReadFile(*entry)
	if err != nil {
		return err
	}
	var v2 certification.CertificationResponseV3
	if err := types.Cbor.Unmarshal(raw, &v2); err != nil {
		return fmt.Errorf("not a version 3 certification response: %w", err)
	}
	if err := v2.IsValid(); err != nil {
		return err
	}
	for i, u := range v2.TrustBaseUpdates {
		if bytes.Equal(u, want) {
			e, _ := types.DecodeRootTrustBaseV2(u)
			fmt.Printf("ok: the response (partition %d, status %d, UC epoch %d) attaches the entry of epoch %d at position %d byte for byte\n",
				v2.Response.Partition, v2.Response.Status, sealEpoch(&v2.Response.UC), e.Epoch, i)
			return nil
		}
	}
	return fmt.Errorf("none of the %d attachments equals %s", len(v2.TrustBaseUpdates), *entry)
}

func sealEpoch(uc *types.UnicityCertificate) uint64 {
	if uc.UnicitySeal == nil {
		return 0
	}
	return uc.UnicitySeal.Epoch
}

// findUCs walks a CBOR value and returns every certificate in it, whether tagged in place or carried as a byte string.
func findUCs(v any, out *[]types.UnicityCertificate) {
	switch x := v.(type) {
	case cbor.Tag:
		if x.Number == types.UnicityCertificateTag {
			enc, err := types.Cbor.MarshalTaggedValue(x.Number, x.Content)
			if err == nil {
				var uc types.UnicityCertificate
				if types.Cbor.Unmarshal(enc, &uc) == nil && uc.UnicitySeal != nil {
					*out = append(*out, uc)
					return
				}
			}
		}
		findUCs(x.Content, out)
	case []any:
		for _, e := range x {
			findUCs(e, out)
		}
	case map[any]any:
		for _, e := range x {
			findUCs(e, out)
		}
	case []byte:
		if len(x) > 16 && x[0] == 0xd9 && x[1] == 0x98 && x[2] == 0x59 {
			var uc types.UnicityCertificate
			if types.Cbor.Unmarshal(x, &uc) == nil && uc.UnicitySeal != nil {
				*out = append(*out, uc)
				return
			}
		}
		if len(x) > 16 && len(x) < 1<<20 {
			var inner any
			if cbor.Unmarshal(x, &inner) == nil {
				findUCs(inner, out)
			}
		}
	}
}

func cmdUCVerify(args []string) error {
	fs := flag.NewFlagSet("uc-verify", flag.ExitOnError)
	tokenPath := fs.String("token", "", "a saved token (or any CBOR holding certificates)")
	bundlePath := fs.String("bundle", "", "the signed trust-base history")
	confPath := fs.String("shard-conf", "", "the partition description of the certified shard (its hash binds the certificate); a token can hold certificates of several shards: a comma-separated list, each certificate takes the description of its own partition")
	_ = fs.Parse(args)
	b, err := readBundle(*bundlePath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*tokenPath)
	if err != nil {
		return err
	}
	var tree any
	dm, _ := cbor.DecOptions{DefaultMapType: nil, IntDec: cbor.IntDecConvertNone}.DecMode()
	if err := dm.Unmarshal(raw, &tree); err != nil {
		return fmt.Errorf("%s is not CBOR: %w", *tokenPath, err)
	}
	var ucs []types.UnicityCertificate
	findUCs(tree, &ucs)
	if len(ucs) == 0 {
		return errors.New("no unicity certificate found in the token")
	}
	var pdrs []*types.PartitionDescriptionRecord
	var hashes [][]byte
	for _, path := range strings.Split(*confPath, ",") {
		if path == "" {
			continue
		}
		c, err := readPDR(path)
		if err != nil {
			return err
		}
		h, err := c.Hash(crypto.SHA256)
		if err != nil {
			return err
		}
		pdrs, hashes = append(pdrs, c), append(hashes, h)
	}
	for i := range ucs {
		uc := &ucs[i]
		epoch := uc.UnicitySeal.Epoch
		var e *types.RootTrustBaseV2
		var next *types.RootTrustBaseV2
		for j, cand := range b.Entries {
			if cand.Epoch == epoch {
				e = cand
				if j+1 < len(b.Entries) {
					next = b.Entries[j+1]
				}
			}
		}
		if e == nil {
			return fmt.Errorf("certificate %d is of epoch %d, which the history does not hold", i, epoch)
		}
		round := uc.UnicitySeal.RootChainRoundNumber
		if round < e.EpochStart || (next != nil && round >= next.EpochStart) {
			return fmt.Errorf("certificate %d: seal round %d is outside the activation interval of epoch %d", i, round, epoch)
		}
		var partition types.PartitionID
		var shard types.ShardID
		var confHash []byte
		if uc.UnicityTreeCertificate != nil {
			partition = uc.UnicityTreeCertificate.Partition
		}
		if len(pdrs) > 0 {
			k := -1
			for j, c := range pdrs {
				if len(pdrs) == 1 || c.PartitionID == partition {
					k = j
				}
			}
			if k < 0 {
				return fmt.Errorf("certificate %d is of partition %d, for which no shard configuration was given", i, partition)
			}
			partition, shard, confHash = pdrs[k].PartitionID, pdrs[k].ShardID, hashes[k]
		}
		if err := uc.Verify(quorumweight.Checked(e), crypto.SHA256, partition, shard, confHash); err != nil {
			return fmt.Errorf("certificate %d (epoch %d, seal round %d) does not verify under its epoch's committee: %w", i, epoch, round, err)
		}
		var signed uint64
		for _, m := range e.RootNodes {
			if _, ok := uc.UnicitySeal.Signatures[m.NodeID]; ok {
				signed += m.Stake
			}
		}
		id, _ := e.EntryID()
		fmt.Printf("certificate %d: epoch %d seal round %d verified under entry 0x%x: signers %d signed-weight %d threshold %d, activation interval ok\n",
			i, epoch, round, id, len(uc.UnicitySeal.Signatures), signed, e.QuorumThreshold)
	}
	return nil
}

func readPDR(path string) (*types.PartitionDescriptionRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p types.PartitionDescriptionRecord
	if err := jsonUnmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
