// Command tokenvec gives a projection outside Go (the nbp TS/Rust plug-ins) the two halves of the token-level harness
// (b1ref/tokenvec): it certifies anchors over the harness registry with the projection's own state roots, and it runs the Go
// reference (b1ref.Cert) on the CERT_BATCH_V2 request the projection built.
//
//	tokenvec certify -spec spec.json            # writes the certified anchors and the registry, as JSON, to stdout
//	tokenvec verify  -registry certified.json -request <hex>
//	tokenvec scenarios                          # the fixed scenarios of package tokenvec, as specs
//
// spec.json: {"depth": d, "depthByEpoch": {"6": 2}, "anchors": [{"epoch": e, "round": r, "shard": "01", "stateRoot": "<hex32>"}]}.
// The registry is b1gen.History (epochs 0..8, O = 1,000,000); shards of epoch e have depthByEpoch[e], else depth, bits.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-core/b1ref/b1gen"
	"github.com/unicitynetwork/bft-core/b1ref/tokenvec"
)

type anchorSpec struct {
	Epoch     uint64 `json:"epoch"`
	Round     uint64 `json:"round"`
	Shard     string `json:"shard"`
	StateRoot string `json:"stateRoot"`
}

type spec struct {
	ID           string         `json:"id,omitempty"`
	Depth        int            `json:"depth"`
	DepthByEpoch map[string]int `json:"depthByEpoch,omitempty"`
	Anchors      []anchorSpec   `json:"anchors"`
	Want         *tokenvec.Want `json:"want,omitempty"`
}

type anchorOut struct {
	Spec      anchorSpec `json:"spec"`
	Partition uint32     `json:"partition"`
	Claim     string     `json:"claim"`
	UC        string     `json:"uc"`
	IR        string     `json:"inputRecord"`
	IRHash    string     `json:"expectedIRHash"`
	ShardConf string     `json:"shardConfHash"`
	IRTime    uint64     `json:"irTime"`
}

type certified struct {
	Seed     string          `json:"seed"`
	Registry *b1gen.PreState `json:"registry"`
	Anchors  []anchorOut     `json:"anchors"`
}

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("usage: tokenvec certify|verify|scenarios"))
	}
	var err error
	switch os.Args[1] {
	case "certify":
		err = certify(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "scenarios":
		err = scenarios()
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "tokenvec:", err)
	os.Exit(2)
}

func emit(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func (s spec) depthOf(e uint64) int {
	if d, ok := s.DepthByEpoch[strconv.FormatUint(e, 10)]; ok {
		return d
	}
	return s.Depth
}

func certify(args []string) error {
	fs := flag.NewFlagSet("certify", flag.ContinueOnError)
	path := fs.String("spec", "", "spec JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	var s spec
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	out, err := certifySpec(s)
	if err != nil {
		return err
	}
	return emit(out)
}

// certifySpec signs a spec's anchors over the harness registry.
func certifySpec(s spec) (*certified, error) {
	specs := make([]b1gen.AnchorSpec, len(s.Anchors))
	for i, a := range s.Anchors {
		root, err := hex.DecodeString(a.StateRoot)
		if err != nil || len(root) != 32 {
			return nil, fmt.Errorf("anchor %d: stateRoot must be 32 bytes of hex", i)
		}
		specs[i] = b1gen.AnchorSpec{Epoch: a.Epoch, Round: a.Round, Shard: a.Shard}
		copy(specs[i].StateRoot[:], root)
	}
	w := b1gen.NewTokenWorld(tokenvec.Seed, s.depthOf)
	anchors, err := w.Certify(specs)
	if err != nil {
		return nil, err
	}
	pre := w.Pre()
	out := certified{Seed: tokenvec.Seed, Registry: &pre}
	for i, a := range anchors {
		irHash := sha256hex(a.IR)
		out.Anchors = append(out.Anchors, anchorOut{Spec: s.Anchors[i], Partition: a.Partition, Claim: hex.EncodeToString(a.Claim),
			UC: hex.EncodeToString(a.UC), IR: hex.EncodeToString(a.IR), IRHash: irHash, ShardConf: hex.EncodeToString(a.ShardConf[:]),
			IRTime: b1gen.IRTime(a.Spec.Round)})
	}
	return &out, nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	regPath := fs.String("registry", "", "the certify output")
	reqHex := fs.String("request", "", "CERT_BATCH_V2 request, hex")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := os.ReadFile(*regPath)
	if err != nil {
		return err
	}
	var c certified
	if err := json.Unmarshal(raw, &c); err != nil {
		return err
	}
	req, err := hex.DecodeString(*reqHex)
	if err != nil {
		return err
	}
	return emit(verifyRequest(&c, req))
}

// result is what verify reports.
type result struct {
	Status   string          `json:"status"` // ok, halt or registry
	Valid    bool            `json:"valid"`
	Why      string          `json:"why,omitempty"`
	Gas      uint64          `json:"gas,omitempty"`
	Grouping *b1ref.Grouping `json:"grouping,omitempty"`
}

// verifyRequest runs the reference on a request against a certify output's registry.
func verifyRequest(c *certified, req []byte) result {
	st := b1ref.Words{}
	for _, sw := range c.Registry.Storage {
		st[word(sw.Slot)] = word(sw.Value)
	}
	pins := b1ref.Pins{GenesisCommitment: word(c.Registry.PinnedGenesisCommitment), ProfileHash: word(c.Registry.PinnedProfileHash)}
	r := result{Status: "ok"}
	if g, err := b1ref.Group(req); err == nil {
		r.Grouping = &g
	}
	v, err := b1ref.Cert(req, st, pins)
	switch {
	case errors.Is(err, b1ref.ErrInfrastructure):
		r.Status, r.Why = "registry", err.Error()
	case err != nil:
		r.Status, r.Why = "halt", err.Error()
	default:
		r.Valid, r.Gas = v.Valid, v.Gas
		if v.Why != nil {
			r.Why = v.Why.Error()
		}
	}
	return r
}

func scenarios() error {
	var out []spec
	for _, s := range tokenvec.Scenarios {
		sp := spec{ID: s.ID, Depth: s.Depth(0), DepthByEpoch: map[string]int{}}
		for e := uint64(0); e <= b1gen.HistoryOrigin; e++ {
			if d := s.Depth(e); d != sp.Depth {
				sp.DepthByEpoch[strconv.FormatUint(e, 10)] = d
			}
		}
		for _, a := range s.Anchors {
			sp.Anchors = append(sp.Anchors, anchorSpec{Epoch: a.Epoch, Round: a.Round, Shard: a.Shard, StateRoot: "<your RSMT root>"})
		}
		w := s.Want
		sp.Want = &w
		out = append(out, sp)
	}
	return emit(out)
}

func word(s string) (w [32]byte) {
	b, _ := hex.DecodeString(s)
	copy(w[:], b)
	return
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
