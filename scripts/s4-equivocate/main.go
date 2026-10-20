// Command s4-equivocate is the harness of the S4 live slashing exercise (briefs/s4-live-slashing-brief.md): a harness-only signer that produces two
// native scheme 2 root votes of one key for one (voting epoch, voting round) with different statements, one of them committing (vote and seal
// signatures), and delivers each over the real root vote protocol (/ab/root-vote) to a chosen root.
//
//	s4-equivocate make --keys KEYS.json --network N --genesis 0x.. [--utb] --epoch E --round R [--timestamp T] [--commit-epoch E] --out DIR
//	    writes DIR/a.vote (non-committing), DIR/b.vote (committing) as the wire CBOR the roots decode, and DIR/statements.json: everything public about
//	    the two statements (the voter, key, epoch, round, the typed fields, the preimage and its digest, the signatures). The private key is read
//	    and never written.
//	s4-equivocate calldata --journal J.db... --network-word 0x.. --root-network N --genesis 0x.. --exposure 0x.. --out DIR
//	    from the merged journals: DIR/canonical.hex (the submitEvidence call the submitter sends) and the control variants a reviewer expects the contract to refuse:
//	    identical.hex (one statement twice), altered.hex (the committing statement's executed state changed after signing), sealstripped.hex (its seal signature
//	    removed), reordered.hex (the same pair in the other order: not refused before admission, a duplicate offence after it)
//	s4-equivocate send --keys KEYS.json --vote FILE --to /ip4/H/tcp/P/p2p/ID
//	    opens a libp2p host whose identity is the voter's authentication key (the voter's node id), dials the root and sends the vote on the root
//	    vote protocol. It does not change, bypass or disable anything in the root: the root receives an ordinary signed vote.
//
// The key file is the node's own keys.json (sigKey signs, authKey is the libp2p identity). Production code never reaches this tool.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/cli/ubft/cmd"
	testobs "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/keyvaluedb/boltdb"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-core/rootevidence"
)

// Params is what the two statements are made of. Network and Genesis are the live epoch's signing configuration (the candidate configuration of the
// lane: network, genesis); UTB selects the version 3 vote envelope of a UTB epoch.
type Params struct {
	Cfg     votesig.Config
	Author  string
	Epoch   uint64
	Round   uint64
	Parent  uint64 // 0: Round-1
	Time    uint64 // the proposal time both statements carry (0: the historical vote info form)
	CommitE uint64 // the committing statement's commit epoch (0: Epoch)
	CommitT uint64 // its commit timestamp (0: Time, else 1)
}

// BuildPair makes the non-committing and the committing statement of one slot. They differ in the executed state hash (and the committing one commits
// a state), so they are two different statements for the same (key, epoch, round): an equivocation.
func BuildPair(signer abcrypto.Signer, p Params) (nonCommitting, committing *abdrc.VoteMsg, err error) {
	if p.Cfg.Scheme != votesig.SchemeDomainBound {
		return nil, nil, fmt.Errorf("the harness signs scheme 2 votes only, got scheme %d", p.Cfg.Scheme)
	}
	if p.Round < 3 || p.Epoch == 0 {
		return nil, nil, errors.New("a voting round of at least 3 in an epoch of at least 1 is needed (the committing statement commits a round below it)")
	}
	parent := p.Parent
	if parent == 0 {
		parent = p.Round - 1
	}
	commitEpoch := p.CommitE
	if commitEpoch == 0 {
		commitEpoch = p.Epoch
	}
	commitTime := p.CommitT
	if commitTime == 0 {
		commitTime = p.Time
		if commitTime == 0 {
			commitTime = 1
		}
	}
	mk := func(tag string, commit bool) (*abdrc.VoteMsg, error) {
		exec := sha256.Sum256([]byte(fmt.Sprintf("s4-equivocation/%s/%d/%d/%s", tag, p.Epoch, p.Round, p.Author)))
		vi := votesig.VoteInfo{Epoch: p.Epoch, Round: p.Round, Parent: parent, Exec: exec, Timestamp: p.Time}
		vh, err := p.Cfg.VoteInfoHash(vi)
		if err != nil {
			return nil, err
		}
		seal := &types.UnicitySeal{Version: 1, PreviousHash: vh[:]}
		if commit {
			h := sha256.Sum256([]byte(fmt.Sprintf("s4-equivocation/commit/%d/%d/%s", p.Epoch, p.Round, p.Author)))
			seal = &types.UnicitySeal{Version: 1, NetworkID: types.NetworkID(p.Cfg.Network), PreviousHash: vh[:], RootChainRoundNumber: p.Round - 1,
				Epoch: commitEpoch, Timestamp: commitTime, Hash: h[:]}
		}
		v := &abdrc.VoteMsg{VoteInfo: &drctypes.RoundInfo{Version: 1, RoundNumber: p.Round, Epoch: p.Epoch, ParentRoundNumber: parent, CurrentRootHash: exec[:], Timestamp: p.Time},
			LedgerCommitInfo: seal, Author: p.Author}
		if err := v.SignDomainBound(signer, p.Cfg); err != nil {
			return nil, err
		}
		if p.Cfg.UTB {
			v.Envelope = votesig.EnvelopeUTB
		}
		return v, nil
	}
	if nonCommitting, err = mk("a", false); err != nil {
		return nil, nil, err
	}
	if committing, err = mk("b", true); err != nil {
		return nil, nil, err
	}
	return nonCommitting, committing, nil
}

// Statement is the public description of one made vote.
type Statement struct {
	Committing      bool   `json:"committing"`
	Parent          uint64 `json:"parent"`
	Exec            string `json:"exec"`
	Timestamp       uint64 `json:"timestamp"`
	CommitHash      string `json:"commitHash,omitempty"`
	CommitRound     uint64 `json:"commitRound,omitempty"`
	CommitEpoch     uint64 `json:"commitEpoch,omitempty"`
	CommitTimestamp uint64 `json:"commitTimestamp,omitempty"`
	PV              string `json:"pv"`
	Digest          string `json:"digest"`
	Signature       string `json:"signature"`
	SealSignature   string `json:"sealSignature,omitempty"`
	Wire            string `json:"wireFile"`
}

// Description is statements.json: public only.
type Description struct {
	Author     string       `json:"author"`
	Epoch      uint64       `json:"epoch"`
	Round      uint64       `json:"round"`
	Network    uint64       `json:"network"`
	Genesis    string       `json:"genesis"`
	UTB        bool         `json:"utb"`
	Statements []*Statement `json:"statements"`
}

func describe(p Params, votes ...*abdrc.VoteMsg) (*Description, error) {
	d := &Description{Author: p.Author, Epoch: p.Epoch, Round: p.Round, Network: p.Cfg.Network, Genesis: "0x" + hex.EncodeToString(p.Cfg.Genesis[:]), UTB: p.Cfg.UTB}
	for i, v := range votes {
		pv, _, committing, err := drctypes.DomainBoundStatement(p.Cfg, v.VoteInfo, v.LedgerCommitInfo, len(v.SealSignature) != 0)
		if err != nil {
			return nil, err
		}
		dg := sha256.Sum256(pv)
		s := &Statement{Committing: committing, Parent: v.VoteInfo.ParentRoundNumber, Exec: hex.EncodeToString(v.VoteInfo.CurrentRootHash), Timestamp: v.VoteInfo.Timestamp,
			PV: hex.EncodeToString(pv), Digest: hex.EncodeToString(dg[:]), Signature: hex.EncodeToString(v.Signature), Wire: string(rune('a'+i)) + ".vote"}
		if committing {
			s.CommitHash, s.CommitRound, s.CommitEpoch, s.CommitTimestamp = hex.EncodeToString(v.LedgerCommitInfo.Hash), v.LedgerCommitInfo.RootChainRoundNumber, v.LedgerCommitInfo.Epoch, v.LedgerCommitInfo.Timestamp
			s.SealSignature = hex.EncodeToString(v.SealSignature)
		}
		d.Statements = append(d.Statements, s)
	}
	return d, nil
}

func readKeys(path string) (*cmd.KeyConf, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var k cmd.KeyConf
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &k, nil
}

func parseGenesis(s string) ([32]byte, error) {
	var g [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != 32 {
		return g, fmt.Errorf("the genesis must be 32 bytes of hex, got %q", s)
	}
	copy(g[:], b)
	return g, nil
}

func runMake(args []string) error {
	fs := flag.NewFlagSet("make", flag.ExitOnError)
	keys := fs.String("keys", "", "the voter's keys.json")
	network := fs.Uint64("network", 0, "the root network id N of the signing configuration")
	genesis := fs.String("genesis", "", "the root-chain genesis identity G (0x + 32 bytes)")
	utb := fs.Bool("utb", false, "the epoch is a UTB epoch: the votes carry the version 3 envelope")
	epoch := fs.Uint64("epoch", 0, "the voting epoch")
	round := fs.Uint64("round", 0, "the voting round")
	ts := fs.Uint64("timestamp", uint64(time.Now().Unix()), "the proposal time both statements carry")
	commitEpoch := fs.Uint64("commit-epoch", 0, "the committing statement's commit epoch (default: the voting epoch)")
	out := fs.String("out", "", "the output directory")
	_ = fs.Parse(args)
	if *keys == "" || *out == "" || *genesis == "" {
		return errors.New("make needs --keys, --genesis and --out")
	}
	k, err := readKeys(*keys)
	if err != nil {
		return err
	}
	signer, err := k.Signer()
	if err != nil {
		return err
	}
	id, err := k.NodeID()
	if err != nil {
		return err
	}
	g, err := parseGenesis(*genesis)
	if err != nil {
		return err
	}
	p := Params{Cfg: votesig.Config{Scheme: votesig.SchemeDomainBound, Network: *network, Genesis: g, UTB: *utb}, Author: id.String(), Epoch: *epoch, Round: *round, Time: *ts, CommitE: *commitEpoch}
	a, b, err := BuildPair(signer, p)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	for name, v := range map[string]*abdrc.VoteMsg{"a.vote": a, "b.vote": b} {
		raw, err := v.MarshalCBOR()
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(*out, name), raw, 0o644); err != nil {
			return err
		}
	}
	d, err := describe(p, a, b)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "statements.json"), append(raw, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("made two scheme 2 statements of %s for epoch %d round %d: %s (non-committing) and %s (committing)\n", id, *epoch, *round, d.Statements[0].Digest[:16], d.Statements[1].Digest[:16])
	return nil
}

type oneMsg struct{ msg any }

func (q *oneMsg) Len() int {
	if q.msg == nil {
		return 0
	}
	return 1
}

func (q *oneMsg) PopFront() any {
	m := q.msg
	q.msg = nil
	return m
}

// Send delivers one vote to a root over the root vote protocol from a host whose identity is the voter's authentication key.
func Send(ctx context.Context, k *cmd.KeyConf, vote *abdrc.VoteMsg, to peer.AddrInfo, timeout time.Duration) error {
	kp, err := k.AuthKeyPair()
	if err != nil {
		return err
	}
	conf, err := network.NewPeerConfiguration("/ip4/127.0.0.1/tcp/0", nil, kp, []peer.AddrInfo{to}, &network.BootstrapConnectRetry{Count: 5, Delay: 1})
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	host, err := network.NewPeer(ctx, conf, log, prometheus.NewRegistry())
	if err != nil {
		return err
	}
	defer host.Close()
	net, err := network.NewLibP2RootConsensusNetwork(host, 16, timeout, testobs.NOPObservability())
	if err != nil {
		return err
	}
	q := &oneMsg{msg: vote}
	sctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := net.SendMsgs(sctx, q, to.ID); err != nil {
		return err
	}
	// the stream is written and closed; give the receiver's handler the moment it needs to read the frame before this host (and the connection) goes away
	time.Sleep(time.Second)
	return nil
}

func runSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	keys := fs.String("keys", "", "the voter's keys.json")
	voteFile := fs.String("vote", "", "a vote written by make")
	to := fs.String("to", "", "the root's multiaddress with its peer id")
	_ = fs.Parse(args)
	if *keys == "" || *voteFile == "" || *to == "" {
		return errors.New("send needs --keys, --vote and --to")
	}
	k, err := readKeys(*keys)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*voteFile)
	if err != nil {
		return err
	}
	var v abdrc.VoteMsg
	if err := v.UnmarshalCBOR(raw); err != nil {
		return fmt.Errorf("%s is not a vote: %w", *voteFile, err)
	}
	ai, err := peer.AddrInfoFromString(*to)
	if err != nil {
		return err
	}
	if err := Send(context.Background(), k, &v, *ai, 15*time.Second); err != nil {
		return err
	}
	fmt.Printf("sent %s (epoch %d round %d, committing=%t) to %s\n", filepath.Base(*voteFile), v.VoteInfo.Epoch, v.VoteInfo.RoundNumber, len(v.SealSignature) != 0, ai.ID)
	return nil
}

const submitEvidenceABI = `[{"type":"function","name":"submitEvidence","stateMutability":"nonpayable","inputs":[
 {"name":"h","type":"tuple","components":[{"name":"network","type":"bytes32"},{"name":"domain","type":"uint8"},{"name":"key","type":"bytes"},{"name":"votingEpoch","type":"uint64"},{"name":"votingRound","type":"uint64"}]},
 {"name":"a","type":"tuple","components":[{"name":"parent","type":"uint64"},{"name":"exec","type":"bytes32"},{"name":"timestamp","type":"uint64"},{"name":"committing","type":"bool"},{"name":"commitHash","type":"bytes32"},{"name":"commitRound","type":"uint64"},{"name":"commitEpoch","type":"uint64"},{"name":"commitTimestamp","type":"uint64"},{"name":"signature","type":"bytes"},{"name":"sealSignature","type":"bytes"}]},
 {"name":"b","type":"tuple","components":[{"name":"parent","type":"uint64"},{"name":"exec","type":"bytes32"},{"name":"timestamp","type":"uint64"},{"name":"committing","type":"bool"},{"name":"commitHash","type":"bytes32"},{"name":"commitRound","type":"uint64"},{"name":"commitEpoch","type":"uint64"},{"name":"commitTimestamp","type":"uint64"},{"name":"signature","type":"bytes"},{"name":"sealSignature","type":"bytes"}]},
 {"name":"exposureID","type":"bytes32"}],"outputs":[{"name":"caseID","type":"bytes32"}]}]`

type evHeader struct {
	Network     [32]byte
	Domain      uint8
	Key         []byte
	VotingEpoch uint64
	VotingRound uint64
}

type evVote struct {
	Parent          uint64
	Exec            [32]byte
	Timestamp       uint64
	Committing      bool
	CommitHash      [32]byte
	CommitRound     uint64
	CommitEpoch     uint64
	CommitTimestamp uint64
	Signature       []byte
	SealSignature   []byte
}

// Variants returns the canonical submitEvidence call of the single paired slot of the journals and its controls, as hex (no 0x prefix) calldata.
func Variants(journals []*rootevidence.Journal, network [32]byte, cfg votesig.Config, exposure [32]byte) (map[string][]byte, error) {
	col, err := rootevidence.Collect(journals...)
	if err != nil {
		return nil, err
	}
	pairs := col.Pairs()
	if len(pairs) != 1 {
		return nil, fmt.Errorf("the journals hold %d offences, the exercise needs exactly one", len(pairs))
	}
	canonical, err := rootevidence.SubmitCalldata(network, cfg, pairs[0], exposure)
	if err != nil {
		return nil, err
	}
	parsed, err := abi.JSON(strings.NewReader(submitEvidenceABI))
	if err != nil {
		return nil, err
	}
	m := parsed.Methods["submitEvidence"]
	args, err := m.Inputs.Unpack(canonical[4:])
	if err != nil {
		return nil, err
	}
	h := *abi.ConvertType(args[0], new(evHeader)).(*evHeader)
	a := *abi.ConvertType(args[1], new(evVote)).(*evVote)
	b := *abi.ConvertType(args[2], new(evVote)).(*evVote)
	pack := func(h evHeader, a, b evVote) ([]byte, error) {
		raw, err := m.Inputs.Pack(h, a, b, exposure)
		if err != nil {
			return nil, err
		}
		return append(append([]byte{}, m.ID...), raw...), nil
	}
	out := map[string][]byte{"canonical": canonical}
	committing, other := &b, &a
	if a.Committing {
		committing, other = &a, &b
	}
	_ = other
	if out["identical"], err = pack(h, a, a); err != nil {
		return nil, err
	}
	if out["reordered"], err = pack(h, b, a); err != nil {
		return nil, err
	}
	alt := func(mut func(c *evVote)) ([]byte, error) {
		x, y := a, b
		if committing == &b {
			mut(&y)
		} else {
			mut(&x)
		}
		return pack(h, x, y)
	}
	if out["altered"], err = alt(func(c *evVote) { c.Exec[31] ^= 1 }); err != nil {
		return nil, err
	}
	if out["sealstripped"], err = alt(func(c *evVote) { c.SealSignature = nil }); err != nil {
		return nil, err
	}
	return out, nil
}

func openJournals(paths []string) ([]*rootevidence.Journal, func(), error) {
	var js []*rootevidence.Journal
	var closers []func()
	closeAll := func() {
		for _, c := range closers {
			c()
		}
	}
	for _, p := range paths {
		db, err := boltdb.New(p)
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("journal %q: %w", p, err)
		}
		closers = append(closers, func() { _ = db.Close() })
		j, err := rootevidence.NewJournal(db, 0)
		if err != nil {
			closeAll()
			return nil, nil, err
		}
		js = append(js, j)
	}
	return js, closeAll, nil
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func runCalldata(args []string) error {
	fs := flag.NewFlagSet("calldata", flag.ExitOnError)
	var journals listFlag
	fs.Var(&journals, "journal", "an observer journal copy (repeat)")
	netWord := fs.String("network-word", "", "the deployment's network word (0x + 32 bytes)")
	rootNetwork := fs.Uint64("root-network", 0, "the root network id N")
	genesis := fs.String("genesis", "", "the root-chain genesis identity G")
	exposure := fs.String("exposure", "", "the exposure id (0x + 32 bytes)")
	out := fs.String("out", "", "the output directory")
	_ = fs.Parse(args)
	if len(journals) == 0 || *out == "" || *netWord == "" || *genesis == "" || *exposure == "" {
		return errors.New("calldata needs --journal, --network-word, --genesis, --exposure and --out")
	}
	nw, err := parseGenesis(*netWord)
	if err != nil {
		return err
	}
	g, err := parseGenesis(*genesis)
	if err != nil {
		return err
	}
	ex, err := parseGenesis(*exposure)
	if err != nil {
		return err
	}
	js, closeAll, err := openJournals(journals)
	if err != nil {
		return err
	}
	defer closeAll()
	cfg := votesig.Config{Scheme: votesig.SchemeDomainBound, Network: *rootNetwork, Genesis: g}
	v, err := Variants(js, nw, cfg, ex)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	for name, data := range v {
		if err := os.WriteFile(filepath.Join(*out, name+".hex"), []byte("0x"+hex.EncodeToString(data)+"\n"), 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("wrote %d calldata files to %s\n", len(v), *out)
	return nil
}

func main() {
	var err error
	switch {
	case len(os.Args) >= 2 && os.Args[1] == "calldata":
		err = runCalldata(os.Args[2:])
	case len(os.Args) >= 2 && os.Args[1] == "make":
		err = runMake(os.Args[2:])
	case len(os.Args) >= 2 && os.Args[1] == "send":
		err = runSend(os.Args[2:])
	default:
		err = errors.New("usage: s4-equivocate make|send ...")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "s4-equivocate:", err)
		os.Exit(1)
	}
}
