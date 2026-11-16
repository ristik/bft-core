// Command dnb-tool holds the operator tools of the bridge deployment that stay with native bridge v2 (docs/design/native-bridge-v2.md):
//
//	dnb-tool trust-bundle --trust-base trust-base.json --out trust-base.bundle.cbor --out-pin genesis-entry-id.hex
//	dnb-tool b1check --request req.bin --trust-base trust-base.json --profile b1-profile.json --clock N
//
// The protocol 6/7 commands (deployment, pdr, lockproof, lockproof-serve) were removed with that bridge (bft-core#1106).
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/utb"
	"github.com/unicitynetwork/bft-go-base/types"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dnb-tool trust-bundle|b1check ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "trust-bundle":
		err = trustBundle(os.Args[2:])
	case "b1check":
		err = b1check(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "dnb-tool:", err)
		os.Exit(1)
	}
}

// trustBundle writes the release bundle of the deployment's trust-base history at its genesis (the entry a root is started with,
// ubft trust-base utb-genesis) and its genesis EntryID: the trust input of native bridge v2 (Γ.rootGenesis32 and the wallets' trust input,
// deploy/testnet/bridge/nb2/deploy_nb2.py) and its pin. The bundle holds the genesis only: past a root epoch change give the wallet the
// exported history (ubft trust-base utb-export) instead; its pin is unchanged. The bundle is checked to install under its pin with the
// installation budget of a release bundle (trustBundleLimits, as nb2ref.LoadTrustInput).
func trustBundle(args []string) error {
	fs := flag.NewFlagSet("trust-bundle", flag.ContinueOnError)
	in := fs.String("trust-base", "", "the genesis (epoch 1) trust base JSON")
	out := fs.String("out", "", "where to write the release bundle")
	outPin := fs.String("out-pin", "", "where to write the genesis EntryID (hex)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	var tb types.RootTrustBaseV1
	if err := json.Unmarshal(raw, &tb); err != nil {
		return err
	}
	genesis, err := utb.BuildUnsigned(nil, utb.FromProjection(&tb))
	if err != nil {
		return err
	}
	enc, err := types.Cbor.Marshal(genesis)
	if err != nil {
		return err
	}
	bundle, err := types.EncodeTrustBaseBundle([][]byte{enc})
	if err != nil {
		return err
	}
	id, err := genesis.EntryID()
	if err != nil {
		return err
	}
	if err := checkTrustBundle(bundle, id); err != nil {
		return fmt.Errorf("the bundle is not a loadable trust input: %w", err)
	}
	if err := os.WriteFile(*out, bundle, 0o644); err != nil { // #nosec G306 -- public configuration
		return err
	}
	return os.WriteFile(*outPin, []byte(hex.EncodeToString(id[:])+"\n"), 0o644) // #nosec G306 -- public configuration
}

// trustBundleLimits is the installation budget of a release bundle (nb2ref's trustBundleLimits).
var trustBundleLimits = types.TrustBaseLimits{MaxBytes: 1 << 20, MaxEntries: 1 << 16}

// checkTrustBundle is the installation check of nb2ref.LoadTrustInput: the bundle decodes within the budget, its genesis is the pin, and the
// history verifies from it.
func checkTrustBundle(bundle []byte, pin [32]byte) error {
	b, err := types.DecodeTrustBaseBundle(bundle, trustBundleLimits)
	if err != nil {
		return err
	}
	if id, err := b.Entries[0].EntryID(); err != nil || id != pin {
		return fmt.Errorf("the bundle's genesis EntryID is not the pin")
	}
	return types.VerifyTrustBaseBundle(b, pin)
}

// b1check evaluates a CERT_BATCH_V2 request with the Go reference verifier (b1ref) against a format-2 registry holding the deployment's genesis
// authority, at a given registry clock: the first place to look when the native call answers false. A v1 request (same claim layout) is read
// as v2.
func b1check(args []string) error {
	fs := flag.NewFlagSet("b1check", flag.ContinueOnError)
	req := fs.String("request", "", "CERT_BATCH_V2 (or v1) request bytes")
	tbPath := fs.String("trust-base", "", "root trust base")
	profPath := fs.String("profile", "", "b1 profile JSON (hex form)")
	clock := fs.Uint64("clock", 0, "registry clock.rootRound")
	if err := fs.Parse(args); err != nil {
		return err
	}
	in, err := os.ReadFile(*req)
	if err != nil {
		return err
	}
	rawTB, err := os.ReadFile(*tbPath)
	if err != nil {
		return err
	}
	var tb types.RootTrustBaseV1
	if err := json.Unmarshal(rawTB, &tb); err != nil {
		return err
	}
	rawProf, err := os.ReadFile(*profPath)
	if err != nil {
		return err
	}
	var pf struct {
		Network uint16
	}
	if err := json.Unmarshal(rawProf, &pf); err != nil {
		return err
	}
	h, err := q3format.NewHistory(&tb)
	if err != nil {
		return err
	}
	first, err := h.ForEpoch(1)
	if err != nil {
		return err
	}
	entries, err := h.B1Entries(first.Start())
	if err != nil {
		return err
	}
	last := entries[len(entries)-1].Epoch
	model := b1ref.Model{GenesisCommitment: [32]byte{1}, ProfileHash: [32]byte{1}, Phase: 2, Network: pf.Network, GenesisEpoch: entries[0].Epoch,
		ImportedTip: last, OriginReady: true, Origin: last, RootRound: *clock, Epochs: entries}
	if len(in) > 0 && in[0] == 1 {
		in = append([]byte{2}, in[1:]...)
	}
	v, err := b1ref.Cert(in, model.Words(), b1ref.Pins{GenesisCommitment: model.GenesisCommitment, ProfileHash: model.ProfileHash})
	fmt.Printf("valid=%v why=%v err=%v gas=%d (epoch entry: start=%d members=%d)\n", v.Valid, v.Why, err, v.Gas, entries[0].Start, len(entries[0].Members))
	return nil
}
