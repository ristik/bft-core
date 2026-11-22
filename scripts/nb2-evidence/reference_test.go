package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/unicitynetwork/bft-core/nb2ref"
)

// The Γ the deployment encodes decodes under the build that admits its K, with the section 4.2 derivations.
func TestGammaBuildAndView(t *testing.T) {
	for _, kb := range [][2]uint64{{4, 2}, {8, 4}, {64, 16}} {
		c := &nb2ref.Config{Network: 3, ChainID: 31337, EVMPartition: 8, EVMShard: []byte{0x80}, AggregatorPartition: 7, K: kb[0], B: kb[1],
			Asset: nb2ref.AssetUCT, Qmax: new(big.Int).Exp(big.NewInt(10), big.NewInt(27), nil)}
		c.RootGenesis[0], c.ExecutionGenesis[0], c.Vault[19], c.Verifier[19], c.VerifierCodeHash[0] = 1, 2, 3, 4, 5
		c.Ty = nb2ref.DeriveType(c.Network, c.RootGenesis, c.ExecutionGenesis, c.ChainID)
		c.Aid = nb2ref.DeriveCoin(c.Network, c.RootGenesis, c.ExecutionGenesis, c.ChainID)
		raw := c.Bytes()
		want := nb2ref.BuildOf(kb[0])
		if got := buildOfGamma(raw); got != want {
			t.Fatalf("K=%d: build %s, want %s", kb[0], got, want)
		}
		d, err := nb2ref.DecodeConfig(raw, nb2ref.BuildParams(want))
		if err != nil {
			t.Fatal(err)
		}
		v := viewOf(d)
		if v.Gamma != hx(raw) || v.K != kb[0] || v.B != kb[1] || v.Build != want || v.Qmax != "1000000000000000000000000000" {
			t.Fatalf("view %+v", v)
		}
		if _, err := nb2ref.Construct(raw, nb2ref.Environment{Address: c.Vault, ChainID: 31337, VerifierCodeHash: c.VerifierCodeHash}, nb2ref.BuildParams(want)); err != nil {
			t.Fatalf("the vault constructor's rules refuse the encoded Γ: %v", err)
		}
	}
}

func TestGammaFlatFlag(t *testing.T) {
	args := []string{
		"-flat", "-network", "3", "-chain-id", "5587796",
		"-root-genesis", strings.Repeat("01", 32), "-execution-genesis", strings.Repeat("02", 32),
		"-vault", strings.Repeat("03", 20), "-verifier", strings.Repeat("04", 20),
		"-verifier-code-hash", strings.Repeat("05", 32), "-profile-hash", strings.Repeat("06", 32),
		"-qmax", "1000000000000000000000000000",
	}
	var out bytes.Buffer
	if err := gammaCmd(args, &out); err != nil {
		t.Fatal(err)
	}
	var view gammaJSON
	if err := json.Unmarshal(out.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(view.Gamma, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	flat, err := nb2ref.DecodeFlatConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	domain := flat.Domain()
	if view.Domain != hx(domain[:]) || flat.K != 64 || flat.B != 16 || flat.ChainID != 5587796 {
		t.Fatalf("view %+v", view)
	}
	if _, err := nb2ref.DecodeConfig(raw, nb2ref.CandidateParams); err == nil {
		t.Fatal("continuation config was accepted by the legacy decoder")
	}
}
