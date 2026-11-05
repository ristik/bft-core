package bridgeprofile

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
)

// TestParity85Rows recomputes the oracle's verdict (status name, status code, gas) of every seeded-patch case of ureth's
// crates/unicity/bridge/testdata/parity-85.json and prints (PARITY85_ROW lines) the rows whose stored expectation differs. Each fixture
// is a base input, the claim table of the corpus B1 (ClaimsB1) and cases of byte patches (offset, xor); the input is the base with the
// patches applied, run through NativeCompose (v1) or NativeComposeV2 (v2) with an effectively unlimited gas. ureth's
// crates/unicity/bridge/tools/rerun_parity85.py runs this test and rewrites the differing rows.
//
//	PARITY85_FILE=<ureth>/crates/unicity/bridge/testdata/parity-85.json go test ./bridgeprofile -run TestParity85Rows -v
func TestParity85Rows(t *testing.T) {
	path := os.Getenv("PARITY85_FILE")
	if path == "" {
		t.Skip("PARITY85_FILE is not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]json.RawMessage
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	type patch struct{ O, X int }
	type pcase struct {
		ID       string  `json:"id"`
		Patch    []patch `json:"patch"`
		Expected struct {
			Values map[string]string `json:"values"`
		} `json:"expected"`
	}
	type fixture struct {
		Base   string  `json:"base"`
		Claims string  `json:"claims"`
		Cases  []pcase `json:"cases"`
	}
	for _, key := range []string{"v1", "v2"} {
		var fs []fixture
		if err := json.Unmarshal(d[key], &fs); err != nil {
			t.Fatal(err)
		}
		for _, f := range fs {
			base, err := hex.DecodeString(f.Base)
			if err != nil {
				t.Fatal(err)
			}
			b1, err := parseClaims(f.Claims)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range f.Cases {
				in := append([]byte{}, base...)
				for _, p := range c.Patch {
					in[p.O] ^= byte(p.X)
				}
				var status, gas uint64
				var name string
				if key == "v2" {
					_, status, gas, _ = NativeComposeV2(in, ^uint64(0)>>1, b1)
					name = ComposeStatusNameV2(status)
				} else {
					_, status, gas, _ = NativeCompose(in, ^uint64(0)>>1, b1)
					name = ComposeStatusName(status)
				}
				if c.Expected.Values["statusName"] != name || c.Expected.Values["gas"] != strconv.FormatUint(gas, 10) {
					fmt.Printf("PARITY85_ROW\t%s\t%d\t%s\t%d\n", c.ID, status, name, gas)
				}
			}
		}
	}
}
