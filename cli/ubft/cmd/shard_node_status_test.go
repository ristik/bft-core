package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unicitynetwork/bft-core/archivewiring"
)

func TestShardNodeStatusCommandReadsJSONAndPrintsSummary(t *testing.T) {
	want := archivewiring.OperatorStatus{CurrentRootEpoch: 3,
		Journal:   archivewiring.JournalUsage{CandidatesUsed: 2, CandidatesCap: 16, ObservationsUsed: 4, ObservationsCap: 32, BytesUsed: 99, BytesCap: 1024},
		Replicas:  []archivewiring.ReplicaReport{{Replica: "replica-a", LastAcknowledgedHeight: 9}},
		Authority: &archivewiring.AuthorityReport{Reachable: true, RootEpoch: 3, ReservedRound: 14}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/operator/status" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer server.Close()

	var stdout, stderr strings.Builder
	cmd := shardNodeStatusCmd()
	cmd.SetArgs([]string{"--url", server.URL})
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	var got archivewiring.OperatorStatus
	if err := json.Unmarshal([]byte(stdout.String()), &got); err != nil {
		t.Fatalf("status output is not JSON: %v", err)
	}
	if got.CurrentRootEpoch != want.CurrentRootEpoch || len(got.Replicas) != 1 || got.Replicas[0].LastAcknowledgedHeight != 9 {
		t.Fatalf("status mismatch: %+v", got)
	}
	if !strings.Contains(stderr.String(), "root epoch 3") || !strings.Contains(stderr.String(), "authority epoch=3 high-water=14") {
		t.Fatalf("short summary missing from stderr: %q", stderr.String())
	}
}
