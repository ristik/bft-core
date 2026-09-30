package cmd

import (
	"context"
	"encoding/json"
	"errors"
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

func TestShardNodeCertifiedParentCommandIsReadOnly(t *testing.T) {
	want := "0x" + strings.Repeat("ab", 32)
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/operator/status" {
			t.Errorf("unexpected non-read-only request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(archivewiring.OperatorStatus{CertifiedTip: &archivewiring.BlockPin{
			Height: 42, Hash: want, RootEpoch: 3, RootRound: 91,
		}})
	}))
	defer server.Close()

	var stdout, stderr strings.Builder
	cmd := shardNodeCertifiedParentCmd()
	cmd.SetArgs([]string{"--url", server.URL})
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != want+"\n" || !strings.Contains(stderr.String(), "height=42 rootEpoch=3 rootRound=91") {
		t.Fatalf("unexpected parent output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if requests != 1 {
		t.Fatalf("status query made %d requests, want one", requests)
	}
}

func TestCertifiedParentFromStatusErrorIsUnavailableWhenTipMissing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("status must be read-only, got %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(archivewiring.OperatorStatus{})
	}))
	defer server.Close()

	_, _, err := certifiedParentFromStatus(context.Background(), server.URL)
	if !errors.Is(err, ErrCertifiedParentUnavailable) {
		t.Fatalf("missing certified tip error = %v, want ErrCertifiedParentUnavailable", err)
	}
}

func TestShardNodeStatusRejectsIncompatibleAuthorityEncoding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("status must be read-only, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authority":{"rootEpoch":3,"health":"active"}}`))
	}))
	defer server.Close()

	_, err := fetchShardNodeStatus(context.Background(), server.URL)
	if err == nil || !strings.Contains(err.Error(), `unknown field "health"`) {
		t.Fatalf("incompatible authority encoding error = %v, want clear unknown-field refusal", err)
	}
}
