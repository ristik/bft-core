package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-core/archivewiring"
)

type shardNodeStatusFlags struct {
	URL     string
	Timeout time.Duration
}

func shardNodeStatusCmd() *cobra.Command {
	flags := &shardNodeStatusFlags{}
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Read the running shard node's journal, archive, handoff and signing status",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if flags.URL == "" {
				return errors.New("--url is required")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), flags.Timeout)
			defer cancel()
			status, err := fetchShardNodeStatus(ctx, flags.URL)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.ErrOrStderr(), operatorStatusSummary(status))
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(status)
		},
	}
	cmd.Flags().StringVar(&flags.URL, "url", "", "base URL of the running shard node's read-only status server")
	cmd.Flags().DurationVar(&flags.Timeout, "timeout", 5*time.Second, "status request timeout")
	return cmd
}

func fetchShardNodeStatus(ctx context.Context, base string) (archivewiring.OperatorStatus, error) {
	var status archivewiring.OperatorStatus
	base = strings.TrimRight(base, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/operator/status", nil)
	if err != nil {
		return status, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return status, fmt.Errorf("reading shard-node status: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return status, fmt.Errorf("shard-node status returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&status); err != nil {
		return status, fmt.Errorf("decoding shard-node status: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return status, errors.New("shard-node status response has trailing JSON")
	}
	return status, nil
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func operatorStatusSummary(s archivewiring.OperatorStatus) string {
	var b strings.Builder
	fmt.Fprintf(&b, "root epoch %d; journal %d/%d candidates, %d/%d observations, %d/%d bytes",
		s.CurrentRootEpoch, s.Journal.CandidatesUsed, s.Journal.CandidatesCap,
		s.Journal.ObservationsUsed, s.Journal.ObservationsCap, s.Journal.BytesUsed, s.Journal.BytesCap)
	if s.PruneFrontier != nil {
		fmt.Fprintf(&b, "; prune frontier h=%d %s", s.PruneFrontier.Height, s.PruneFrontier.Hash)
	} else {
		b.WriteString("; prune frontier unavailable")
	}
	if s.RestoreBase != nil {
		fmt.Fprintf(&b, "; restore base h=%d %s", s.RestoreBase.Height, s.RestoreBase.Hash)
	}
	if s.LatestLocalV2 != nil {
		fmt.Fprintf(&b, "; local v2 archive h=%d %s", s.LatestLocalV2.Height, s.LatestLocalV2.Hash)
	} else {
		b.WriteString("; local v2 archive empty")
	}
	for _, replica := range s.Replicas {
		fmt.Fprintf(&b, "; replica %s ack h=%d", replica.Replica, replica.LastAcknowledgedHeight)
		if replica.Error != "" {
			fmt.Fprintf(&b, " (%s)", replica.Error)
		}
	}
	if s.Authority != nil {
		if s.Authority.Reachable {
			fmt.Fprintf(&b, "; authority epoch=%d high-water=%d", s.Authority.RootEpoch, s.Authority.ReservedRound)
		} else {
			fmt.Fprintf(&b, "; authority unavailable (%s)", s.Authority.Error)
		}
	}
	return b.String()
}

func writeOperatorStatus(w http.ResponseWriter, r *http.Request, read func(context.Context) (archivewiring.OperatorStatus, error)) {
	status, err := read(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}
