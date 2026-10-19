package cmd

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
)

// The operator endpoints of the root and of the shard node (handoff, abort, Q3, pos-control) answer only requests whose TCP peer address is in the
// configured operator sources. The default is loopback only (127.0.0.1 and ::1); an operator widens it with --operator-allowed-sources. This is address
// filtering, not authentication (owner §25): the posture stays "bind the RPC to loopback or an isolated operator network".

// operatorSourcesUsage is the help text of --operator-allowed-sources.
const operatorSourcesUsage = `comma-separated IP addresses and CIDR prefixes whose requests the operator endpoints (handoff, abort, Q3, pos-control) answer; ` +
	`loopback only by default. Address filtering on the TCP peer, not authentication: keep the RPC address on loopback or an isolated operator network`

// defaultOperatorSources is the default allowed-source list: loopback only.
const defaultOperatorSources = "127.0.0.0/8,::1/128"

// operatorSourceSet is an immutable list of allowed source prefixes.
type operatorSourceSet struct {
	prefixes []netip.Prefix
	loopback bool // the set is exactly the loopback default
}

// parseOperatorSources reads a comma-separated list of addresses and CIDR prefixes (empty means the loopback default). An empty element or any
// malformed element is an error, so a typo fails the start instead of silently refusing (or admitting) operators.
func parseOperatorSources(list string) (*operatorSourceSet, error) {
	if strings.TrimSpace(list) == "" {
		list = defaultOperatorSources // not configured
	}
	set := &operatorSourceSet{loopback: list == defaultOperatorSources}
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		var p netip.Prefix
		if strings.Contains(item, "/") {
			var err error
			if p, err = netip.ParsePrefix(item); err != nil {
				return nil, fmt.Errorf("--operator-allowed-sources: %q is not a CIDR prefix: %w", item, err)
			}
		} else {
			a, err := netip.ParseAddr(item)
			if err != nil {
				return nil, fmt.Errorf("--operator-allowed-sources: %q is not an IP address or CIDR prefix: %w", item, err)
			}
			if a.Zone() != "" {
				return nil, fmt.Errorf("--operator-allowed-sources: %q carries an IPv6 zone", item)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		set.prefixes = append(set.prefixes, p)
	}
	return set, nil
}

// allows reports whether the host part of a TCP peer address is inside the set. IPv4-mapped IPv6 addresses count as their IPv4 address.
func (s *operatorSourceSet) allows(host string) bool {
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	a = a.WithZone("").Unmap() // a zone ("fe80::1%eth0") is not part of the address
	for _, p := range s.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// exposed lists the configured prefixes that are not loopback (for the start-up warning).
func (s *operatorSourceSet) exposed() []string {
	var out []string
	for _, p := range s.prefixes {
		if !p.Addr().IsLoopback() {
			out = append(out, p.String())
		}
	}
	return out
}

var activeOperatorSources atomic.Pointer[operatorSourceSet]

func init() {
	set, err := parseOperatorSources(defaultOperatorSources)
	if err != nil {
		panic(err)
	}
	activeOperatorSources.Store(set)
}

// operatorSources is the set the operator endpoints of this process check.
func operatorSources() *operatorSourceSet { return activeOperatorSources.Load() }

// configureOperatorSources validates the flag value and installs it for the process; it is called at start, before any endpoint is served. A non-loopback
// range is allowed (an isolated operator network) but logged, since the endpoints have no authentication.
func configureOperatorSources(log *slog.Logger, list string) error {
	set, err := parseOperatorSources(list)
	if err != nil {
		return err
	}
	activeOperatorSources.Store(set)
	if exposed := set.exposed(); len(exposed) > 0 {
		log.Warn("the operator endpoints accept requests from non-loopback sources and have no operator authentication: restrict them to an isolated operator network "+
			"(see docs/operations/root-rpc-exposure.md, #533)", "sources", exposed)
	}
	return nil
}

// remoteHost is the host part of a request's TCP peer address.
func remoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return ""
	}
	return host
}

// operatorLogger is the logger of the process's observability, or the default one when a test drives a run function without it.
func operatorLogger(o Observability) *slog.Logger {
	if o == nil {
		return slog.Default()
	}
	return o.Logger()
}
