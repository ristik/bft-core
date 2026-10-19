package cmd

import (
	"log/slog"
	"net"
	"strings"
)

// rpcBindIsLoopback reports whether an RPC server bound to addr ("host:port") is reachable from this host only. An empty host (":8080"), the
// unspecified addresses (0.0.0.0, ::) and any non-loopback IP or name other than "localhost" listen on a network interface.
func rpcBindIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// warnIfRPCExposed logs a WARN when an RPC address that serves operator endpoints is not loopback (#533). The handoff and Q3 operator endpoints of the
// root and of the shard node answer only the configured operator sources (--operator-allowed-sources, loopback by default; localOperatorRequest), but that is the TCP peer address only, so a reverse proxy on the
// same host defeats it, and PUT /api/v1/trustbases on the root is not guarded at all; docs/operations/root-rpc-exposure.md says what each endpoint can do.
func warnIfRPCExposed(log *slog.Logger, node, addr string) {
	if addr == "" || rpcBindIsLoopback(addr) {
		return
	}
	log.Warn("the "+node+" RPC address is not loopback and has no operator authentication: bind it to 127.0.0.1 or an isolated operator network, "+
		"never publish it or proxy it (see docs/operations/root-rpc-exposure.md, #533)", "address", addr)
}
