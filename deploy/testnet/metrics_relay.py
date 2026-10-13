#!/usr/bin/env python3
"""Read-only metrics relay inside one validator pod's network namespace (deploy/testnet).

The root and shard operator listeners bind to loopback (their guarded endpoints accept loopback TCP peers only, and their unguarded writes must not be
reachable from the shared network). Prometheus is on the shared network, so this process, living in the pod's namespace, serves ONLY the two metrics
documents, by exact path and GET only. It builds its own upstream request (fixed URL, no client headers, no body): nothing the client sends reaches the node,
and no other path exists. It is not a forwarder: a request for anything else is refused here and never reaches a loopback endpoint.
"""
import http.server
import os
import urllib.request

# the listeners' addresses come from the generated Compose file (generate.py --rpc-bind, loopback), not from this file
ROUTES = {}   # filled by main() from the environment


def routes(environ):
    return {'/root/metrics': 'http://%s/api/v1/metrics' % environ['ROOT_RPC'], '/shard/metrics': 'http://%s/api/v1/metrics' % environ['SHARD_RPC']}
MAX_BODY = 4 * 1024 * 1024


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'metrics-relay'

    def reply(self, status, body=b'', ctype='text/plain'):
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def do_GET(self):
        upstream = ROUTES.get(self.path)   # the raw request target: a query string, a different case or a traversal is not a route
        if upstream is None:
            return self.reply(404, b'not found\n')
        try:
            with urllib.request.urlopen(upstream, timeout=5) as response:
                body = response.read(MAX_BODY + 1)
                ctype = response.headers.get('Content-Type', 'text/plain')
        except OSError:
            return self.reply(502, b'upstream unavailable\n')
        if len(body) > MAX_BODY:
            return self.reply(502, b'upstream too large\n')
        self.reply(200, body, ctype)

    def refuse(self):
        self.reply(405, b'method not allowed\n')
    do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = refuse

    def log_message(self, *args):
        pass


def main(port=9102):
    ROUTES.update(routes(os.environ))
    http.server.ThreadingHTTPServer(('0.0.0.0', port), Handler).serve_forever()


if __name__ == '__main__':
    main()
