#!/usr/bin/env python3
"""A stub of the aggregator's trust-base endpoint for the local run of the SDK clients: GET /api/v1/trustbases?from=E&maxEntries=N[&snapshotEnd=E&snapshotEntryId=0x..],
the tag-39015 response of bft-core gettrustbase, served from a REAL complete history (--bundle, e.g. the shared dev fixture). Nothing is signed here: the entries are
served byte for byte. Every request is appended to --log (one JSON line) so the runner can assert what each client fetched.

  stub_aggregator.py --bundle FILE [--port 0] [--port-file FILE] [--log FILE]
"""
import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import utbcbor as u  # noqa: E402

OK, INVALID_REQUEST, NOT_YET_AVAILABLE, HISTORY_MISMATCH = 0, 1, 3, 4


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bundle', required=True)
    ap.add_argument('--port', type=int, default=0)
    ap.add_argument('--port-file')
    ap.add_argument('--log')
    a = ap.parse_args()
    network, entries = u.history(open(a.bundle, 'rb').read())
    first = u.entry_fields(entries[0])[2]
    ids = [u.entry_id(e) for e in entries]
    tip = first + len(entries) - 1

    def page(query):
        try:
            frm, count = int(query['from'][0]), int(query['maxEntries'][0])
        except (KeyError, ValueError):
            return u.response(network, INVALID_REQUEST, 0, 0, None, [], None)
        end = tip
        if 'snapshotEnd' in query:
            end = int(query['snapshotEnd'][0])
            want = bytes.fromhex(query['snapshotEntryId'][0].removeprefix('0x'))
            if not first <= end <= tip or ids[end - first] != want:
                return u.response(network, HISTORY_MISMATCH, frm, tip, ids[-1], [], None)
        if frm < first or count < 1:
            return u.response(network, INVALID_REQUEST, frm, tip, ids[-1], [], None)
        if frm > end:
            return u.response(network, NOT_YET_AVAILABLE, frm, tip, ids[-1], [], None)
        last = min(end, frm + count - 1)
        nxt = last + 1 if last < end else None
        return u.response(network, OK, frm, end, ids[end - first], entries[frm - first:last - first + 1], nxt)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            url = urlparse(self.path)
            if url.path != '/api/v1/trustbases':
                self.send_error(404)
                return
            query = parse_qs(url.query)
            body = page(query)
            if a.log:
                with open(a.log, 'a') as f:
                    f.write(json.dumps({'query': {k: v[0] for k, v in query.items()}, 'bytes': len(body)}) + '\n')
            self.send_response(200)
            self.send_header('Content-Type', 'application/cbor')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', a.port), Handler)
    if a.port_file:
        open(a.port_file, 'w').write(str(server.server_address[1]))
    print(f'listening {server.server_address[1]}', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
