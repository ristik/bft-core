"""Private RPC relay: paired ureth validators do not gossip transactions in M1."""
import http.server
import json
import os
from pathlib import Path
try:
    from .gateway import request
except ImportError:  # Standalone faucet image/CLI.
    from gateway import request


class Relay:
    def __init__(self, cfg):
        self.cfg = cfg

    def call(self, method, params):
        results = []
        # Check every target before submitting to any target. Fail closed on partial
        # availability. A timeout during broadcast remains ambiguous to the caller.
        for url in self.cfg['validator_rpc_urls']:
            def rpc(m, p):
                return request(url, dict(jsonrpc='2.0', id=1, method=m, params=p),
                               {'Content-Type': 'application/json'})
            chain = rpc('eth_chainId', []).get('result')
            genesis = rpc('eth_getBlockByNumber', ['0x0', False]).get('result')
            if chain is None or int(chain, 16) != self.cfg['chain_id'] or not genesis or genesis['hash'].lower() != self.cfg['genesis_hash']:
                raise ValueError('validator identity mismatch')
        targets = self.cfg['validator_rpc_urls'] if method == 'eth_sendRawTransaction' else self.cfg['validator_rpc_urls'][:1]
        for url in targets:
            results.append(request(url, dict(jsonrpc='2.0', id=1, method=method, params=params),
                                   {'Content-Type': 'application/json'}))
        if method == 'eth_sendRawTransaction' and any(r.get('result') != results[0].get('result') for r in results):
            raise ValueError('partial broadcast; inspect transaction before retry')
        return results[0]


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.connection.settimeout(10)
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length < 16384 or self.headers.get('Transfer-Encoding'):
                raise ValueError('body size')
            body = json.loads(self.rfile.read(length))
            if body['method'] not in {'eth_chainId', 'eth_getBlockByNumber', 'eth_getBalance',
                                      'eth_getTransactionCount', 'eth_gasPrice',
                                      'eth_maxPriorityFeePerGas', 'eth_sendRawTransaction'}:
                raise ValueError('unsupported method')
            # go-ethereum omits params for zero-argument RPC methods.
            response = self.server.relay.call(body['method'], body.get('params', []))
            response['id'] = body.get('id')
            code = 200
        except Exception:
            code, response = 503, {'error': 'RPC unavailable or identity mismatch; broadcast may be partial'}
        payload = json.dumps(response).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == '__main__':
    cfg = json.loads(Path(os.environ.get('FAUCET_CONFIG', '/config/network.json')).read_text())
    server = http.server.ThreadingHTTPServer(('0.0.0.0', int(os.environ.get('PORT', '8545'))), Handler)
    server.relay = Relay(cfg)
    server.serve_forever()
