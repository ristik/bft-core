"""Bounded public JSON-RPC reverse proxy. No batches, signing, admin or Engine API.

Two public routes:
  POST /                    the execution chain's allow-listed methods (PUBLIC), through the relay to every validator. Bodies up to MAX_BODY,
                            except LARGE_METHODS up to MAX_RAW_TX_BODY: a bridge redemption carries its whole return proof (the 2 MiB direct
                            envelope is about 4.2 MB as hex), and a wallet checks it with eth_call and eth_estimateGas on the same calldata before
                            it sends it; at most LARGE_SLOTS bodies above MAX_BODY are read at once.
  POST /aggregator          the aggregator's JSON-RPC (AGG_METHODS, the state-transition SDK's), bodies up to AGG_MAX_BODY, and
  GET  /api/v1/trustbases   the aggregator's signed trust-base pages (the SDK's refresh resolves this path against the aggregator URL's host):
                            both forwarded to AGG_URL unchanged, with their own rate limit. No authentication (testnet).
"""
import collections
import concurrent.futures
import http.server
import ipaddress
import json
import os
from pathlib import Path
import sys
import threading
import time
import urllib.error
import urllib.request

from faucet.relay import Relay

PUBLIC = frozenset('eth_chainId eth_blockNumber eth_getBlockByNumber eth_getBalance eth_getTransactionCount eth_gasPrice eth_maxPriorityFeePerGas eth_estimateGas eth_call eth_getCode eth_getTransactionReceipt eth_getTransactionByHash eth_sendRawTransaction net_version web3_clientVersion'.split())
MAX_BODY = 16384
MAX_RAW_TX_BODY = 4718592   # 4.5 MiB: the 2 MiB envelope as hex in a redeem transaction, with its ABI and JSON framing
# the methods that may carry a redemption's calldata: its send, and the call and the estimate a wallet makes first (their execution is bounded by the
# gas the call is given, their concurrency by LARGE_SLOTS)
LARGE_METHODS = frozenset({'eth_sendRawTransaction', 'eth_call', 'eth_estimateGas'})
LARGE_SLOTS = 2
AGG_METHODS = frozenset('certification_request get_inclusion_proof.v2 get_inclusion_proofs.v1 get_block_height get_non_inclusion_proof.v1'.split())
AGG_MAX_BODY = 65536        # a 256-state get_inclusion_proofs.v1 batch is about 17 KB
AGG_URL = os.environ.get('AGG_URL', 'http://aggregator:8080')
AGG_TIMEOUT = 30            # the SDK's batch proof call may wait (waitMs) for its states


class Limiter:
    """At most PER_IP requests a second from one address and TOTAL from all."""
    def __init__(self, per_ip, total):
        self.per_ip, self.total = per_ip, total
        self.lock = threading.Lock()
        self.clients = collections.OrderedDict()
        self.window = time.monotonic()
        self.budget = total

    def allowed(self, ip):
        with self.lock:
            now = time.monotonic()
            if now - self.window >= 1:
                self.budget, self.window = self.total, now
            stamp, count = self.clients.pop(ip, (now, 0))
            if now - stamp >= 1:
                stamp, count = now, 0
            self.clients[ip] = (stamp, count + 1)
            if len(self.clients) > 10000:
                self.clients.popitem(last=False)
            self.budget -= 1
            return count < self.per_ip and self.budget >= 0


def upstream(url, payload=None, content_type='application/json'):
    """The aggregator's answer: (status, content type, body), any HTTP status passed through."""
    req = urllib.request.Request(url, payload, {'Content-Type': content_type} if payload is not None else {})
    try:
        with urllib.request.urlopen(req, timeout=AGG_TIMEOUT) as r:
            return r.status, r.headers.get('Content-Type', 'application/json'), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get('Content-Type', 'application/json'), e.read()

class Server(http.server.HTTPServer):
    def __init__(self, address, handler, relay):
        super().__init__(address, handler)
        self.relay = relay
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
        self.slots = threading.BoundedSemaphore(8)
        self.large = threading.BoundedSemaphore(LARGE_SLOTS)
        self.rpc_limit = Limiter(10, 100)
        self.agg_limit = Limiter(10, 50)
        self.requests = self.errors = self.agg_requests = self.agg_errors = 0

    def process_request(self, sock, address):
        sock.settimeout(5)
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(sock)
            return
        self.pool.submit(self.worker, sock, address)

    def worker(self, sock, address):
        try:
            self.finish_request(sock, address)
        except Exception:
            pass
        finally:
            self.shutdown_request(sock)
            self.slots.release()

    def allowed(self, ip):
        self.requests += 1
        return self.rpc_limit.allowed(ip)

class Handler(http.server.BaseHTTPRequestHandler):
    def reply(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def reply_raw(self, status, content_type, payload):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def client_ip(self):
        """The client's address (the forwarded one from the trusted proxy), or None when the proxy forwarded none."""
        ip = self.client_address[0]
        if ip == os.environ.get('TRUSTED_PROXY_IP'):
            try:
                ip = str(ipaddress.ip_address(self.headers.get('X-Forwarded-For', '')))
            except ValueError:
                return None
        return ip

    def do_POST(self):
        ip = self.client_ip()
        if ip is None:
            return self.reply(400, {'error': 'invalid proxy address'})
        if self.path == '/aggregator':
            return self.aggregator_post(ip)
        if not self.server.allowed(ip):
            return self.reply(429, {'error': 'rate limit'})
        large = False
        try:
            if self.path != '/' or self.headers.get('Transfer-Encoding'):
                raise ValueError('path/encoding')
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= MAX_RAW_TX_BODY:
                raise ValueError('body size')
            if length > MAX_BODY:
                # only LARGE_METHODS may be this large; the method is known only after the read, so few such reads run at once
                if not self.server.large.acquire(blocking=False):
                    return self.reply(503, {'error': 'busy: too many large requests, retry'})
                large = True
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict) or body.get('jsonrpc') != '2.0' or body.get('method') not in PUBLIC or not isinstance(body.get('params', []), list):
                raise ValueError('unsupported JSON-RPC request')
            if length > MAX_BODY and body.get('method') not in LARGE_METHODS:
                raise ValueError('body size')
            if not isinstance(body.get('id'), (str, int, type(None))):
                raise ValueError('id')
            try:
                result = self.server.relay.call(body['method'], body.get('params', []))
                result['id'] = body.get('id')
            except Exception:
                self.server.errors += 1
                return self.reply(503, {'error': 'RPC unavailable; broadcast may be partial, inspect before retry'})
            self.reply(200, result)
        except (ValueError, TypeError, KeyError):
            return self.reply(400, {'error': 'invalid or forbidden JSON-RPC request'})
        finally:
            if large:   # held until the large body is relayed and answered: the container's memory bounds them
                self.server.large.release()

    def aggregator_post(self, ip):
        if not self.server.agg_limit.allowed(ip):
            return self.reply(429, {'error': 'rate limit'})
        self.server.agg_requests += 1
        try:
            if self.headers.get('Transfer-Encoding'):
                raise ValueError('encoding')
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= AGG_MAX_BODY:
                raise ValueError('body size')
            raw = self.rfile.read(length)
            body = json.loads(raw)
            if not isinstance(body, dict) or body.get('jsonrpc') != '2.0' or body.get('method') not in AGG_METHODS:
                raise ValueError('unsupported aggregator request')
        except (ValueError, TypeError, KeyError):
            return self.reply(400, {'error': 'invalid or forbidden aggregator request'})
        try:
            self.reply_raw(*upstream(AGG_URL.rstrip('/') + '/', raw))
        except Exception:
            self.server.agg_errors += 1
            self.reply(503, {'error': 'aggregator unavailable'})

    def do_GET(self):
        if self.path.split('?', 1)[0] == '/api/v1/trustbases':
            ip = self.client_ip()
            if ip is None:
                return self.reply(400, {'error': 'invalid proxy address'})
            if not self.server.agg_limit.allowed(ip):
                return self.reply(429, {'error': 'rate limit'})
            self.server.agg_requests += 1
            try:
                return self.reply_raw(*upstream(AGG_URL.rstrip('/') + self.path))
            except Exception:
                self.server.agg_errors += 1
                return self.reply(503, {'error': 'aggregator unavailable'})
        if self.path != '/healthz':
            return self.reply(404, {'error': 'not found'})
        try:
            result = self.server.relay.call('eth_blockNumber', [])
            if 'result' not in result:
                raise ValueError('no head')
            self.reply(200, {'head': result['result']})
        except Exception:
            self.reply(503, {'error': 'unhealthy'})

class Metrics(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        g = self.server.gateway
        payload = ('tn_rpc_requests_total %d\ntn_rpc_upstream_errors_total %d\ntn_agg_requests_total %d\ntn_agg_upstream_errors_total %d\n' %
                   (g.requests, g.errors, g.agg_requests, g.agg_errors)).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

if __name__ == '__main__':
    cfg = json.loads(Path(os.environ.get('FAUCET_CONFIG', '/network/network.json')).read_text())
    server = Server(('0.0.0.0', 8545), Handler, Relay(cfg))
    metrics = http.server.HTTPServer(('0.0.0.0', 9090), Metrics)
    metrics.gateway = server
    threading.Thread(target=metrics.serve_forever, daemon=True).start()
    server.serve_forever()
