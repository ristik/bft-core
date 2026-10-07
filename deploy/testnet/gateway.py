"""Bounded public JSON-RPC reverse proxy. No batches, signing, admin or Engine API."""
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

from faucet.relay import Relay

PUBLIC = frozenset('eth_chainId eth_blockNumber eth_getBlockByNumber eth_getBalance eth_getTransactionCount eth_gasPrice eth_maxPriorityFeePerGas eth_estimateGas eth_call eth_getCode eth_getTransactionReceipt eth_getTransactionByHash eth_sendRawTransaction net_version web3_clientVersion'.split())
MAX_BODY = 16384

class Server(http.server.HTTPServer):
    def __init__(self, address, handler, relay):
        super().__init__(address, handler)
        self.relay = relay
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
        self.slots = threading.BoundedSemaphore(8)
        self.lock = threading.Lock()
        self.clients = collections.OrderedDict()
        self.requests = self.errors = 0
        self.window = time.monotonic()
        self.budget = 100

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
        with self.lock:
            now = time.monotonic()
            if now - self.window >= 1:
                self.budget, self.window = 100, now
            stamp, count = self.clients.pop(ip, (now, 0))
            if now - stamp >= 1:
                stamp, count = now, 0
            self.clients[ip] = (stamp, count + 1)
            if len(self.clients) > 10000:
                self.clients.popitem(last=False)
            self.requests += 1
            self.budget -= 1
            return count < 10 and self.budget >= 0

class Handler(http.server.BaseHTTPRequestHandler):
    def reply(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        ip = self.client_address[0]
        if ip == os.environ.get('TRUSTED_PROXY_IP'):
            try:
                ip = str(ipaddress.ip_address(self.headers.get('X-Forwarded-For', '')))
            except ValueError:
                return self.reply(400, {'error': 'invalid proxy address'})
        if not self.server.allowed(ip):
            return self.reply(429, {'error': 'rate limit'})
        try:
            if self.path != '/' or self.headers.get('Transfer-Encoding'):
                raise ValueError('path/encoding')
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= MAX_BODY:
                raise ValueError('body size')
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict) or body.get('jsonrpc') != '2.0' or body.get('method') not in PUBLIC or not isinstance(body.get('params', []), list):
                raise ValueError('unsupported JSON-RPC request')
            if not isinstance(body.get('id'), (str, int, type(None))):
                raise ValueError('id')
        except (ValueError, TypeError, KeyError):
            return self.reply(400, {'error': 'invalid or forbidden JSON-RPC request'})
        try:
            result = self.server.relay.call(body['method'], body.get('params', []))
            result['id'] = body.get('id')
            self.reply(200, result)
        except Exception:
            self.server.errors += 1
            self.reply(503, {'error': 'RPC unavailable; broadcast may be partial, inspect before retry'})

    def do_GET(self):
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
        payload = ('tn_rpc_requests_total %d\ntn_rpc_upstream_errors_total %d\n' %
                   (self.server.gateway.requests, self.server.gateway.errors)).encode()
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
