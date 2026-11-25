"""Bounded public JSON-RPC reverse proxy. No batches, signing, admin or Engine API.

Two public routes:
  POST /                    the execution chain's allow-listed methods (PUBLIC), through the relay to healthy validators. Bodies up to MAX_BODY,
                            except LARGE_METHODS up to MAX_RAW_TX_BODY: a bridge redemption carries its whole return proof (the 2 MiB direct
                            envelope is about 4.2 MB as hex), and a wallet checks it with eth_call and eth_estimateGas on the same calldata before
                            it sends it; at most LARGE_SLOTS bodies above MAX_BODY are read at once. The wallet evidence methods
                            (WALLET_EVIDENCE: the native bridge v2 wallet RPC contract, docs/design/native-bridge-v2.md) are public reads;
                            eth_getLogs must name one contract address and either a blockHash or an explicit numeric fromBlock..toBlock of
                            at most LOG_BLOCK_RANGE blocks (a wallet pages through longer spans window by window), the other evidence reads
                            take exactly EVIDENCE_PARAMS, HEAVY_METHODS have their own rate limit, and no answer above MAX_RESULT_BYTES is
                            relayed (413: page).
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
import socket
from pathlib import Path
import sys
import threading
import time
import urllib.error
import urllib.request

from public_relay import Relay, ResponseTooLarge

# The reads a native bridge v2 wallet builds its evidence from (bft-core#1102): certified header evidence (the companion of the child block
# carries the certificate of its parent), the block's receipts for the receipt-trie path, vault logs, and the companion retention horizon.
WALLET_EVIDENCE = frozenset('eth_getStorageAt eth_getBlockByHash eth_getBlockReceipts eth_getLogs eth_getRawTransactionByBlockHashAndIndex unicity_getSealCompanionV1 unicity_sealCompanionHorizonV1'.split())
PUBLIC = frozenset('eth_chainId eth_blockNumber eth_syncing eth_getBlockByNumber eth_getBalance eth_getTransactionCount eth_gasPrice eth_maxPriorityFeePerGas eth_estimateGas eth_call eth_getCode eth_getTransactionReceipt eth_getTransactionByHash eth_sendRawTransaction net_version web3_clientVersion'.split()) | WALLET_EVIDENCE
LOG_BLOCK_RANGE = 10000     # the most blocks one eth_getLogs may span (toBlock - fromBlock + 1)
LOG_FILTER_KEYS = frozenset({'address', 'topics', 'fromBlock', 'toBlock', 'blockHash'})
LOG_TOPICS = 4              # topic positions an EVM log has
LOG_TOPIC_ALTERNATIVES = 64 # hashes one topic position may list (for example the wanted segment indices)
# the reads whose upstream work and answer grow with the chain: their own, tighter per-client and total rate, on top of the general one
HEAVY_METHODS = frozenset({'eth_getLogs', 'eth_getBlockReceipts'})
MAX_RESULT_BYTES = 8 << 20  # the most bytes of one upstream answer the gateway reads and relays; above it the wallet pages (413)
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


def _quantity(v):
    """An explicit hex block number (no tags: a window is fixed before it is asked for), else None."""
    if not isinstance(v, str) or not v.startswith('0x') or not 2 < len(v) <= 18 or (len(v) > 3 and v[2] == '0'):
        return None
    if any(c not in '0123456789abcdefABCDEF' for c in v[2:]):
        return None
    return int(v[2:], 16)


def _hexbytes(v, n):
    """V is 0x and exactly 2N hex digits."""
    return isinstance(v, str) and len(v) == 2 + 2 * n and v.startswith('0x') and all(c in '0123456789abcdefABCDEF' for c in v[2:])


def _address(v):
    return _hexbytes(v, 20)


def _hash(v):
    return _hexbytes(v, 32)


def _topic(v):
    """One topic position: null (any), a 32-byte hash, or a short non-empty list of hashes."""
    if v is None or _hash(v):
        return True
    return isinstance(v, list) and 0 < len(v) <= LOG_TOPIC_ALTERNATIVES and all(_hash(t) for t in v)


# NB2 return admission reads just this public consensus word.
B1_REGISTRY = '0xff00000000000000000000000000000000000002'
B1_IMPORTED_TIP_SLOT = '0xefa6b7f0bacdcf81ddd8a710fb8420140ae07d47982dc167bb647c00d3f5f4fc'


def _b1_tip_read(params):
    if len(params) != 3 or params[0] != B1_REGISTRY or params[1] != B1_IMPORTED_TIP_SLOT:
        return False
    block = params[2]
    return (isinstance(block, dict) and set(block) == {'blockHash', 'requireCanonical'}
            and _hash(block['blockHash']) and block['requireCanonical'] is True)


# The exact parameters of each wallet evidence read besides eth_getLogs (check_log_filter); a refusal names the accepted shape.
EVIDENCE_PARAMS = {
    'eth_getStorageAt': ('[B1 registry, imported tip slot, {blockHash, requireCanonical: true}]', _b1_tip_read),
    'eth_getBlockByHash': ('[blockHash, false]', lambda p: len(p) == 2 and _hash(p[0]) and p[1] is False),
    'eth_getBlockReceipts': ('[blockHash] or [hex block number]', lambda p: len(p) == 1 and (_hash(p[0]) or _quantity(p[0]) is not None)),
    'eth_getRawTransactionByBlockHashAndIndex': ('[blockHash, hex transaction index]',
                                               lambda p: len(p) == 2 and _hash(p[0]) and _quantity(p[1]) is not None),
    'unicity_getSealCompanionV1': ('[blockHash]', lambda p: len(p) == 1 and _hash(p[0])),
    'unicity_sealCompanionHorizonV1': ('[]', lambda p: len(p) == 0),
}


def check_log_filter(params):
    """Raise ValueError unless PARAMS is one bounded eth_getLogs filter: exactly one contract address, a blockHash or an explicit numeric
    fromBlock..toBlock of at most LOG_BLOCK_RANGE blocks, and at most LOG_TOPICS topic positions of hashes."""
    if len(params) != 1 or not isinstance(params[0], dict) or not set(params[0]) <= LOG_FILTER_KEYS:
        raise ValueError('log filter shape')
    f = params[0]
    if not _address(f.get('address')):
        raise ValueError('log filter must name exactly one contract address')
    if 'topics' in f and (not isinstance(f['topics'], list) or len(f['topics']) > LOG_TOPICS or not all(_topic(t) for t in f['topics'])):
        raise ValueError(f'log filter topics: at most {LOG_TOPICS}, each null, a 32-byte hash or at most {LOG_TOPIC_ALTERNATIVES} hashes')
    if 'blockHash' in f:
        if 'fromBlock' in f or 'toBlock' in f or not _hash(f['blockHash']):
            raise ValueError('log filter block hash')
        return
    lo, hi = _quantity(f.get('fromBlock')), _quantity(f.get('toBlock'))
    if lo is None or hi is None or hi < lo or hi - lo + 1 > LOG_BLOCK_RANGE:
        raise ValueError('log filter range')


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
    # The NB2 wallet checks nine graph fields concurrently. Keep the eight
    # workers and admit one additional batch of sockets to their bounded queue.
    request_queue_size = 16

    def __init__(self, address, handler, relay):
        super().__init__(address, handler)
        self.relay = relay
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
        self.slots = threading.BoundedSemaphore(16)
        self.large = threading.BoundedSemaphore(LARGE_SLOTS)
        self.rpc_limit = Limiter(10, 100)
        self.heavy_limit = Limiter(2, 20)   # HEAVY_METHODS, in addition to rpc_limit
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
    methods, large_methods = PUBLIC, LARGE_METHODS

    def log_filter(self, params):
        check_log_filter(params)

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
            if not isinstance(body, dict) or body.get('jsonrpc') != '2.0' or body.get('method') not in self.methods or not isinstance(body.get('params', []), list):
                raise ValueError('unsupported JSON-RPC request')
            if length > MAX_BODY and body.get('method') not in self.large_methods:
                raise ValueError('body size')
            if not isinstance(body.get('id'), (str, int, type(None))):
                raise ValueError('id')
            method, params = body['method'], body.get('params', [])
            if method == 'eth_getLogs':
                try:
                    self.log_filter(params)
                except ValueError as e:   # named, so a wallet knows to page: one address, a blockHash or at most LOG_BLOCK_RANGE blocks
                    return self.reply(400, {'error': f'eth_getLogs: {e} (one address; blockHash, or numeric fromBlock..toBlock of at most {LOG_BLOCK_RANGE} blocks)'})
            elif method in EVIDENCE_PARAMS:
                shape, ok = EVIDENCE_PARAMS[method]
                if not ok(params):
                    return self.reply(400, {'error': f'{method}: params must be exactly {shape}'})
            if method in HEAVY_METHODS and not self.server.heavy_limit.allowed(ip):
                return self.reply(429, {'error': f'rate limit ({method})'})
            try:
                result = self.server.relay.call(method, params, max_bytes=MAX_RESULT_BYTES)
                result['id'] = body.get('id')
            except ResponseTooLarge:
                return self.reply(413, {'error': f'{method}: the answer is above {MAX_RESULT_BYTES} bytes; ask for less (a narrower eth_getLogs window)'})
            except Exception:
                self.server.errors += 1
                if method == 'eth_sendRawTransaction':
                    return self.reply(503, {'error': 'No transaction acknowledgement; check the hash before retrying the same bytes'})
                return self.reply(503, {'error': 'RPC unavailable'})
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

class ExecutionHandler(Handler):
    """Internal access to one validator's bounded wallet RPC methods."""
    # The public gateway's duplicate check hashes the raw transaction it relays (public_relay.duplicate_hash: web3_sha3, then eth_getTransactionByHash) on
    # these guards: a pure function, internal only, as large as the transaction (bft-core#1287).
    methods, large_methods = PUBLIC | {'web3_sha3'}, LARGE_METHODS | {'web3_sha3'}

    def do_POST(self):
        if self.path != '/':
            return self.reply(404, {'error': 'not found'})
        return super().do_POST()

    def do_GET(self):
        return self.reply(404, {'error': 'not found'})

    def log_filter(self, params):
        # The local operator CLI uses the latest tag to look up registrations.
        # Pin it to a numbered head before applying the same window and shape
        # checks as the public gateway.
        if len(params) == 1 and isinstance(params[0], dict) and params[0].get('toBlock') == 'latest':
            params[0]['toBlock'] = self.server.relay.call('eth_blockNumber', []).get('result')
        super().log_filter(params)


if __name__ == '__main__':
    cfg = json.loads(Path(os.environ.get('FAUCET_CONFIG', '/network/network.json')).read_text())
    local = os.environ.get('TN_LOCAL_EXECUTION_ALIAS')
    if local:
        bind = socket.gethostbyname(local)
        if ipaddress.ip_address(bind).is_loopback:
            raise ValueError('validator wallet relay must bind its private network address')
        cfg['validator_rpc_urls'] = ['http://127.0.0.1:8545']
        server = Server((bind, 8545), ExecutionHandler, Relay(cfg, small_body_limit=MAX_BODY))
        # The public edge already limits individual clients. This listener
        # sees the edge's single internal address for all forwarded calls.
        server.rpc_limit = Limiter(100, 100)
        server.heavy_limit = Limiter(20, 20)
    else:
        server = Server(('0.0.0.0', 8545), Handler, Relay(cfg, small_body_limit=MAX_BODY))
        metrics = http.server.HTTPServer(('0.0.0.0', 9090), Metrics)
        metrics.gateway = server
        threading.Thread(target=metrics.serve_forever, daemon=True).start()
    server.serve_forever()
