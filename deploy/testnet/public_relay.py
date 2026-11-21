"""Availability policy for the public RPC gateway."""
from concurrent.futures import Future, InvalidStateError, ThreadPoolExecutor, wait
from http.client import HTTPConnection, HTTPException, HTTPSConnection
import json
from queue import Empty, SimpleQueue
import re
import socket
import threading
import time
from urllib.parse import urlsplit

from faucet.gateway import ResponseTooLarge

# Upstream work starts after the HTTP handler validates the client body. Leave
# time for the gateway to answer its ten-second Docker health probe.
REQUEST_TIMEOUT = 9
DUPLICATE_RESERVE = 3
PROBE_TIMEOUT = 1
METHOD_TIMEOUT = 8
READ_SLOTS = 8
SEND_GROUPS = 4
SEND_WIDTH = 4
LARGE_SEND_GROUPS = 2
RETRY_AFTER = 5
CONTROL_BYTES = 16 << 10
HASH = re.compile(r'0x[0-9a-fA-F]{64}')
QUANTITY = re.compile(r'0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,15})')
BRIDGE_PREFLIGHT = {'eth_call', 'eth_estimateGas'}
LOOKUP_HASH_FIELD = {'eth_getTransactionReceipt': 'transactionHash', 'eth_getTransactionByHash': 'hash'}


class Unavailable(ValueError):
    """A backend failed transport, protocol or network identity checks."""


def quantity(value):
    return int(value, 16) if isinstance(value, str) and QUANTITY.fullmatch(value) else None


def is_hash(value):
    return isinstance(value, str) and HASH.fullmatch(value) is not None


def same_hash(value, expected):
    return is_hash(value) and value.lower() == expected.lower()


def payload(method, params):
    return json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=params)).encode()


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise Unavailable('validator deadline elapsed')
    return seconds


def fair_slice(deadline, peers_left):
    """Reserve a share of the remaining budget for every untried peer."""
    now = time.monotonic()
    return now + (deadline - now) / peers_left


def interrupt(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass  # The connection already closed.


def publish(answer, reply):
    try:
        answer.set_result(reply)
    except InvalidStateError:
        pass  # Another worker already published an answer.


class Relay:
    def __init__(self, cfg, *, small_body_limit):
        self.urls = tuple(cfg['validator_rpc_urls'])
        self.chain_id = cfg['chain_id']
        self.genesis_hash = cfg['genesis_hash']
        self.small_body_limit = small_body_limit
        self.retry_at = {}
        self.lock = threading.Lock()
        self.read_slots = threading.BoundedSemaphore(READ_SLOTS)
        self.send_slots = threading.BoundedSemaphore(SEND_GROUPS)
        self.large_send_slots = threading.BoundedSemaphore(LARGE_SEND_GROUPS)
        self.read_pool = ThreadPoolExecutor(max_workers=READ_SLOTS)
        self.send_pool = ThreadPoolExecutor(max_workers=SEND_GROUPS)
        self.peer_pool = ThreadPoolExecutor(max_workers=SEND_GROUPS * SEND_WIDTH)
        self.resolver_pool = ThreadPoolExecutor(max_workers=max(1, len(self.urls)))
        self.resolving = {}

    def close(self):
        self.read_pool.shutdown()
        self.send_pool.shutdown()
        self.peer_pool.shutdown()
        self.resolver_pool.shutdown()

    def resolve(self, address, deadline):
        remaining(deadline)
        with self.lock:
            task = self.resolving.get(address)
            if task is None or task.done():
                # libc resolution cannot be interrupted. Share one outstanding
                # task per configured endpoint, retaining no request bodies.
                task = self.resolver_pool.submit(socket.getaddrinfo, *address, type=socket.SOCK_STREAM)
                self.resolving[address] = task
        return task.result(timeout=remaining(deadline))

    def connect_peer(self, address, deadline):
        candidates = self.resolve(address, deadline)
        last_error = None
        for family, kind, proto, _, target in candidates:
            timeout = remaining(deadline)
            sock = None
            try:
                sock = socket.socket(family, kind, proto)
                sock.settimeout(timeout)
                sock.connect(target)
                sock.settimeout(remaining(deadline))
                return sock
            except (OSError, Unavailable) as exc:
                if sock is not None:
                    sock.close()
                last_error = exc
        raise Unavailable('no usable validator address') from last_error

    def rpc(self, url, body, deadline, max_bytes=CONTROL_BYTES, timeout=PROBE_TIMEOUT):
        deadline = min(deadline, time.monotonic() + timeout)
        target = urlsplit(url)
        connect = HTTPSConnection if target.scheme == 'https' else HTTPConnection
        try:
            connection = connect(target.hostname, target.port, timeout=remaining(deadline))
            try:
                # Supply a deadline-aware dialer while keeping HTTP Host and TLS
                # server-name verification tied to the configured hostname.
                connection._create_connection = lambda address, *_: self.connect_peer(address, deadline)
                connection.connect()
                # Socket timeouts are per operation. A watchdog also bounds a peer
                # that trickles headers or body bytes without going idle.
                watchdog = threading.Timer(remaining(deadline), interrupt, args=(connection.sock,))
                watchdog.daemon = True
                watchdog.start()
                try:
                    path = target.path or '/'
                    if target.query:
                        path += '?' + target.query
                    connection.request('POST', path, body, {'Content-Type': 'application/json'})
                    with connection.getresponse() as response:
                        if response.status != 200:
                            raise Unavailable('validator HTTP failure')
                        raw = response.read() if max_bytes is None else response.read(max_bytes + 1)
                finally:
                    watchdog.cancel()
            finally:
                connection.close()
            remaining(deadline)
            if max_bytes is not None and len(raw) > max_bytes:
                raise ResponseTooLarge(f'upstream answer above {max_bytes} bytes')
            reply = json.loads(raw)
        except (Unavailable, ResponseTooLarge):
            raise
        except (OSError, HTTPException, ValueError) as exc:
            raise Unavailable('validator transport or JSON failure') from exc
        if isinstance(reply, dict) and reply.get('jsonrpc') == '2.0' and reply.get('id') == 1:
            error = reply.get('error')
            if 'result' in reply and 'error' not in reply:
                return reply
            if 'result' not in reply and isinstance(error, dict) and isinstance(error.get('message'), str):
                return reply
        raise Unavailable('invalid validator JSON-RPC reply')

    def identity(self, url, deadline):
        try:
            chain = self.rpc(url, payload('eth_chainId', []), deadline).get('result')
            genesis = self.rpc(url, payload('eth_getBlockByNumber', ['0x0', False]), deadline).get('result')
        except ResponseTooLarge as exc:
            raise Unavailable('oversized validator identity response') from exc
        if quantity(chain) != self.chain_id:
            raise Unavailable('validator chain ID mismatch')
        if not isinstance(genesis, dict) or not same_hash(genesis.get('hash'), self.genesis_hash):
            raise Unavailable('validator genesis mismatch')

    def health(self, url, available):
        with self.lock:
            if available:
                self.retry_at.pop(url, None)
            else:
                self.retry_at[url] = time.monotonic() + RETRY_AFTER

    def read_order(self):
        with self.lock:
            now = time.monotonic()
            return sorted(self.urls, key=lambda url: self.retry_at.get(url, 0) > now)

    def head(self, url, deadline):
        head = quantity(self.rpc(url, payload('eth_blockNumber', []), deadline).get('result'))
        if head is None:
            raise Unavailable('validator head unavailable')
        return head

    def covers(self, url, method, params, deadline):
        """Check coverage for reads where a lagging node could give a misleading answer."""
        block = params[0] if params else None
        if method == 'eth_getLogs':
            block = block.get('blockHash', block.get('toBlock'))
        elif method not in {'eth_getBlockByNumber', 'eth_getBlockReceipts', 'unicity_getSealCompanionV1'}:
            return True
        number = quantity(block)
        if number is None and is_hash(block) and method != 'eth_getBlockByNumber':
            # false requests transaction hashes, so the coverage probe stays bounded
            # even when the block contains large transactions.
            header = self.rpc(url, payload('eth_getBlockByHash', [block, False]), deadline, max_bytes=8 << 20).get('result')
            if not isinstance(header, dict) or not same_hash(header.get('hash'), block):
                return False
            number = quantity(header.get('number'))
            if number is None:
                return False
        return number is None or self.head(url, deadline) >= number

    def read(self, method, params, max_bytes, deadline):
        body = payload(method, params)
        miss = None
        error = None
        urls = self.read_order()
        for index, url in enumerate(urls):
            if time.monotonic() >= deadline:
                break
            # Start bridge preflight on the healthiest peer with the full
            # remaining budget. Restarting an expensive execution on every
            # peer at a short timeout can exhaust an otherwise sufficient budget.
            attempt = deadline if method in BRIDGE_PREFLIGHT else fair_slice(deadline, len(urls) - index)
            try:
                self.identity(url, attempt)
                covered = self.covers(url, method, params, attempt)
                if not covered and method in {'eth_getLogs', 'eth_getBlockReceipts'}:
                    self.health(url, True)
                    if method == 'eth_getBlockReceipts' and miss is None:
                        miss = dict(jsonrpc='2.0', id=1, result=None)
                    continue
                reply = self.rpc(url, body, attempt, max_bytes=max_bytes, timeout=METHOD_TIMEOUT)
                self.health(url, True)
                if 'error' in reply:
                    if covered and error is None:
                        error = reply
                    continue
                result = reply['result']
                if method == 'eth_blockNumber' and quantity(result) is None:
                    raise Unavailable('validator head unavailable')
                if result is None:
                    if miss is None:
                        miss = reply
                    continue
                if not covered and method != 'unicity_getSealCompanionV1':
                    continue
                if method == 'unicity_getSealCompanionV1':
                    status = result.get('status') if isinstance(result, dict) else None
                    if status in ('unknown', 'unavailable'):
                        if miss is None or (status == 'unavailable' and covered):
                            miss = reply
                        continue
                    if status != 'found' or not covered:
                        continue
                if method in LOOKUP_HASH_FIELD and params and is_hash(params[0]):
                    field = LOOKUP_HASH_FIELD[method]
                    if not isinstance(result, dict) or not same_hash(result.get(field), params[0]):
                        continue
                    block = result.get('blockNumber')
                    if method == 'eth_getTransactionByHash' and block is None:
                        # Prefer an included copy when a peer still shows a pool copy.
                        if miss is None or miss['result'] is None:
                            miss = reply
                        continue
                    number = quantity(block)
                    if number is None or self.head(url, attempt) < number:
                        continue
                return reply
            except Unavailable:
                self.health(url, False)
        if miss is not None:
            return miss
        if error is not None:
            return error
        raise Unavailable('no validator could serve the read')

    def send_to(self, url, body, deadline):
        try:
            self.identity(url, deadline)
            reply = self.rpc(url, body, deadline, timeout=METHOD_TIMEOUT)
        except (Unavailable, ResponseTooLarge):
            self.health(url, False)
            return None
        self.health(url, True)
        return reply

    def fanout(self, urls, body, deadline, answer, outcomes):
        for index, url in enumerate(urls):
            if time.monotonic() >= deadline:
                break
            reply = self.send_to(url, body, fair_slice(deadline, len(urls) - index))
            if reply is None:
                continue
            if is_hash(reply.get('result')):
                publish(answer, reply)
                continue
            message = reply.get('error', {}).get('message', '').lower()
            if message in ('already known', 'nonce too low') or message.startswith('nonce too low:'):
                outcomes.put(url)

    def duplicate_hash(self, params, preferred, deadline):
        # A duplicate responder is a good hash source. Check all configured
        # validators, including ones that could not be reached during broadcast.
        urls = preferred + [url for url in self.read_order() if url not in preferred]
        body = payload('web3_sha3', params)
        hash_deadline = fair_slice(deadline, 2)
        for index, url in enumerate(urls):
            attempt = fair_slice(hash_deadline, len(urls) - index)
            try:
                self.identity(url, attempt)
                tx_hash = self.rpc(url, body, attempt).get('result')
                if is_hash(tx_hash):
                    break
            except (Unavailable, ResponseTooLarge):
                continue
        else:
            return None
        body = payload('eth_getTransactionByHash', [tx_hash])
        for index, url in enumerate(urls):
            attempt = fair_slice(deadline, len(urls) - index)
            try:
                self.identity(url, attempt)
                found = self.rpc(url, body, attempt, max_bytes=8 << 20).get('result')
                if isinstance(found, dict) and same_hash(found.get('hash'), tx_hash):
                    return tx_hash
            except (Unavailable, ResponseTooLarge):
                continue
        return None

    def deliver(self, body, params, deadline, answer):
        # Each admitted group has its own four worker slots, so competing
        # requests cannot queue behind a slow 16-validator fan-out.
        tasks = []
        outcomes = SimpleQueue()
        try:
            urls = self.read_order()
            broadcast_deadline = deadline - DUPLICATE_RESERVE
            for index in range(min(SEND_WIDTH, len(urls))):
                task = self.peer_pool.submit(
                    self.fanout, urls[index::SEND_WIDTH], body, broadcast_deadline, answer, outcomes)
                tasks.append(task)
                task.add_done_callback(lambda _: outcomes.put(None))
            wait(tasks, timeout=max(0, broadcast_deadline - time.monotonic()))
            if len(params) != 1 or not isinstance(params[0], str):
                return

            # The cutoff starts duplicate confirmation. Workers can still
            # publish replies they received before it, including while a
            # different worker is still running.
            pending = len(tasks)
            while pending and not answer.done():
                try:
                    outcome = outcomes.get(timeout=remaining(deadline))
                except (Empty, Unavailable):
                    break
                preferred = []
                while True:
                    if outcome is None:
                        pending -= 1
                    else:
                        preferred.append(outcome)
                    try:
                        outcome = outcomes.get_nowait()
                    except Empty:
                        break
                if preferred and not answer.done():
                    tx_hash = self.duplicate_hash(params, preferred, deadline)
                    if tx_hash is not None:
                        publish(answer, dict(jsonrpc='2.0', id=1, result=tx_hash))
        finally:
            # Keep a positive acknowledgement eligible to win until workers
            # finish publishing. The caller enforces its own request deadline.
            # The group retains admission until its workers release the body.
            wait(tasks)
            publish(answer, None)

    def send(self, params, deadline):
        body = payload('eth_sendRawTransaction', params)
        if not self.send_slots.acquire(blocking=False):
            raise Unavailable('all broadcast slots occupied')
        large = len(body) > self.small_body_limit
        if large and not self.large_send_slots.acquire(blocking=False):
            self.send_slots.release()
            raise Unavailable('all large broadcast slots occupied')

        def release(_):
            if large:
                self.large_send_slots.release()
            self.send_slots.release()

        # Keep admission until all delivery work finishes, even if the HTTP
        # handler has returned an acknowledgement and released its body slot.
        answer = Future()
        try:
            job = self.send_pool.submit(self.deliver, body, params, deadline, answer)
        except RuntimeError:
            release(None)
            raise
        job.add_done_callback(release)
        reply = answer.result(timeout=remaining(deadline))
        if reply is None:
            raise Unavailable('no validator acknowledged this transaction')
        return reply

    def call(self, method, params, max_bytes=8 << 20):
        deadline = time.monotonic() + REQUEST_TIMEOUT
        if method == 'eth_sendRawTransaction':
            return self.send(params, deadline)
        if not self.read_slots.acquire(blocking=False):
            raise Unavailable('all read slots occupied')
        try:
            job = self.read_pool.submit(self.read, method, params, max_bytes, deadline)
        except RuntimeError:
            self.read_slots.release()
            raise
        job.add_done_callback(lambda _: self.read_slots.release())
        return job.result(timeout=remaining(deadline))
