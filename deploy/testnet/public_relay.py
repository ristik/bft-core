"""Availability policy for the public RPC gateway."""
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPException
import json
import re
import threading
import time
import urllib.error

from faucet.gateway import ResponseTooLarge, request

PROBE_TIMEOUT = 1
RETRY_AFTER = 5
CONTROL_BYTES = 16 << 10
HASH = re.compile(r'0x[0-9a-fA-F]{64}')
QUANTITY = re.compile(r'0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,15})')
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


def rpc(url, body, max_bytes=CONTROL_BYTES, timeout=PROBE_TIMEOUT):
    try:
        reply = request(url, body, {'Content-Type': 'application/json'}, max_bytes=max_bytes, timeout=timeout)
    except ResponseTooLarge:
        raise
    except urllib.error.HTTPError as exc:
        exc.close()
        raise Unavailable('validator HTTP failure') from exc
    except (OSError, HTTPException, ValueError) as exc:
        raise Unavailable('validator transport or JSON failure') from exc
    if isinstance(reply, dict) and reply.get('jsonrpc') == '2.0' and reply.get('id') == 1:
        error = reply.get('error')
        if 'result' in reply and 'error' not in reply:
            return reply
        if 'result' not in reply and isinstance(error, dict) and isinstance(error.get('message'), str):
            return reply
    raise Unavailable('invalid validator JSON-RPC reply')


class Relay:
    def __init__(self, cfg):
        self.urls = tuple(cfg['validator_rpc_urls'])
        self.chain_id = cfg['chain_id']
        self.genesis_hash = cfg['genesis_hash']
        self.retry_at = {}
        self.lock = threading.Lock()
        self.pool = ThreadPoolExecutor(max_workers=16)

    def close(self):
        self.pool.shutdown()

    def identity(self, url):
        try:
            chain = rpc(url, payload('eth_chainId', [])).get('result')
            genesis = rpc(url, payload('eth_getBlockByNumber', ['0x0', False])).get('result')
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

    @staticmethod
    def head(url):
        head = quantity(rpc(url, payload('eth_blockNumber', [])).get('result'))
        if head is None:
            raise Unavailable('validator head unavailable')
        return head

    def covers(self, url, method, params):
        """Check coverage for reads where a lagging node could give a misleading answer."""
        block = params[0] if params else None
        if method == 'eth_getLogs':
            block = block.get('blockHash', block.get('toBlock'))
        elif method not in {'eth_getBlockByNumber', 'eth_getBlockReceipts', 'unicity_getSealCompanionV1'}:
            return True
        number = quantity(block)
        if number is None and is_hash(block) and method in {'eth_getLogs', 'unicity_getSealCompanionV1'}:
            # false requests transaction hashes, so the coverage probe stays bounded
            # even when the block contains large transactions.
            header = rpc(url, payload('eth_getBlockByHash', [block, False]), max_bytes=8 << 20).get('result')
            if not isinstance(header, dict) or not same_hash(header.get('hash'), block):
                return False
            number = quantity(header.get('number'))
            if number is None:
                return False
        return number is None or self.head(url) >= number

    def read(self, method, params, max_bytes):
        body = payload(method, params)
        miss = None
        error = None
        for url in self.read_order():
            try:
                self.identity(url)
                covered = self.covers(url, method, params)
                if not covered and method == 'eth_getLogs':
                    self.health(url, True)
                    continue
                reply = rpc(url, body, max_bytes=max_bytes, timeout=8)
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
                    if number is None or self.head(url) < number:
                        continue
                return reply
            except Unavailable:
                self.health(url, False)
        if miss is not None:
            return miss
        if error is not None:
            return error
        raise Unavailable('no validator could serve the read')

    def send_to(self, url, body):
        try:
            self.identity(url)
        except (Unavailable, ResponseTooLarge):
            self.health(url, False)
            return False, None
        try:
            reply = rpc(url, body, timeout=8)
        except (Unavailable, ResponseTooLarge):
            self.health(url, False)
            return True, None
        self.health(url, True)
        return True, reply

    def duplicate_hash(self, params, urls):
        # The pinned execution clients implement Keccak in web3_sha3. Hashing
        # here also handles large bridge calldata without a Python hot loop.
        body = payload('web3_sha3', params)
        for url in urls:
            try:
                self.identity(url)
                tx_hash = rpc(url, body).get('result')
                if is_hash(tx_hash):
                    break
            except (Unavailable, ResponseTooLarge):
                continue
        else:
            return None
        body = payload('eth_getTransactionByHash', [tx_hash])
        for url in urls:
            try:
                self.identity(url)
                found = rpc(url, body, max_bytes=8 << 20).get('result')
                if isinstance(found, dict) and same_hash(found.get('hash'), tx_hash):
                    return tx_hash
            except (Unavailable, ResponseTooLarge):
                continue
        return None

    def send(self, params):
        body = payload('eth_sendRawTransaction', params)
        urls = self.read_order()
        tasks = [self.pool.submit(self.send_to, url, body) for url in urls]
        replies = [task.result() for task in tasks]
        duplicate = False
        for _, reply in replies:
            if reply is None:
                continue
            if is_hash(reply.get('result')):
                return reply
            message = reply.get('error', {}).get('message', '').lower()
            if message in ('already known', 'nonce too low') or message.startswith('nonce too low:'):
                duplicate = True
        if duplicate and len(params) == 1 and isinstance(params[0], str):
            urls = [url for url, (attempted, _) in zip(urls, replies) if attempted]
            tx_hash = self.duplicate_hash(params, urls)
            if tx_hash is not None:
                return dict(jsonrpc='2.0', id=1, result=tx_hash)
        raise Unavailable('no validator acknowledged this transaction')

    def call(self, method, params, max_bytes=8 << 20):
        if method == 'eth_sendRawTransaction':
            return self.send(params)
        return self.read(method, params, max_bytes)
