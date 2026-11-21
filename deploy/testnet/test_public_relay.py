"""Public relay regressions against controllable JSON-RPC validators."""
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest
import urllib.error
import urllib.request

from gateway import Handler, Relay, Server

GENESIS = '0x' + 'aa' * 32
TX = '0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347'
BLOCK = '0x' + 'cc' * 32
RAW = '0xc0'
KNOWN = {'code': -32000, 'message': 'already known'}
NONCE = {'code': -32000, 'message': 'nonce too low: next nonce 2, tx nonce 1'}


class Node:
    def __init__(self, *, chain='0x46', head='0x7', answers=None):
        self.answers = {
            'eth_chainId': {'result': chain},
            'eth_blockNumber': {'result': head},
            'eth_getBlockByNumber': {'result': {'hash': GENESIS}},
            **(answers or {}),
        }
        self.calls = []

    def handler(self):
        node = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                method, params = req['method'], req['params']
                node.calls.append((method, params))
                answer = node.answers.get(method, {'result': None})
                if callable(answer):
                    answer = answer(params)
                if answer is None:
                    return self.send_error(503)
                payload = json.dumps(dict(jsonrpc='2.0', id=req['id'], **answer)).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        return Handler


class PublicRelayTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)

    def serve(self, server):
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01})
        thread.start()
        self.stack.callback(server.server_close)
        self.stack.callback(thread.join)
        self.stack.callback(server.shutdown)
        return 'http://127.0.0.1:' + str(server.server_port)

    def gateway(self, *nodes):
        urls = []
        for node in nodes:
            if node is None:
                # Reserve the port without listening, to exercise a refused connection.
                server = ThreadingHTTPServer(('127.0.0.1', 0), Node().handler(), bind_and_activate=False)
                server.server_bind()
                self.stack.callback(server.server_close)
                urls.append('http://127.0.0.1:' + str(server.server_address[1]))
            else:
                urls.append(self.serve(ThreadingHTTPServer(('127.0.0.1', 0), node.handler())))
        relay = Relay(dict(validator_rpc_urls=urls, chain_id=70, genesis_hash=GENESIS))
        server = Server(('127.0.0.1', 0), Handler, relay)
        if hasattr(relay, 'close'):
            self.stack.callback(relay.close)
        self.stack.callback(server.pool.shutdown)
        self.url = self.serve(server)

    def rpc(self, method, params=()):
        body = dict(jsonrpc='2.0', id='caller', method=method, params=list(params))
        req = urllib.request.Request(self.url, json.dumps(body).encode())
        try:
            response = urllib.request.urlopen(req, timeout=8)
        except urllib.error.HTTPError as e:
            response = e
        with response:
            return response.code, json.load(response)

    def assert_result(self, method, params, result):
        self.assertEqual(self.rpc(method, params), (200, dict(jsonrpc='2.0', id='caller', result=result)))

    def test_read_when_validator_is_down(self):
        self.gateway(None, Node())
        self.assert_result('eth_chainId', [], '0x46')

    def test_send_with_acceptance_and_already_known(self):
        accepted = Node(answers={'eth_sendRawTransaction': {'result': TX}})
        duplicate = Node(answers={'eth_sendRawTransaction': {'error': KNOWN}})
        self.gateway(accepted, duplicate)
        self.assert_result('eth_sendRawTransaction', [RAW], TX)
        for node in (accepted, duplicate):
            self.assertIn(('eth_sendRawTransaction', [RAW]), node.calls)

    def test_health_tracks_outage_and_recovery(self):
        first = Node(answers={'eth_chainId': None})
        second = Node(head='0x6')
        self.gateway(first, second)
        with urllib.request.urlopen(self.url + '/healthz', timeout=4) as response:
            self.assertEqual(json.load(response), {'head': '0x6'})
        first_count = len(first.calls)
        first.answers['eth_chainId'] = {'result': '0x46'}
        self.assert_result('eth_blockNumber', [], '0x6')
        self.assertEqual(len(first.calls), first_count)
        second.answers['eth_chainId'] = None
        self.assert_result('eth_blockNumber', [], '0x7')

    def test_wrong_chain_and_wrong_genesis_never_receive_the_write(self):
        wrong_chain = Node(chain='0x47')
        wrong_genesis = Node(answers={'eth_getBlockByNumber': {'result': {'hash': BLOCK}}})
        good = Node(answers={'eth_sendRawTransaction': {'result': TX}})
        self.gateway(wrong_chain, wrong_genesis, None, good)
        self.assert_result('eth_sendRawTransaction', [RAW], TX)
        for wrong in (wrong_chain, wrong_genesis):
            self.assertNotIn(('eth_sendRawTransaction', [RAW]), wrong.calls)

    def test_no_pinned_backend_returns_unavailable(self):
        self.gateway(Node(chain='0x47'), None)
        self.assertEqual(self.rpc('eth_chainId')[0], 503)
        self.assertEqual(self.rpc('eth_sendRawTransaction', [RAW])[0], 503)

    def test_read_survives_method_transport_failure_and_preserves_revert(self):
        error = {'code': 3, 'message': 'execution reverted', 'data': '0x1234'}
        down = Node(answers={'eth_call': None})
        good = Node(answers={'eth_call': {'error': error}, 'eth_getBalance': {'result': '0x5'}})
        self.gateway(down, good)
        self.assertEqual(self.rpc('eth_call', [{}]), (200, dict(jsonrpc='2.0', id='caller', error=error)))
        self.assert_result('eth_getBalance', [], '0x5')

    def test_lagging_validator_cannot_hide_receipt_or_answer_future_logs(self):
        receipt = {'transactionHash': TX, 'blockNumber': '0x7', 'blockHash': BLOCK}
        lagging = Node(head='0x6', answers={'eth_getLogs': {'result': []}})
        good = Node(answers={'eth_getTransactionReceipt': {'result': receipt}, 'eth_getLogs': {'result': [{'blockHash': BLOCK}]}})
        self.gateway(lagging, good)
        self.assert_result('eth_getTransactionReceipt', [TX], receipt)
        self.assert_result('eth_getLogs', [{'address': '0x' + 'ab' * 20, 'fromBlock': '0x6', 'toBlock': '0x7'}], [{'blockHash': BLOCK}])
        self.assertNotIn('eth_getLogs', [method for method, _ in lagging.calls])

    def test_seal_companion_fails_over_unknown_and_pruned_results(self):
        block = {'hash': BLOCK, 'number': '0x7'}
        found = {'status': 'found', 'companion': {}}
        unknown = Node(answers={'unicity_getSealCompanionV1': {'result': {'status': 'unknown'}}})
        pruned = Node(answers={'eth_getBlockByHash': {'result': block},
                              'unicity_getSealCompanionV1': {'result': {'status': 'unavailable', 'horizon': 8}}})
        good = Node(answers={'eth_getBlockByHash': {'result': block}, 'unicity_getSealCompanionV1': {'result': found}})
        self.gateway(unknown, pruned, good)
        self.assert_result('unicity_getSealCompanionV1', [BLOCK], found)

    def test_hash_logs_skip_backend_missing_the_block(self):
        block = {'hash': BLOCK, 'number': '0x7'}
        missing = Node(answers={'eth_getLogs': {'result': []}})
        good = Node(answers={'eth_getBlockByHash': {'result': block}, 'eth_getLogs': {'result': [{'blockHash': BLOCK}]}})
        self.gateway(missing, good)
        self.assert_result('eth_getLogs', [{'address': '0x' + 'ab' * 20, 'blockHash': BLOCK}], [{'blockHash': BLOCK}])
        self.assertNotIn('eth_getLogs', [method for method, _ in missing.calls])

    def test_exact_duplicate_is_idempotent_in_pool_and_after_inclusion(self):
        transaction = {'hash': TX, 'blockNumber': None}
        node = Node(answers={
            'eth_sendRawTransaction': {'error': KNOWN},
            'web3_sha3': lambda args: {'result': TX} if args == [RAW] else {'result': BLOCK},
            'eth_getTransactionByHash': lambda args: {'result': transaction if args == [TX] else None},
        })
        self.gateway(node)
        self.assert_result('eth_sendRawTransaction', [RAW], TX)
        node.answers['eth_sendRawTransaction'] = {'error': NONCE}
        transaction['blockNumber'] = '0x7'
        self.assert_result('eth_sendRawTransaction', [RAW], TX)
        self.assertEqual(self.rpc('eth_sendRawTransaction', ['0xc1'])[0], 503)
        self.assertIn(('eth_getTransactionByHash', [BLOCK]), node.calls)

    def test_no_acceptance_with_rejection_or_lost_reply_returns_503(self):
        rejected = Node(answers={'eth_sendRawTransaction': {'error': {'code': -32000, 'message': 'invalid sender'}}})
        lost = Node(answers={'eth_sendRawTransaction': None})
        self.gateway(rejected, lost)
        self.assertEqual(self.rpc('eth_sendRawTransaction', [RAW])[0], 503)
        for node in (rejected, lost):
            self.assertIn(('eth_sendRawTransaction', [RAW]), node.calls)


if __name__ == '__main__':
    unittest.main()
