import concurrent.futures
import http.server
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

import gateway
import relay


def config():
    return dict(chain_id=31337, genesis_hash='0x' + '12' * 32,
                funding_address='0x' + '34' * 20, rpc_url='http://rpc',
                backend_url='http://signer', captcha_sitekey='site', daily_claims=10,
                minimum_balance_wei=20000000000000000, dev_only=False,
                validator_rpc_urls=['http://v1', 'http://v2'])


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = str(Path(self.tmp.name) / 'claims.sqlite')
        self.cfg = config()
        self.guard = gateway.Guard(self.cfg, self.state)

    def test_durable_caps_and_reset(self):
        self.assertTrue(self.guard.reserve('a', '1'))
        restarted = gateway.Guard(self.cfg, self.state)
        self.assertFalse(restarted.reserve('a', '2'))
        self.assertFalse(restarted.reserve('b', '1'))
        changed = dict(self.cfg, genesis_hash='0x' + '99' * 32)
        with self.assertRaises(ValueError):
            gateway.Guard(changed, self.state)
        gateway.Guard(changed, str(Path(self.tmp.name) / 'reset.sqlite'))

    def test_atomic_concurrent_claims(self):
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            outcomes = list(pool.map(lambda i: self.guard.reserve('same', str(i)), range(8)))
        self.assertEqual(sum(outcomes), 1)

    def test_global_budget_and_expiry(self):
        for i in range(10):
            self.assertTrue(self.guard.reserve(str(i), str(i)))
        self.assertFalse(self.guard.reserve('next', 'next'))
        with self.guard.db() as db:
            db.execute('UPDATE claims SET ts=0')
        self.assertTrue(self.guard.reserve('next', 'next'))

    def test_health_rejects_wrong_chain_genesis_balance_and_signer(self):
        def rpc(method, params):
            return {'eth_chainId': hex(31337), 'eth_getBlockByNumber': {'hash': self.cfg['genesis_hash']},
                    'eth_getBalance': hex(self.cfg['minimum_balance_wei'])}[method]
        info = {'account': self.cfg['funding_address'], 'payout': '0.01', 'hcaptcha_sitekey': 'site'}
        with patch.object(self.guard, 'rpc', side_effect=rpc), patch.object(gateway, 'request', return_value=info):
            self.assertEqual(self.guard.health()['status'], 'ready')
            for method, bad in [('eth_chainId', '0x1'), ('eth_getBlockByNumber', {'hash': '0x' + '99'*32}), ('eth_getBalance', '0x0')]:
                with patch.object(self.guard, 'rpc', side_effect=lambda m, p: bad if m == method else rpc(m, p)):
                    with self.assertRaises(ValueError):
                        self.guard.health()
            info['account'] = '0x' + '77'*20
            with self.assertRaises(ValueError):
                self.guard.health()

    def test_http_validation_spoofing_and_uncertain_failure(self):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), gateway.Handler)
        server.guard = self.guard
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = f'http://127.0.0.1:{server.server_port}/api/claim'
        body = dict(address='0x' + '56'*20, chain_id=31337, genesis_hash=self.cfg['genesis_hash'])

        def claim(payload, token='captcha', forged='1.2.3.4'):
            req = urllib.request.Request(url, json.dumps(payload).encode(),
                                         {'h-captcha-response': token, 'X-Forwarded-For': forged})
            try:
                return urllib.request.urlopen(req).status
            except urllib.error.HTTPError as error:
                error.close()
                return error.code

        with patch.object(self.guard, 'health', return_value={'status': 'ready'}), patch.object(gateway, 'request', return_value={'msg': 'tx'}) as backend:
            self.assertEqual(claim(dict(body, address='bad')), 400)
            self.assertEqual(claim(dict(body, chain_id=1)), 409)
            self.assertEqual(claim(dict(body, genesis_hash='0x' + '99'*32)), 409)
            self.assertEqual(claim(body, token=''), 400)
            backend.assert_not_called()
            self.assertEqual(claim(body), 200)
            self.assertEqual(claim(dict(body, address='0x' + '57'*20), forged='9.9.9.9'), 429)
            self.assertEqual(backend.call_count, 1)
            with self.guard.db() as db:
                db.execute('DELETE FROM claims')
            backend.side_effect = TimeoutError()
            self.assertEqual(claim(body), 503)
            self.assertEqual(claim(body), 429)


class RelayTests(unittest.TestCase):
    def test_geth_zero_argument_rpc_omits_params(self):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), relay.Handler)
        server.relay = relay.Relay(config())
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with patch.object(server.relay, 'call', return_value={'jsonrpc': '2.0', 'id': 1, 'result': '0x7a69'}) as call:
            response = gateway.request(f'http://127.0.0.1:{server.server_port}',
                                       {'jsonrpc': '2.0', 'id': 7, 'method': 'eth_chainId'})
            self.assertEqual(response['result'], '0x7a69')
            self.assertEqual(response['id'], 7)
            call.assert_called_once_with('eth_chainId', [])

    def test_broadcast_checks_all_pins_before_any_send(self):
        cfg = config()
        calls = []

        def rpc(url, body, headers):
            calls.append((url, body['method']))
            if body['method'] == 'eth_chainId':
                return {'result': hex(cfg['chain_id'])}
            if body['method'] == 'eth_getBlockByNumber':
                return {'result': {'hash': cfg['genesis_hash'] if url.endswith('v1') else 'wrong'}}
            return {'result': '0xtransaction'}

        with patch.object(relay, 'request', side_effect=rpc):
            with self.assertRaises(ValueError):
                relay.Relay(cfg).call('eth_sendRawTransaction', ['0xraw'])
        self.assertFalse(any(m == 'eth_sendRawTransaction' for _, m in calls))
        cfg['validator_rpc_urls'] = ['http://v1', 'http://another-v1']
        calls.clear()
        with patch.object(relay, 'request', side_effect=rpc):
            relay.Relay(cfg).call('eth_sendRawTransaction', ['0xraw'])
        self.assertEqual(sum(m == 'eth_sendRawTransaction' for _, m in calls), 2)


if __name__ == '__main__':
    unittest.main()
