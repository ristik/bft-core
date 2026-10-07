"""Run by FAUCET_PROBE=1 after the paired lane's bootstrap, while lock is held.

FAUCET_BACKEND_BIN and FAUCET_EVMTX_BIN must point to prebuilt native tools.
Only disposable random keys are used; no key is included in retained evidence.
"""
import copy
import http.server
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import time
import urllib.error

import gateway
import relay


def main():
    binary = os.environ['FAUCET_BACKEND_BIN']
    evmtx = os.environ['FAUCET_EVMTX_BIN']
    urls = [f'http://127.0.0.1:{18545+i}' for i in range(4)]

    def rpc(method, params):
        return gateway.request(urls[0], dict(jsonrpc='2.0', id=1, method=method, params=params),
                               {'Content-Type': 'application/json'})['result']

    def tx(*args):
        return subprocess.check_output([evmtx, *args], text=True).strip()

    def receipt(hash_):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            result = rpc('eth_getTransactionReceipt', [hash_])
            if result:
                assert result['status'] == '0x1', result
                assert int(result['gasUsed'], 16) > 0
                assert int(result['effectiveGasPrice'], 16) > 0
                admitted = []
                for validator in range(1, 5):
                    lines = Path(f'test-nodes/evm{validator}/debug.log').read_text().splitlines()
                    if any('certificate admitted' in line and 'block=' + result['blockHash'][2:] + ' ' in line for line in lines):
                        admitted.append(validator)
                if len(admitted) >= 3:
                    evidence = {k: result[k] for k in ('transactionHash', 'blockNumber', 'blockHash', 'status', 'gasUsed', 'effectiveGasPrice')}
                    evidence['certified_validators'] = admitted
                    return evidence
            time.sleep(1)
        raise TimeoutError(hash_)

    faucet_key, wallet_key = secrets.token_hex(32), secrets.token_hex(32)
    faucet = tx('-private-key', faucet_key, '-address')
    wallet = tx('-private-key', wallet_key, '-address')
    funder = tx('-address')
    cfg = dict(chain_id=int(rpc('eth_chainId', []), 16),
               genesis_hash=rpc('eth_getBlockByNumber', ['0x0', False])['hash'].lower(),
               funding_address=faucet, rpc_url='http://127.0.0.1:18845',
               backend_url='http://127.0.0.1:18846', validator_rpc_urls=urls,
               minimum_balance_wei=20000000000000000, daily_claims=10,
               captcha_sitekey='', dev_only=True)
    evidence = dict(config=cfg, upstream_revision='e7572628addc86c634d8acc3a61d5899667f0e33',
                    faucet_address=faucet, fresh_wallet=wallet,
                    initial_balance=rpc('eth_getBalance', [wallet, 'latest']))
    assert int(evidence['initial_balance'], 16) == 0
    previous = None
    if os.environ.get('FAUCET_PREVIOUS_EVIDENCE'):
        previous = json.loads(Path(os.environ['FAUCET_PREVIOUS_EVIDENCE']).read_text())['config']
        assert previous['genesis_hash'] != cfg['genesis_hash'], 'reset must actually change genesis'
        evidence['previous_genesis_hash'] = previous['genesis_hash']
    servers, processes = [], []
    with tempfile.TemporaryDirectory(prefix='faucet-probe-') as tmp:
        try:
            rs = http.server.ThreadingHTTPServer(('127.0.0.1', 18845), relay.Handler)
            rs.relay = relay.Relay(cfg)
            servers.append(rs)
            threading.Thread(target=rs.serve_forever, daemon=True).start()
            funding = tx('-send', '-eth-url', cfg['rpc_url'], '-chain-id', str(cfg['chain_id']),
                         '-nonce', str(int(rpc('eth_getTransactionCount', [funder, 'pending']), 16)),
                         '-to', faucet, '-value', '100000000000000000')
            evidence['funding'] = receipt(funding)
            log = open(Path(tmp) / 'backend.log', 'w')
            env = dict(os.environ, PRIVATE_KEY=faucet_key, WEB3_PROVIDER=cfg['rpc_url'],
                       HCAPTCHA_SECRET='', HCAPTCHA_SITEKEY='')
            processes.append(subprocess.Popen([binary, '-httpport', '18846', '-proxycount', '1',
                                               '-faucet.amount', '0.01', '-faucet.symbol', 'UCT'],
                                              env=env, stdout=log, stderr=log))
            state = str(Path(tmp) / 'claims.sqlite')
            if previous:
                old_state = str(Path(tmp) / 'old-network.sqlite')
                gateway.Guard(previous, old_state)
                try:
                    gateway.Guard(cfg, old_state)
                    raise AssertionError('reset reused prior network state')
                except ValueError:
                    evidence['actual_reset_old_state'] = 'refused'
            guard = gateway.Guard(cfg, state)
            for _ in range(30):
                try:
                    guard.health()
                    break
                except Exception:
                    time.sleep(1)
            else:
                raise RuntimeError('signer failed to become healthy: ' + Path(log.name).read_text())
            gs = http.server.ThreadingHTTPServer(('127.0.0.1', 18847), gateway.Handler)
            gs.guard = guard
            servers.append(gs)
            threading.Thread(target=gs.serve_forever, daemon=True).start()
            evidence['health'] = gateway.request('http://127.0.0.1:18847/healthz')
            body = dict(address=wallet, chain_id=cfg['chain_id'], genesis_hash=cfg['genesis_hash'])

            def claim(payload):
                try:
                    return 200, gateway.request('http://127.0.0.1:18847/api/claim', payload,
                                                {'Content-Type': 'application/json'})
                except urllib.error.HTTPError as error:
                    with error:
                        return error.code, json.load(error)

            evidence['invalid_address'] = claim(dict(body, address='invalid'))
            evidence['wrong_chain'] = claim(dict(body, chain_id=1))
            evidence['wrong_genesis'] = claim(dict(body, genesis_hash='0x' + '99'*32))
            if previous:
                evidence['actual_reset_old_wallet_pin'] = claim(dict(body, chain_id=previous['chain_id'], genesis_hash=previous['genesis_hash']))
                assert evidence['actual_reset_old_wallet_pin'][0] == 409
            assert [evidence[k][0] for k in ('invalid_address', 'wrong_chain', 'wrong_genesis')] == [400, 409, 409]
            status, sent = claim(body)
            assert status == 200, sent
            dispensed = sent['msg'].split()[-1]
            evidence['dispense'] = receipt(dispensed)
            evidence['dispensed_balance'] = rpc('eth_getBalance', [wallet, 'latest'])
            assert int(evidence['dispensed_balance'], 16) == 10**16
            evidence['duplicate'] = claim(body)
            evidence['same_ip_new_address'] = claim(dict(body, address='0x' + '42'*20))
            assert evidence['duplicate'][0] == evidence['same_ip_new_address'][0] == 429
            # Same persisted SQLite state, fresh process-equivalent guard instance.
            gs.guard = gateway.Guard(cfg, state)
            evidence['restart_duplicate'] = claim(body)
            assert evidence['restart_duplicate'][0] == 429
            paid = tx('-send', '-eth-url', cfg['rpc_url'], '-chain-id', str(cfg['chain_id']),
                      '-private-key', wallet_key, '-nonce', '0', '-value', '1')
            evidence['paid_transaction'] = receipt(paid)
            evidence['final_balance'] = rpc('eth_getBalance', [wallet, 'latest'])
            assert 0 < int(evidence['final_balance'], 16) < 10**16
            reset = copy.deepcopy(cfg)
            reset['genesis_hash'] = '0x' + '99'*32
            try:
                gateway.Guard(reset, state)
                raise AssertionError('old state accepted new genesis')
            except ValueError:
                evidence['reset_old_state'] = 'refused'
            reset_guard = gateway.Guard(reset, str(Path(tmp) / 'new.sqlite'))
            try:
                reset_guard.health()
                raise AssertionError('wrong RPC genesis accepted')
            except Exception as error:
                assert str(error) == 'RPC genesis mismatch', error
                evidence['wrong_rpc_genesis'] = str(error)
            exhausted = dict(cfg, minimum_balance_wei=10**30)
            try:
                gateway.Guard(exhausted, str(Path(tmp) / 'exhausted.sqlite')).health()
                raise AssertionError('exhausted faucet healthy')
            except ValueError as error:
                assert 'exhausted' in str(error)
                evidence['exhaustion'] = str(error)
            Path('test-nodes/faucet-evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
            print(json.dumps(evidence, indent=2), flush=True)
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()
            for process in processes:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == '__main__':
    main()
