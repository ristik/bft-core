#!/usr/bin/env python3
"""Check each paired validator and the deployment's public relay while the lane is live."""
import argparse
import json
from pathlib import Path
import subprocess
import signal
import sys
from threading import Thread
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'deploy/testnet'))
from gateway import Handler, MAX_BODY, MAX_RAW_TX_BODY, MAX_RESULT_BYTES, Relay, Server

METHOD = 'eth_getRawTransactionByBlockHashAndIndex'


def call(url, method, *params):
    body = json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=params)).encode()
    with urlopen(Request(url, body, headers={'Content-Type': 'application/json'}), timeout=15) as response:
        reply = json.load(response)
    if 'result' not in reply:
        raise ValueError(reply)
    return reply['result']


def keccak(wire):
    return subprocess.check_output(['cast', 'keccak', wire], text=True).strip()



def archive(lane_url, chain_id, genesis, ready):
    relay = Relay(dict(validator_rpc_urls=[lane_url], chain_id=chain_id, genesis_hash=genesis),
                  small_body_limit=MAX_BODY)
    server = Server(('127.0.0.1', 0), Handler, relay)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    ready.write_text(f'http://127.0.0.1:{server.server_port}\n')
    try:
        server.serve_forever()
    finally:
        server.server_close()
        server.pool.shutdown()
        relay.close()


def main():
    if len(sys.argv) == 6 and sys.argv[1] == 'archive':
        archive(sys.argv[2], int(sys.argv[3]), sys.argv[4], Path(sys.argv[5]))
        return
    p = argparse.ArgumentParser()
    p.add_argument('run', type=Path)
    p.add_argument('lane', type=Path)
    p.add_argument('receipt', type=Path, help='receipt path relative to the run')
    args = p.parse_args()
    g = json.loads((args.run / 'deployment.json').read_text())
    receipt = json.loads((args.run / args.receipt).read_text())
    callargs = receipt['blockHash'], receipt['transactionIndex']
    rpc = urlparse(g['routes']['rpc'])
    urls = [f'http://127.0.0.1:{rpc.port+n}' for n in range(4)]
    expected_tx = receipt['transactionHash']
    validators = []

    for n, url in enumerate(urls, 1):
        chain = int(call(url, 'eth_chainId'), 16)
        genesis = call(url, 'eth_getBlockByNumber', '0x0', False)['hash']
        assert chain == int(g['chainId']) and genesis == g['executionGenesis']
        raw = call(url, METHOD, *callargs)
        assert keccak(raw) == expected_tx, url
        runtime = {role: keccak(call(url, 'eth_getCode', g[role], 'latest')) for role in g['runtimeHashes']}
        assert runtime == g['runtimeHashes'], url
        config = call(url, 'eth_call', {'to': g['vault'], 'data': '0x' + keccak('0x636f6e6669672829')[2:10]}, 'latest')
        gamma = (args.run / 'gamma.bin').read_bytes()
        offset = int(config[2:66], 16)
        length = int(config[2 + 2 * offset:66 + 2 * offset], 16)
        assert bytes.fromhex(config[66 + 2 * offset:66 + 2 * offset + 2 * length]) == gamma
        horizon = call(url, 'unicity_sealCompanionHorizonV1')
        node = args.lane / 'test-nodes' / f'reth{n}'
        flags = (Path('/proc') / (node / 'pid').read_text().strip() / 'cmdline').read_text().split('\0')
        settings = {key: next(arg.split('=', 1)[1] for arg in flags if arg.startswith(key + '='))
                    for key in ('--txpool.max-tx-gas', '--txpool.max-tx-input-bytes', '--unicity.max-gas',
                                '--unicity.system-gas', '--unicity.profile-hash')}
        validators.append(dict(url=url, chainId=chain, executionGenesis=genesis, runtimeHashes=runtime,
                               rawTransaction=expected_tx, companionHorizon=horizon, settings=settings))
    assert all(v['settings'] == validators[0]['settings'] for v in validators)
    assert all(v['companionHorizon'] is None for v in validators)

    relay = Relay(dict(validator_rpc_urls=urls, chain_id=int(g['chainId']), genesis_hash=g['executionGenesis']),
                  small_body_limit=MAX_BODY)
    server = Server(('127.0.0.1', 0), Handler, relay)
    thread = Thread(target=server.serve_forever)
    thread.start()
    try:
        url = f'http://127.0.0.1:{server.server_port}'
        assert keccak(call(url, METHOD, *callargs)) == expected_tx
        try:
            call(url, METHOD, callargs[0], '0x-1')
        except HTTPError as error:
            assert error.code == 400
        else:
            raise AssertionError('public relay accepted a malformed index')
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
        server.pool.shutdown()
        relay.close()
    (args.run / 'validator-graph.json').write_text(json.dumps(validators, indent=2) + '\n')
    (args.run / 'public-relay-check.json').write_text(json.dumps({
        'method': METHOD, 'blockHash': callargs[0], 'transactionIndex': callargs[1], 'expectedTxHash': expected_tx,
        'signedBytes': (len(raw) - 2) // 2, 'failedTransaction': receipt['status'] == '0x0',
        'maxRequestBytes': MAX_RAW_TX_BODY, 'maxResultBytes': MAX_RESULT_BYTES,
    }, indent=2) + '\n')


if __name__ == '__main__':
    main()
