#!/usr/bin/env python3
"""Tester-side network check: does the endpoint I am about to use serve the published network?

Standard library only. Compares what the endpoint says with the two values the operator publishes (chain ID and block-zero hash, from the
public manifest or the faucet's /api/network): eth_chainId, net_version, block 0's hash, and that the chain is producing blocks. Exit 0 = every check
passed, 1 = a check failed, 2 = the endpoint could not be asked. It reads only; it sends no transaction and holds no key.
"""
import argparse, json, re, sys, time, urllib.request

HASH = re.compile(r'0x[0-9a-f]{64}')


def rpc(url, method, params=(), timeout=10):
    req = urllib.request.Request(url, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode(),
                                 {'Content-Type': 'application/json', 'User-Agent': 'tester-check'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = json.load(r)
    if 'error' in body:
        raise RuntimeError(f"{method}: {body['error']}")
    return body['result']


def published(args):
    """(chain_id, genesis_hash) from --manifest (a manifest.json or the faucet's /api/network JSON, a file or URL) or from the two flags."""
    if args.manifest and (args.chain_id is not None or args.genesis_hash):
        raise ValueError('give either --manifest or --chain-id and --genesis-hash, not both')
    if args.manifest:
        if args.manifest.startswith(('http://', 'https://')):
            with urllib.request.urlopen(args.manifest, timeout=10) as r:
                m = json.load(r)
        else:
            m = json.load(open(args.manifest))
        chain, genesis = m.get('chain_id'), m.get('genesis_hash')
    else:
        chain, genesis = args.chain_id, args.genesis_hash
    if not isinstance(chain, int) or isinstance(chain, bool) or chain <= 0 or not isinstance(genesis, str) or not HASH.fullmatch(genesis.lower()):
        raise ValueError('need a positive integer chain ID and a 0x-prefixed 32-byte block-zero hash (--manifest, or --chain-id and --genesis-hash)')
    return chain, genesis.lower()


def check(url, chain, genesis, wait):
    """Return a list of (name, ok, detail)."""
    out = []
    def add(name, ok, detail): out.append((name, bool(ok), detail))
    got = int(rpc(url, 'eth_chainId'), 16)
    add('chain ID', got == chain, f'endpoint {got}, published {chain}')
    ver = rpc(url, 'net_version')
    add('net_version', ver == str(chain), f'endpoint {ver}, published {chain}')
    zero = rpc(url, 'eth_getBlockByNumber', ['0x0', False])['hash'].lower()
    add('block-zero hash', zero == genesis, f'endpoint {zero}, published {genesis}')
    first = int(rpc(url, 'eth_blockNumber'), 16)
    deadline = time.monotonic() + wait
    last = first
    while last <= first and time.monotonic() < deadline:
        time.sleep(1)
        last = int(rpc(url, 'eth_blockNumber'), 16)
    # An idle chain makes no blocks (the shard seals on demand), so no new block is only a note unless the caller asked to wait for one.
    add('blocks', last > first or wait == 0, f'height {first} then {last}' + ('' if last > first else ' (no new block; the chain may be idle)'))
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--rpc', required=True, help='endpoint URL, e.g. https://rpc.<domain>/')
    p.add_argument('--manifest', help='manifest.json or the faucet /api/network, file path or URL')
    p.add_argument('--chain-id', type=int)
    p.add_argument('--genesis-hash')
    p.add_argument('--wait', type=int, default=0, help='seconds to wait for a new block (0: do not require one)')
    a = p.parse_args(argv)
    try:
        chain, genesis = published(a)
        results = check(a.rpc, chain, genesis, a.wait)
    except ValueError as e:
        print(f'error: {e}', file=sys.stderr)
        return 2
    except Exception as e:
        print(f'could not ask {a.rpc}: {e}', file=sys.stderr)
        return 2
    for name, ok, detail in results:
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {detail}")
    if all(ok for _, ok, _ in results):
        print('This endpoint serves the published network.')
        return 0
    print('DO NOT USE this endpoint with this wallet: it is not the published network (or the network was reset; refresh the manifest).')
    return 1


if __name__ == '__main__':
    sys.exit(main())
