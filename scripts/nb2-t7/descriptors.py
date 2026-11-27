#!/usr/bin/env python3
"""Derive fresh T7 release descriptors from the selected source and build."""
import argparse
from importlib import import_module
from pathlib import Path

verify = import_module('check-qualification')


def generate(repo, ureth, plugin, binary, output, wallet_index):
    pins = verify.read(repo / 'scripts/nb2-t7/pins.json')
    fixtures = repo / 'testvectors/nb2-continuation-v1.1-supplement/descriptors'
    package = repo / 'deploy/testnet/bridge/nb2'
    output.mkdir()
    for name in ('cert-batch-v2', 'rsmt-member-v1', 'registry-layout', 'execution',
                 'primitive-vectors', 'semantic-profile'):
        template = package / f'{name}-tip.json'
        if not template.is_file():
            template = fixtures / f'{name}.json'
        record = verify.read(template)
        if 'ureth' in record:
            record['ureth'] = pins['ureth']
        for key in ('rules', 'native', 'sources', 'artifacts', 'specification'):
            if key in record:
                native = name in ('cert-batch-v2', 'rsmt-member-v1', 'execution') or key == 'native'
                record[key] = {path: verify.sha(verify.source_file(ureth, pins['ureth'], path))
                               if native else verify.digest(repo / path) for path in record[key]}
        verify.write(output / f'{name}.json', record)
    verify.write(output / 'build-index.json', {
        'ureth': pins['ureth'],
        'binaries': {'unicity-reth': verify.digest(binary)},
        'wallet': {
            'revision': pins['plugin'],
            'lockSha256': verify.digest(plugin / 'package-lock.json'),
            'compiledSdkIndexSha256': verify.digest(wallet_index),
            'sources': {str(path.relative_to(plugin)): verify.digest(path)
                        for path in sorted((plugin / 'wallet').glob('*.ts'))
                        if not path.name.endswith('.test.ts')},
        },
    })


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'ureth', 'plugin', 'binary', 'output', 'wallet_index'):
        parser.add_argument(name, type=Path)
    generate(**vars(parser.parse_args()))
