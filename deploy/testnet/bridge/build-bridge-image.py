#!/usr/bin/env python3
"""Build the bridge tools image (Dockerfile.tools) from checkouts verified against bridge/pins.json, and record its ID beside the node images.

    build-bridge-image.py --bft-source DIR --contracts-source DIR --nbp-source DIR

Each source must be a clean checkout at exactly its pinned commit (contracts with its submodules). dnb-tool is built from --bft-source, which must be
the node images' pin (deploy/testnet/pins.json "bft", the same checkout build-images.py builds ubft from): the lock-proof endpoint reads the validators'
archives, so it must speak the nodes' archive layout (bft-core#1075: a dnb-tool older than the packed archive of #1059 found no lock proof). The pin is
recorded, and bridge/overlay.py refuses an image recorded for another one. dnb-tool (cgo), forge's build of the contracts and
the plug-ins' `npm ci` all run inside the image build, on the image's own platform (linux/amd64).
Writes artifacts/bridge-images.json.
"""
import argparse
import json
import pathlib
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
PINS = json.loads((HERE / 'pins.json').read_text())
NODE_PINS = json.loads((HERE.parent / 'pins.json').read_text())   # the node images' sources: dnb-tool shares their bft pin
ARTIFACTS = HERE.parent / 'artifacts'
sys.path.insert(0, str(HERE.parent))
from imagetag import build   # noqa: E402  per-pin immutable tags (bft-core#1092)


def run(*args, **kw):
    return subprocess.check_output(args, text=True, **kw).strip()


def verified(name, src):
    src = src.resolve()
    want = NODE_PINS['bft'] if name == 'bft' else PINS[name]
    if run('git', '-C', str(src), 'rev-parse', 'HEAD') != want:
        raise SystemExit(f'{name} source pin mismatch: {src} is not at {want}' + (' (deploy/testnet/pins.json: the node images\' bft pin)' if name == 'bft' else ''))
    if run('git', '-C', str(src), 'status', '--porcelain', '--untracked-files=no', '--ignore-submodules=none'):
        raise SystemExit(f'{name} dirty source: {src}')
    return src


def stage(src, dst):
    # the tracked files only (with submodules): no .git, no node_modules, no build output and nothing untracked; the image build makes its own
    for rel in run('git', '-C', str(src), 'ls-files', '--recurse-submodules', '-z').split('\0'):
        if rel and (src / rel).is_file():
            (dst / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src / rel, dst / rel)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--bft-source', required=True, type=pathlib.Path, help='bft-core at deploy/testnet/pins.json "bft" (the checkout build-images.py builds ubft from)')
    p.add_argument('--contracts-source', required=True, type=pathlib.Path)
    p.add_argument('--nbp-source', required=True, type=pathlib.Path)
    a = p.parse_args()
    bft = verified('bft', a.bft_source)
    contracts = verified('contracts', a.contracts_source)
    nbp = verified('native-bridge-plugins', a.nbp_source)

    ctx = ARTIFACTS / 'bridge-context'
    shutil.rmtree(ctx, ignore_errors=True)
    ctx.mkdir(parents=True)
    stage(bft, ctx / 'bft')
    stage(contracts, ctx / 'contracts')
    stage(nbp, ctx / 'native-bridge-plugins')
    shutil.copy2(HERE / 'Dockerfile.tools', ctx / 'Dockerfile')

    f = PINS['foundry']
    image, tag = build('bridge', NODE_PINS['bft'][:12], '--platform', 'linux/amd64', '--build-arg', 'NODE_IMAGE=' + PINS['node'], '--build-arg', 'GO_IMAGE=' + PINS['go'],
                       '--build-arg', 'FOUNDRY_URL=' + f['url'], '--build-arg', 'FOUNDRY_SHA256=' + f['sha256'], str(ctx))
    # dnb-tool has no --help: an unknown command proves it starts (its cgo libraries resolve) and dispatches
    for probe in (['forge', '--version'], ['cast', '--version'], ['bash', '-c', 'dnb-tool probe 2>&1 | grep -q "unknown command"'],
                  ['npx', '--no-install', 'tsx', '--version']):
        subprocess.run(['docker', 'run', '--rm', '--read-only', '--tmpfs', '/tmp', image, *probe], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    record = {'sources': dict(PINS, bft=run('git', '-C', str(bft), 'rev-parse', 'HEAD')), 'dnb_tool_sha256': run('docker', 'run', '--rm', '--entrypoint', 'sha256sum', image, '/usr/local/bin/dnb-tool').split()[0],
              'images': {'bridge': image}, 'tags': {'bridge': tag}}
    (ARTIFACTS / 'bridge-images.json').write_text(json.dumps(record, indent=2) + '\n')
    shutil.rmtree(ctx)
    print(ARTIFACTS / 'bridge-images.json')


if __name__ == '__main__':
    main()
