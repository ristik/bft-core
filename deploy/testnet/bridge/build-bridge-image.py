#!/usr/bin/env python3
"""Build the bridge tools image (Dockerfile.tools) from checkouts verified against bridge/pins.json, and record its ID beside the node images.

    build-bridge-image.py --contracts-source DIR --nbp-source DIR

Each source must be a clean checkout at exactly its pinned commit (contracts with its submodules); dnb-tool comes from this package's own bft-core
checkout, which must be clean in its tracked files, and its commit is recorded. dnb-tool (cgo), forge's build of the contracts and
the plug-ins' `npm ci` all run inside the image build, on the image's own platform (linux/amd64).
Writes artifacts/bridge-images.json.
"""
import argparse
import json
import pathlib
import shutil
import subprocess

HERE = pathlib.Path(__file__).resolve().parent
PINS = json.loads((HERE / 'pins.json').read_text())
ARTIFACTS = HERE.parent / 'artifacts'
TAG = 'tnops-bridge:verified'


def run(*args, **kw):
    return subprocess.check_output(args, text=True, **kw).strip()


def verified(name, src):
    src = src.resolve()
    if name != 'bft' and run('git', '-C', str(src), 'rev-parse', 'HEAD') != PINS[name]:
        raise SystemExit(f'{name} source pin mismatch: {src} is not at {PINS[name]}')
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
    p.add_argument('--contracts-source', required=True, type=pathlib.Path)
    p.add_argument('--nbp-source', required=True, type=pathlib.Path)
    a = p.parse_args()
    bft = verified('bft', pathlib.Path(run('git', '-C', str(HERE), 'rev-parse', '--show-toplevel')))
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
    subprocess.run(['docker', 'build', '--platform', 'linux/amd64', '-t', TAG, '--build-arg', 'NODE_IMAGE=' + PINS['node'], '--build-arg', 'GO_IMAGE=' + PINS['go'],
                    '--build-arg', 'FOUNDRY_URL=' + f['url'], '--build-arg', 'FOUNDRY_SHA256=' + f['sha256'], str(ctx)], check=True)
    # dnb-tool has no --help: an unknown command proves it starts (its cgo libraries resolve) and dispatches
    for probe in (['forge', '--version'], ['cast', '--version'], ['bash', '-c', 'dnb-tool probe 2>&1 | grep -q "unknown command"'],
                  ['npx', '--no-install', 'tsx', '--version']):
        subprocess.run(['docker', 'run', '--rm', '--read-only', '--tmpfs', '/tmp', TAG, *probe], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    record = {'sources': dict(PINS, bft=run('git', '-C', str(bft), 'rev-parse', 'HEAD')), 'dnb_tool_sha256': run('docker', 'run', '--rm', '--entrypoint', 'sha256sum', TAG, '/usr/local/bin/dnb-tool').split()[0],
              'images': {'bridge': run('docker', 'image', 'inspect', '--format={{.Id}}', TAG)}}
    (ARTIFACTS / 'bridge-images.json').write_text(json.dumps(record, indent=2) + '\n')
    shutil.rmtree(ctx)
    print(ARTIFACTS / 'bridge-images.json')


if __name__ == '__main__':
    main()
