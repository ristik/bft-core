#!/usr/bin/env python3
"""Carry the rehearsal's verified build from the job that built it to the profile jobs.

  pack OUT.tar.zst NAME=PATH...   after build-images.py: the images named in deploy/testnet/artifacts/images.json
                                  (docker save, by their immutable tags), images.json, and the host tools
  unpack IN.tar.zst NAME=PATH...  in a profile job: check, load and install them; fail closed on any mismatch
  key                             the cache key of the build: everything build-images.py builds the images and pinned tools from

unpack refuses the bundle unless
  - every file matches the sha256 the bundle's manifest records;
  - images.json names exactly the sources of this checkout's deploy/testnet/pins.json;
  - each loaded image's ID equals the ID that build-images.py recorded for it (an image ID is the digest of its config);
  - the node image's ubft, unicity-reth and aggregator have the sha256 build-images.py recorded for the binaries it built;
  - the host ubft is the binary build-images.py recorded, and ubft, b1genesis and h4pin report the pinned
    BFT revision and an unmodified tree (the check generate.py makes of ubft and b1genesis).
The names are the host tools: ubft (pinned-bft/build/ubft) and keygen, b1genesis, h4pin.
"""

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
TESTNET = REPO / 'deploy' / 'testnet'
RECORD = TESTNET / 'artifacts' / 'images.json'
KINDS = ('node', 'guard', 'signer', 'rpc')
TOOLS = ('ubft', 'keygen', 'b1genesis', 'h4pin')
PINNED_TOOLS = ('ubft', 'b1genesis', 'h4pin')   # keygen is built from this checkout, as before
IN_NODE = {'ubft': '/usr/local/bin/ubft', 'unicity-reth': '/usr/local/bin/unicity-reth', 'aggregator': '/usr/local/bin/aggregator'}


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def tools(args):
    named = dict(a.split('=', 1) for a in args)
    if sorted(named) != sorted(TOOLS):
        raise SystemExit(f'name exactly the tools {", ".join(TOOLS)} (NAME=PATH)')
    return {k: pathlib.Path(v) for k, v in named.items()}


def out(*args):
    return subprocess.check_output(args, text=True).strip()


def pack(target, paths):
    record = json.loads(RECORD.read_text())
    with tempfile.TemporaryDirectory(dir=pathlib.Path(target).resolve().parent) as tmp:
        d = pathlib.Path(tmp)
        (d / 'bin').mkdir()
        for name, path in paths.items():
            shutil.copy2(path, d / 'bin' / name)
        shutil.copy2(RECORD, d / 'images.json')
        subprocess.run(['docker', 'save', '-o', str(d / 'images.tar'), *(record['tags'][k] for k in KINDS)], check=True)
        files = sorted(str(p.relative_to(d)) for p in d.rglob('*') if p.is_file())
        (d / 'manifest.json').write_text(json.dumps({f: sha256(d / f) for f in files}, indent=1, sort_keys=True) + '\n')
        subprocess.run(f'tar -C {d} -cf - . | zstd -q -T0 -3 -o {target}', shell=True, check=True)
    print(f'{target}: {pathlib.Path(target).stat().st_size >> 20} MiB')


def fail(message):
    raise SystemExit('rehearsal bundle refused: ' + message)


def unpack(source, paths):
    pins = json.loads((TESTNET / 'pins.json').read_text())
    with tempfile.TemporaryDirectory(dir=pathlib.Path(source).resolve().parent) as tmp:
        d = pathlib.Path(tmp)
        subprocess.run(f'zstd -q -d -c {source} | tar -C {d} -xf -', shell=True, check=True)
        manifest = json.loads((d / 'manifest.json').read_text())
        present = sorted(str(p.relative_to(d)) for p in d.rglob('*') if p.is_file() and p.name != 'manifest.json')
        if present != sorted(manifest):
            fail(f'files {present} are not the manifest\'s {sorted(manifest)}')
        for f, digest in manifest.items():
            if sha256(d / f) != digest:
                fail(f'{f} does not match its manifest digest')
        record = json.loads((d / 'images.json').read_text())
        if record['sources'] != pins:
            fail('images.json was built from other sources than deploy/testnet/pins.json')
        subprocess.run(['docker', 'load', '-i', str(d / 'images.tar')], check=True, stdout=subprocess.DEVNULL)
        for kind in KINDS:
            loaded = out('docker', 'image', 'inspect', '--format={{.Id}}', record['tags'][kind])
            if loaded != record['images'][kind]:
                fail(f'{kind}: loaded {loaded}, build-images.py recorded {record["images"][kind]}')
        for binary, inside in IN_NODE.items():
            got = out('docker', 'run', '--rm', '--entrypoint', 'sha256sum', record['images']['node'], inside).split()[0]
            if got != record['binary_sha256'][binary]:
                fail(f'the node image\'s {binary} is not the binary build-images.py built')
        if sha256(d / 'bin' / 'ubft') != record['binary_sha256']['ubft']:
            fail('the host ubft is not the binary build-images.py built')
        for name in PINNED_TOOLS:
            info = out('go', 'version', '-m', str(d / 'bin' / name))
            if 'vcs.revision=' + pins['bft'] not in info or 'vcs.modified=true' in info:
                fail(f'{name} is not built from the clean pinned BFT source')
        for name, path in paths.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(d / 'bin' / name, path)
            path.chmod(0o755)
        RECORD.parent.mkdir(exist_ok=True)
        shutil.copy2(d / 'images.json', RECORD)
    subprocess.run(['docker', 'pull', pins['mongo']], check=True, stdout=subprocess.DEVNULL)   # as build-images.py does
    print(f'verified and loaded: {", ".join(record["images"][k] for k in KINDS)}')


def build_inputs():
    """The files the images and the pinned tools are built from, besides the pinned sources themselves (named by pins.json): the build scripts,
    the Dockerfiles and every file their build contexts COPY from this checkout. Dockerfile.node's context is the build's own artifacts (from
    the pins); faucet/ is hashed whole; Dockerfile.rpc's context is deploy/testnet, so its COPY sources are read from it (fail closed on a form
    this does not parse)."""
    files = ['deploy/testnet/pins.json', 'deploy/testnet/build-images.py', 'deploy/testnet/imagetag.py', 'deploy/testnet/Dockerfile.node',
             'deploy/testnet/Dockerfile.rpc', 'scripts/ci/rehearsal-bundle.py']
    files += out('git', '-C', str(REPO), 'ls-files', 'deploy/testnet/faucet').splitlines()
    for line in (TESTNET / 'Dockerfile.rpc').read_text().splitlines():
        words = line.split()
        if not words or words[0].upper() not in ('COPY', 'ADD'):
            continue
        if words[0].upper() == 'ADD' or any(w.startswith('--') for w in words[1:]) or any(c in line for c in '*?[$'):
            raise SystemExit(f'Dockerfile.rpc: cannot derive the build inputs of {line!r}; extend rehearsal-bundle.py key')
        for source in words[1:-1]:
            path = TESTNET / source
            if not path.is_file():
                raise SystemExit(f'Dockerfile.rpc copies {source}, which is not a file of deploy/testnet')
            files.append(str(path.relative_to(REPO)))
    return sorted(set(files))


# The ignore files that can shape a build context (docker reads <context>/.dockerignore, or <Dockerfile>.dockerignore next to the Dockerfile
# in preference): hashed as present-with-content or absent, so adding, changing or removing one moves the key.
IGNORE_FILES = ('deploy/testnet/.dockerignore', 'deploy/testnet/Dockerfile.rpc.dockerignore',
                'deploy/testnet/faucet/.dockerignore', 'deploy/testnet/faucet/Dockerfile.gateway.dockerignore',
                'deploy/testnet/faucet/Dockerfile.backend.dockerignore',
                'deploy/testnet/artifacts/.dockerignore', 'deploy/testnet/artifacts/Dockerfile.dockerignore')


def key():
    h = hashlib.sha256()
    for f in build_inputs():
        h.update(f.encode() + b'\0' + hashlib.sha256((REPO / f).read_bytes()).digest())
    for f in IGNORE_FILES:
        path = REPO / f
        h.update(f.encode() + b'\0' + (hashlib.sha256(path.read_bytes()).digest() if path.is_file() else b'absent'))
    # the toolchains the build uses from the runner: go (setup-go, from this checkout's go.mod) and the default rustc; the runner image
    for tool in (['go', 'version'], ['rustc', '-V'], ['cargo', '-V']):
        h.update(out(*tool).encode() + b'\0')
    image = f"{os.environ.get('ImageOS', 'unknown')}-{os.environ.get('RUNNER_ARCH', 'unknown')}"
    pins = json.loads((TESTNET / 'pins.json').read_text())
    print(f"key=rehearsal-build-v1-{pins['bft'][:12]}-{h.hexdigest()[:24]}-{image}")


def main(argv):
    if argv[1:] == ['key']:
        return key()
    if len(argv) < 3 or argv[1] not in ('pack', 'unpack'):
        raise SystemExit(__doc__)
    (pack if argv[1] == 'pack' else unpack)(argv[2], tools(argv[3:]))


if __name__ == '__main__':
    main(sys.argv)
