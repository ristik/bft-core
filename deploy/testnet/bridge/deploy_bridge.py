#!/usr/bin/env python3
"""The bridge tools image and how a generation runs it: what nb2/deploy_nb2.py, nb2/release_nb2.py and sdk_clients.py share.

  image(gen)              the bridge tools image by its ID (bft-core#1092): a deployed generation's own record, else the current
                          artifacts/bridge-images.json, refused unless its dnb-tool was built from the node images' bft pin (bft-core#1075)
  record_image(gen, id)   the generation's record of the image it was deployed with (GENERATION/bridge/bridge-image.json), written once
  validators_network(gen) the Compose network of the generation's validators
  tools(gen, *args)       one command in the image on that network: the public network files and the faucet's keystore read-only, GENERATION/bridge
                          writable at /work

This module deploys nothing itself. The protocol 6/7 bridge it used to deploy (BridgeVault, TokenVerifier, the lock-proof endpoint, the tester) was
removed by bft-core#1106 and #1139; the native bridge v2 deploy is nb2/deploy_nb2.py.
"""
import json
import os
import re
import subprocess
from pathlib import Path

ARTIFACTS = Path(__file__).resolve().parent.parent / 'artifacts'
RECORD = 'bridge/bridge-image.json'   # the generation's own record of its bridge image, written by its deploy
IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}')


def bridge_image(record, node_pins):
    """The verified bridge image of artifacts/bridge-images.json, refused unless its dnb-tool was built from the node images' bft pin: dnb-tool
    reads the validators' trust base and archives, so it must speak their layout (bft-core#1075)."""
    image = record.get('images', {}).get('bridge', '')
    if not IMAGE_ID.fullmatch(image):
        raise SystemExit('artifacts/bridge-images.json has no verified bridge image (build-bridge-image.py)')
    built = record.get('sources', {}).get('bft')
    if built != node_pins['bft']:
        raise SystemExit(f'artifacts/bridge-images.json: dnb-tool was built from bft {built}, but the node images are pinned at {node_pins["bft"]} '
                         '(deploy/testnet/pins.json): rebuild it, build-bridge-image.py --bft-source <the pinned bft checkout>')
    return image


def recorded_image(gen):
    """The bridge image a generation was deployed with (GENERATION/bridge/bridge-image.json); None for a generation not deployed yet."""
    if gen is None:
        return None
    own = Path(gen) / RECORD
    return json.loads(own.read_text())['image'] if own.is_file() else None


def image(gen=None):
    """The bridge tools image by ID (bft-core#1092), never through a tag a later build can move. A deployed generation keeps the image it was
    deployed with (recorded_image), so a later rebuild for another pin never changes an older generation's tools. Only a generation being deployed
    takes the current artifacts/bridge-images.json, which must have been built from the node images' bft pin (bft-core#1075). The image must be
    present locally."""
    found = recorded_image(gen)
    if found is None:
        record = json.loads((ARTIFACTS / 'bridge-images.json').read_text())
        found = bridge_image(record, json.loads((ARTIFACTS.parent / 'pins.json').read_text()))
    elif not IMAGE_ID.fullmatch(str(found)):
        raise SystemExit(f'{gen}: the recorded bridge image {found!r} is not an image ID')
    if subprocess.run(['docker', 'image', 'inspect', found], capture_output=True).returncode != 0:
        raise SystemExit(f'the bridge image {found} is not in the local image store: rebuild it (build-bridge-image.py)')
    return found


def record_image(gen, found):
    """Written once, at the generation's deploy: the bridge image its tools keep using after later rebuilds."""
    own = Path(gen) / RECORD
    if not own.is_file():
        own.write_text(json.dumps({'image': found}, indent=2) + '\n')


def validators_network(gen):
    # Compose names a project's networks <project>_<network>; the project is the generation's
    name = json.loads(subprocess.check_output(['docker', 'compose', '-f', str(gen / 'compose.yaml'), 'config', '--format', 'json'], text=True))['name']
    return f'{name}_validators'


def tools(gen, *args, capture=False):
    # only the public network files and the faucet's keystore, read-only (never the validators' or owners' keys); the bridge directory writable at
    # /work; the image itself is read-only. HOME and every scratch copy live on the tmpfs: GENERATION/bridge is backed up with the generation, and
    # backup.py restores plain files and directories only
    cmd = ['docker', 'run', '--rm', '--read-only', '--network', validators_network(gen), '--user', f'{os.getuid()}:{os.getgid()}', '-e', 'HOME=/tmp/home',
           '-v', f'{gen / "network"}:/gen/network:ro', '-v', f'{gen / "faucet-secrets"}:/gen/faucet-secrets:ro', '-v', f'{gen / "bridge"}:/work',
           '--tmpfs', '/tmp', '-w', '/work', image(gen), *args]
    return subprocess.run(cmd, check=True, text=True, capture_output=capture).stdout
