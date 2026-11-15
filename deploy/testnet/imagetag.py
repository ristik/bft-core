"""Image tags of the testnet package (bft-core#1092). A build leaves an immutable tag per pin and per image ID on what it built, never moves an
existing one, and returns the image ID: every record (artifacts/images.json, artifacts/bridge-images.json) and every compose file names images by
ID or digest. `tnops-<kind>:verified` stays as a convenience alias for humans; nothing in the package resolves through it. A later build used to
re-tag `:verified`, which left the previous generation's image dangling, and a prune of dangling images then deleted it."""
import pathlib
import re
import subprocess
import tempfile

IMMUTABLE = re.compile(r'(sha256:[0-9a-f]{64}|[^\s@]+@sha256:[0-9a-f]{64})')


def immutable_tag(kind, pin, image_id):
    """The tag a build leaves on its image (bft-core#1092): per pin and per image, so no later build can move it and leave a generation's image
    dangling (a prune would delete it). Everything the package records and runs names the image by its ID, never by a tag."""
    return f'tnops-{kind}:{pin}-{image_id.split(":", 1)[1][:12]}'


def build(kind, pin, *args):
    """docker build without a mutable tag: the ID from --iidfile, then the immutable tag; `tnops-<kind>:verified` is set last as a convenience
    alias for humans only (nothing in the package resolves through it)."""
    with tempfile.TemporaryDirectory() as tmp:
        iid = pathlib.Path(tmp) / 'iid'
        subprocess.run(['docker', 'build', '--iidfile', str(iid), *args], check=True)
        image_id = iid.read_text().strip()
    tag = immutable_tag(kind, pin, image_id)
    existing = subprocess.run(['docker', 'image', 'inspect', '--format={{.Id}}', tag], capture_output=True, text=True)
    if existing.returncode == 0 and existing.stdout.strip() != image_id:
        raise SystemExit(f'{tag} already names {existing.stdout.strip()}, not {image_id}: an immutable tag is never moved')
    subprocess.run(['docker', 'tag', image_id, tag], check=True)
    subprocess.run(['docker', 'tag', image_id, f'tnops-{kind}:verified'], check=True)
    return image_id, tag


def mutable_images(compose):
    """The services of a compose document whose image is not an image ID or a digest-pinned reference (a tag can be moved)."""
    return sorted(name for name, svc in (compose.get('services') or {}).items() if 'image' in svc and not IMMUTABLE.fullmatch(str(svc['image'])))

