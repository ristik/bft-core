#!/usr/bin/env python3
"""Verify the announced validator bundle and its Docker OCI archive before import."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile


ARCHIVE = 'validator-image.tar.gz'
IMAGE_MANIFEST = 'application/vnd.oci.image.manifest.v1+json'


def digest(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def blob_path(digest_value):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest_value):
        raise ValueError('expected a SHA-256 OCI descriptor')
    return 'blobs/sha256/' + digest_value.removeprefix('sha256:')


def verify_archive(path, image_id, platform):
    with tarfile.open(path, 'r:gz') as archive:
        members = {}
        for member in archive:
            if member.name in members:
                raise ValueError(f'duplicate archive member {member.name}')
            members[member.name] = member

        def member_file(name):
            member = members.get(name)
            if member is None or not member.isfile():
                raise ValueError(f'missing regular archive member {name}')
            return member

        def read_json(name, descriptor=None):
            member = member_file(name)
            if member.size > 1 << 20:
                raise ValueError(f'archive metadata too large: {name}')
            with archive.extractfile(member) as file:
                raw = file.read()
            if descriptor and (len(raw) != descriptor['size'] or
                               'sha256:' + hashlib.sha256(raw).hexdigest() != descriptor['digest']):
                raise ValueError(f'archive descriptor does not match {name}')
            return json.loads(raw)

        entries = read_json('index.json')['manifests']
        if len(entries) != 1 or entries[0]['mediaType'] != IMAGE_MANIFEST or entries[0]['digest'] != image_id:
            raise ValueError('archive OCI image does not match the pinned image ID')
        image = read_json(blob_path(image_id), entries[0])
        config_name = blob_path(image['config']['digest'])
        config = read_json(config_name, image['config'])
        if platform != 'linux/amd64' or f"{config['os']}/{config['architecture']}" != platform:
            raise ValueError('archive image does not match the linux/amd64 platform')
        layers = []
        for layer in image['layers']:
            name = blob_path(layer['digest'])
            if member_file(name).size != layer['size']:
                raise ValueError(f'archive layer length differs from the pinned OCI manifest: {name}')
            layers.append(name)
        # Docker archives also carry a compatibility manifest. It must describe the same image.
        legacy = read_json('manifest.json')
        if len(legacy) != 1 or legacy[0]['Config'] != config_name or legacy[0]['Layers'] != layers:
            raise ValueError('Docker archive manifest differs from the pinned OCI image')


def verified_bundle(bundle, expected_checksums):
    checksums = (bundle/'SHA256SUMS').read_bytes()
    if hashlib.sha256(checksums).hexdigest() != expected_checksums:
        raise ValueError('bundle SHA256SUMS differs from the authenticated digest')
    pinned = {}
    for line in checksums.decode().splitlines():
        checksum, name = line.split('  ', 1)
        if name in pinned or not re.fullmatch(r'[a-z0-9][a-z0-9.-]*', name):
            raise ValueError('invalid checksum manifest member')
        pinned[name] = checksum
    raw_manifest = (bundle/'manifest.json').read_bytes()
    if hashlib.sha256(raw_manifest).hexdigest() != pinned['manifest.json']:
        raise ValueError('bundle manifest checksum mismatch')
    manifest = json.loads(raw_manifest)
    path = bundle/ARCHIVE
    if manifest['archive'] != ARCHIVE or digest(path) != manifest['archiveSha256'] or pinned[ARCHIVE] != manifest['archiveSha256']:
        raise ValueError('archive checksum differs from the authenticated bundle manifest')
    verify_archive(path, manifest['imageId'], manifest['platform'])
    return path, manifest['imageId']


def load_bundle(bundle, expected_checksums):
    archive, image_id = verified_bundle(bundle, expected_checksums)
    subprocess.run(['docker', 'load', '-i', str(archive)], check=True, stdout=sys.stderr)
    return image_id


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('bundle', type=Path)
    cli.add_argument('checksums', help='SHA-256 of SHA256SUMS from the authenticated announcement')
    cli.add_argument('--verify-only', action='store_true')
    args = cli.parse_args()
    try:
        if args.verify_only:
            _, image_id = verified_bundle(args.bundle, args.checksums)
        else:
            image_id = load_bundle(args.bundle, args.checksums)
        print(image_id)
    except (ValueError, TypeError, KeyError, OSError, tarfile.TarError, subprocess.CalledProcessError) as exc:
        cli.exit(1, f'verify validator image: {exc}\n')


if __name__ == '__main__':
    main()
