import hashlib
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent / 'bridge/nb2'))
import export_origin


class Nb2OriginExport(unittest.TestCase):
    genesis = '0x' + '1' * 64
    pinned_head = '0x' + '2' * 64
    new_head = '0x' + '3' * 64
    trust_pin = '0x' + '4' * 64
    registry_hash = '0x' + '5' * 64

    def setUp(self):
        temp = self.enterContext(tempfile.TemporaryDirectory())
        self.generation = Path(temp) / 'generation'
        self.release_dir = Path(temp) / 'release'
        self.generation.mkdir()
        self.release_dir.mkdir()
        self.destination = self.release_dir / 'nb2-origin.json'
        manifest = dict(generation='test-generation', genesis_hash=self.genesis, chain_id=12345,
                        utb={'genesis_id': self.trust_pin})
        (self.generation / 'manifest.json').write_text(json.dumps(manifest))
        release = dict(schema='unicity-nb2-release', version='1.1', status='testnet-provisional',
                       realValueAuthorized=False, package=dict(generation=manifest['generation'],
                       genesisHash=self.genesis, chainId=manifest['chain_id']),
                       trust=dict(genesisEntryId=self.trust_pin,
                                  origin=dict(blockHash=self.pinned_head, blockNumber=80, usableEpoch='1', rootRound='1000')),
                       deployment={'contracts': {'registry': {'address': export_origin.bridge.REGISTRY,
                                                               'runtimeCodeHash': self.registry_hash}}})
        self.release_path = self.release_dir / 'nb2-release.json'
        self.release_path.write_text(json.dumps(release))
        self.digest = hashlib.sha256(self.release_path.read_bytes()).hexdigest()
        self.head = dict(hash=self.new_head, number=hex(95))
        self.root_round = 1450
        self.checks = []

    def hash_bytes(self, data):
        if data == b'\x01':
            return self.registry_hash
        self.assertIn(data, (b'unicity.seal-registry/origin.rootEpoch', b'unicity.seal-registry/clock.rootRound'))
        return data.decode()

    def query(self, method, *params):
        if method == 'eth_getBlockByNumber':
            self.assertFalse(params[1])
            return {'hash': self.genesis} if params[0] == '0x0' else self.head
        if method == 'eth_chainId':
            return hex(12345)
        self.checks.append((method, params[-1]))
        self.assertEqual(params[0], export_origin.bridge.REGISTRY)
        if method == 'eth_getCode':
            return '0x01'
        self.assertEqual(method, 'eth_getStorageAt')
        return '0x1' if params[1].endswith('origin.rootEpoch') else hex(self.root_round)

    def export(self):
        return export_origin.export(self.generation, self.release_dir, self.digest, self.query, self.hash_bytes)

    def test_both_origin_words_and_runtime_use_the_same_canonical_finalized_hash(self):
        record = self.export()
        self.assertEqual(self.checks, [(method, {'blockHash': self.new_head, 'requireCanonical': True})
                                        for method in ('eth_getCode', 'eth_getStorageAt', 'eth_getStorageAt')])
        self.assertEqual(json.loads(self.destination.read_text()), record)
        self.assertEqual(record, dict(schema='unicity-nb2-origin', version=1, network=3, generation='test-generation',
                                      genesisHash=self.genesis, releaseSha256=self.digest, blockHash=self.new_head,
                                      blockNumber=95, usableEpoch='1', rootRound='1450'))
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o644)
        self.assertEqual(hashlib.sha256(self.release_path.read_bytes()).hexdigest(), self.digest)

    def test_export_replaces_checkpoint_atomically_and_leaves_old_inode_intact(self):
        original = self.export()
        with self.destination.open() as held:
            self.head = dict(hash='0x' + '6' * 64, number=hex(96))
            self.root_round += 10
            successor = self.export()
            self.assertEqual(json.load(held), original)
            self.assertEqual(json.loads(self.destination.read_text()), successor)
        self.assertEqual(list(self.release_dir.glob('.nb2-origin-*')), [])

    def test_rejects_rollback_incompatible_same_block_and_release_drift(self):
        original = self.export()
        self.head = dict(hash='0x' + '6' * 64, number=hex(95))
        with self.assertRaisesRegex(ValueError, 'conflicts'):
            self.export()
        self.head = dict(hash='0x' + '6' * 64, number=hex(96))
        self.root_round -= 10
        with self.assertRaisesRegex(ValueError, 'rolls back'):
            self.export()
        self.release_path.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'staged release SHA-256'):
            self.export()
        self.assertEqual(json.loads(self.destination.read_text()), original)


if __name__ == '__main__':
    unittest.main()
