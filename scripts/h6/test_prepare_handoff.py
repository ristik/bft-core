"""In-process checks of prepare-handoff.py against fake loopback roots: no devnet, no node, no lock.

    python3 -m unittest discover -s scripts/h6 -p 'test_prepare_handoff.py' -v
"""
import base64
import contextlib
import hashlib
import http.server
import importlib.util
import io
import json
from pathlib import Path
import re
import tempfile
import threading
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('prepare_handoff', HERE / 'prepare-handoff.py')
ph = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ph)

ROOTS = ['root-a', 'root-b', 'root-c', 'root-d']
BODY = b'canonical-v3-body'
PREDECESSOR = '0x' + 'ab' * 32


def trust(epoch, weights=(1, 1, 1, 1)):
    return {'networkId': 3, 'epoch': epoch, 'rootNodes': [{'nodeId': n, 'stake': w} for n, w in zip(ROOTS, weights)]}


class FakeRoot:
    """One root's operator API. `prepared_after` refusals of endorse mimic a Prepare that is not committed yet."""

    def __init__(self, state):
        self.state = state
        self.calls = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])) or b'null')
                route = self.path.removeprefix('/api/v1/handoff/')
                outer.calls.append((route, body))
                status, reply = outer.state.handle(outer, route, body)
                data = json.dumps(reply).encode() if not isinstance(reply, str) else reply.encode()
                self.send_response(status)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = 'http://127.0.0.1:%d' % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class Cluster:
    def __init__(self, ack_pending=False, receipts_in_plan=True, body=BODY, committed_after_endorsements=None):
        self.ack_pending, self.receipts_in_plan, self.body = ack_pending, receipts_in_plan, body
        self.endorsed = 0
        self.not_prepared = 1
        self.committed_after = committed_after_endorsements
        self.lock = threading.Lock()
        self.roots = [FakeRoot(self) for _ in ROOTS]

    def urls(self):
        return ','.join(r.url for r in self.roots)

    def close(self):
        for r in self.roots:
            r.close()

    def handle(self, root, route, body):
        with self.lock:
            if route == 'evm-assignment/context':
                return 200, {'network': 3, 'predecessor': PREDECESSOR, 'attempt': 4, 'acknowledgementPending': self.ack_pending}
            if route == 'plan':
                if not body.get('q3Receipts') and not body.get('q3'):
                    return 422, 'handoff approval refused: this epoch is a V3 (weighted) epoch: plan with --q3 or --readiness-receipts'
                plan = {'Body': base64.b64encode(self.body).decode(), 'Attempt': 4}
                if self.receipts_in_plan:
                    plan['Receipts'] = body['q3Receipts']
                return 200, plan
            if route == 'intent':
                return 204, ''
            if route == 'endorse':
                if self.not_prepared:
                    self.not_prepared -= 1
                    return 422, 'endorsement refused before the handoff is prepared'
                self.endorsed += 1
                return 204, ''
            if route == 'abort/status':
                committed = self.committed_after is not None and self.endorsed >= self.committed_after
                return 200, {'state': 'too_late' if committed else 'pending'}
        return 404, 'unknown'


class Files(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.write('old.json', trust(1))
        self.write('next.json', trust(2, (6, 1, 1, 1)))
        for n in ROOTS:
            self.write('receipt-%s.json' % n, {'nodeId': n, 'signature': '0x' + hashlib.sha256(n.encode()).hexdigest()})
        self.body_id = hashlib.sha256(BODY).hexdigest()
        (self.dir / 'v3-body-id.txt').write_text(self.body_id + '\n')

    def write(self, name, obj):
        (self.dir / name).write_text(json.dumps(obj))

    def receipts(self, names=ROOTS):
        return ','.join(str(self.dir / ('receipt-%s.json' % n)) for n in names)

    def argv(self, urls, out='evidence', receipts=None, extra=()):
        return ['--next-trust-base', str(self.dir / 'next.json'), '--old-trust-base', str(self.dir / 'old.json'),
                '--receipts', receipts or self.receipts(), '--v3-body-id', str(self.dir / 'v3-body-id.txt'),
                '--root-rpc', urls, '--out', str(self.dir / out), *extra]

    def helper(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = ph.main(argv)
        return code, out.getvalue()


class Encoding(unittest.TestCase):
    def test_the_receipt_set_is_the_go_encoders_bytes(self):
        go = (HERE.parents[1] / 'q3format/receipt_wire_vector_test.go').read_text()
        vector = re.search(r'receiptWireVector = "([0-9a-f]+)"', go).group(1)
        # listed out of order: the canonical set is ordered by node id
        receipts = [{'nodeId': 'root-02', 'signature': '0x0a'}, {'nodeId': 'root-01', 'signature': '0x' + b'12345678901234567890123456789012'.hex()}]
        self.assertEqual(ph.encode_receipts(receipts).hex(), vector)

    def test_long_sets_and_signatures_use_the_shortest_head(self):
        self.assertEqual(ph.head(4, 23), b'\x97')
        self.assertEqual(ph.head(4, 24), b'\x98\x18')
        self.assertEqual(ph.head(2, 65), b'\x58\x41')
        self.assertEqual(ph.head(2, 256), b'\x59\x01\x00')

    def test_duplicates_and_empty_sets_are_refused(self):
        with self.assertRaises(ph.Stop):
            ph.encode_receipts([{'nodeId': 'a', 'signature': '00'}, {'nodeId': 'a', 'signature': '01'}])
        with self.assertRaises(ph.Stop):
            ph.encode_receipts([])


class DryRun(Files):
    def test_validates_and_contacts_nothing(self):
        # no root listens on these ports: a contacted URL would fail the run
        code, out = self.helper(self.argv('http://127.0.0.1:1,http://127.0.0.1:2,http://127.0.0.1:3,http://127.0.0.1:4', extra=['--dry-run']))
        self.assertEqual(code, 0)
        self.assertIn('DRY RUN', out)
        self.assertFalse((self.dir / 'evidence').exists())

    def test_a_successor_that_is_not_the_next_epoch(self):
        self.write('next.json', trust(3))
        with self.assertRaises(ph.Stop) as raised:
            self.helper(self.argv('http://127.0.0.1:1,http://127.0.0.1:2,http://127.0.0.1:3,http://127.0.0.1:4', extra=['--dry-run']))
        self.assertIn('next epoch', str(raised.exception))

    def test_a_missing_receipt(self):
        with self.assertRaises(ph.Stop) as raised:
            self.helper(self.argv('http://127.0.0.1:1,http://127.0.0.1:2,http://127.0.0.1:3,http://127.0.0.1:4', receipts=self.receipts(ROOTS[:3]), extra=['--dry-run']))
        self.assertIn('one q3-readiness receipt per successor entity', str(raised.exception))
    def test_a_stranger_receipt(self):
        self.write('receipt-root-z.json', {'nodeId': 'root-z', 'signature': '0x01'})
        with self.assertRaises(ph.Stop):
            self.helper(self.argv('http://127.0.0.1:1,http://127.0.0.1:2,http://127.0.0.1:3,http://127.0.0.1:4', receipts=self.receipts(ROOTS[:3] + ['root-z']), extra=['--dry-run']))
    def test_non_loopback_and_wrong_member_counts(self):
        for urls in ('http://10.0.0.1:1,http://127.0.0.1:2,http://127.0.0.1:3,http://127.0.0.1:4', 'http://127.0.0.1:1,http://127.0.0.1:2,http://127.0.0.1:3',
                     'http://127.0.0.1:1,http://127.0.0.1:1,http://127.0.0.1:3,http://127.0.0.1:4'):
            with self.assertRaises(ph.Stop):
                self.helper(self.argv(urls, extra=['--dry-run']))
    def test_a_lone_endorsement_that_reaches_the_quorum_is_refused_but_endorse_all_is_not(self):
        self.write('old.json', trust(1, (7, 1, 1, 1)))
        urls = 'http://127.0.0.1:1,http://127.0.0.1:2,http://127.0.0.1:3,http://127.0.0.1:4'
        with self.assertRaises(ph.Stop) as raised:
            self.helper(self.argv(urls, extra=['--dry-run']))
        self.assertIn('stay pre-H', str(raised.exception))
        self.assertEqual(self.helper(self.argv(urls, extra=['--dry-run', '--endorse-all']))[0], 0)


class AgainstFakeRoots(Files):
    def cluster(self, **kw):
        c = Cluster(**kw)
        self.addCleanup(c.close)
        return c

    def test_interrupts_after_one_endorsement_and_leaves_the_abort_target(self):
        c = self.cluster()
        code, out = self.helper(self.argv(c.urls()))
        self.assertEqual(code, 0)
        self.assertIn('PASS: authenticated target is pending', out)
        evidence = self.dir / 'evidence'
        target = json.loads((evidence / 'target.json').read_text())
        self.assertEqual(target, {'network': 3, 'oldEpoch': 1, 'predecessorBodyId': PREDECESSOR, 'attempt': 4, 'nextBodyId': '0x' + self.body_id})
        wire = json.loads((evidence / 'target-wire.json').read_text())
        self.assertEqual(base64.b64decode(wire['nextBodyId']).hex(), self.body_id)
        self.assertEqual(c.endorsed, 1)
        routes = [[call[0] for call in r.calls] for r in c.roots]
        self.assertEqual(routes[0][:2], ['evm-assignment/context', 'plan'])
        self.assertEqual(routes[0].count('endorse'), 2)   # one refusal before the Prepare, then the endorsement
        for later in routes[1:]:
            self.assertEqual(later, ['intent'])
        # the plan request is a V3 plan with exactly the canonical receipt set of the successor entities
        plan_call = next(body for route, body in c.roots[0].calls if route == 'plan')
        expected = ph.encode_receipts(ph.read_receipts(self.receipts().split(',')))
        self.assertEqual(plan_call['q3Receipts'], '0x' + expected.hex())
        self.assertEqual(plan_call['nextTrustBase']['epoch'], 2)

    def test_endorse_all_ends_with_too_late(self):
        c = self.cluster(committed_after_endorsements=3)
        code, out = self.helper(self.argv(c.urls(), extra=['--endorse-all']))
        self.assertEqual(code, 0)
        self.assertIn('PASS: authenticated target is too_late', out)
        self.assertEqual(c.endorsed, 4)
        self.assertTrue(all(r['accepted'] for r in json.loads((self.dir / 'evidence/endorsements.json').read_text())))

    def test_a_plan_without_receipts_is_not_taken_for_a_v3_plan(self):
        c = self.cluster(receipts_in_plan=False)
        with self.assertRaises(ph.Stop) as raised:
            self.helper(self.argv(c.urls()))
        self.assertIn('not a V3 plan', str(raised.exception))
        self.assertEqual(c.endorsed, 0)

    def test_a_plan_for_another_body_than_the_candidates_is_refused_before_any_endorsement(self):
        c = self.cluster(body=b'another-body')
        with self.assertRaises(ph.Stop) as raised:
            self.helper(self.argv(c.urls()))
        self.assertIn('another body than the q3-candidate', str(raised.exception))
        self.assertEqual(c.endorsed, 0)
        self.assertFalse(any(route == 'intent' for r in c.roots for route, _ in r.calls))

    def test_a_pending_assignment_acknowledgement_stops_before_any_plan(self):
        c = self.cluster(ack_pending=True)
        with self.assertRaises(ph.Stop) as raised:
            self.helper(self.argv(c.urls()))
        self.assertIn('acknowledgement is pending', str(raised.exception))
        self.assertEqual([route for route, _ in c.roots[0].calls], ['evm-assignment/context'])

    def test_the_evidence_directory_is_new(self):
        c = self.cluster()
        (self.dir / 'evidence').mkdir()
        with self.assertRaises(FileExistsError):
            self.helper(self.argv(c.urls()))
        self.assertEqual(c.roots[0].calls, [])


if __name__ == '__main__':
    unittest.main()
