"""Structural model of native bridge v2 redemption segments (docs/design/native-bridge-v2.md).

Run: python3 docs/design/models/nb2_segments.py

Part 1 is the model cited by the design's validation record (briefs/native-bridge-checkpoint-segments-design-v2.md,
"Validation record"), recovered from the session that produced it; the one change is that the historical-proof check now
runs before the recent-buffer scan, as in the spec's section 11.1 (boolean acceptance is unchanged). It covers the
sorted circular-gap tree, index-only burns with unsigned starting heads, and the v2 per-bucket layout. It must print 12672 gap cases, 18914
replay/forged-header checks and 48 sealed segments.

Part 2 adds the position-tag layout of review amendment R2 (the spec's baseline), the seal-receipt index rule of R1 and
the packed accounting word of R2, and runs both layouts on one workload: every accept/reject outcome and every archive
head must be equal, and both must match an unbounded reference paid set.

Scope: SHA-256 stands in for keccak256 and CBOR is absent, so these are not production vectors (NB2-03, #1099, owns
those). The model validates the replay relation and buffer bookkeeping under an ideal verifier (the identity on
(eta, a)) and assumed-authentic seal receipts. It does not execute deposit/receipt verification, amount accounting,
payout rollback or error classification, and says nothing about gas. The archive the harness retains is witness-
generation data, not proposed vault storage. Packed-field tests check representation isolation only.
"""

from copy import deepcopy
from hashlib import sha256
from itertools import combinations
from random import Random


def H(*xs):
    return sha256(b''.join(xs)).digest()


def w(x):
    return x.to_bytes(32, 'big')


# ---- Part 1: the cited model (circular-gap tree, v2 sparse buckets) ------------------------------------------------

def build(xs):
    z = sorted(xs)
    assert len(z) == len(set(z))
    n = len(z)
    levels = [[H(b'\x00', w(z[i]), w(z[(i + 1) % n])) for i in range(n)]]
    while len(levels[-1]) > 1:
        a = levels[-1]
        levels.append([H(b'\x01', a[i], a[i + 1]) for i in range(0, len(a), 2)])
    return z, levels


def gap_proof(x, xs):
    z, lv = build(xs)
    n = len(z)
    for i, l in enumerate(z):
        u = z[(i + 1) % n]
        if (i < n - 1 and l < x < u) or (i == n - 1 and (x > l or x < u)):
            sib = []
            pos = i
            for row in lv[:-1]:
                sib.append(row[pos ^ 1])
                pos //= 2
            return i, l, u, sib
    return None


def gap_root(x, n, p):
    if p is None:
        return None
    i, l, u, ss = p
    if not 0 <= i < n or len(ss) != n.bit_length() - 1:
        return None
    if not ((i < n - 1 and l < u and l < x < u) or (i == n - 1 and l > u and (x > l or x < u))):
        return None
    r = H(b'\x00', w(l), w(u))
    pos = i
    for s in ss:
        r = H(b'\x01', r, s) if pos % 2 == 0 else H(b'\x01', s, r)
        pos //= 2
    return r


checks = 0
for k in (2, 4, 8):
    for xs in combinations(range(12), k):
        root = build(xs)[1][-1][0]
        for x in range(12):
            assert (gap_root(x, k, gap_proof(x, xs)) == root) == (x not in xs)
            checks += 1

MARK = 1 << 255
MASK64 = (1 << 64) - 1
MASK192 = (1 << 192) - 1


def pack(g, m, counts):
    assert 0 <= g <= MASK64 and 0 <= m < 256 and len(counts) == 16
    assert sum(counts) == m and all(0 <= q < 256 for q in counts)
    return MARK | g | (m << 64) | sum(q << (72 + 8 * b) for b, q in enumerate(counts))


def unpack(v):
    assert v >> 255 == 1 and (v >> 200) & ((1 << 55) - 1) == 0
    return v & MASK64, (v >> 64) & 255, [(v >> (72 + 8 * b)) & 255 for b in range(16)]


def historical(v, x, a, e, start, ps):
    """Fold the gap proofs of segments a..e-1 from the unsigned start head to the stored head H_e (P = 0: no head)."""
    if not ps:
        return start is None
    r = start
    if not isinstance(r, bytes):
        return False
    for j, pr in enumerate(ps, a):
        root = gap_root(x, v.k, pr)
        if root is None:
            return False
        r = H(b'archive', w(j), r, root)
    return r == v.heads[e]


class Vault:
    """v2 layout: per-bucket slot arrays, generation/count metadata words W0, W1."""

    def __init__(self, k):
        self.k = k
        self.meta = [pack(1, 0, [0] * 16), pack(0, 0, [0] * 16)]
        self.slots = [[[None] * k for _ in range(16)] for _ in range(2)]
        self.heads = [H(b'genesis')]
        self.segs = []
        self.reference = set()

    def state(self):
        a = [unpack(v) for v in self.meta]
        c = max(t[0] for t in a) - 1
        p = c % 2
        assert a[p][0] == c + 1 and a[p][1] < self.k
        assert sum(a[p][2]) == a[p][1]
        assert a[1 - p][0] == c and a[1 - p][1] == (self.k if c else 0)
        return c, p, a

    def current(self):
        return self.state()[0]

    def witness(self, x, a, e=None):
        c = self.current()
        e = c if e is None else e
        if not 0 <= a <= e <= c:
            return (a, e, None, [])
        ps = [gap_proof(x, xs) for xs in self.segs[a:e]]
        return a, e, self.heads[a] if e > a else None, ps

    def early(self, x, wi):
        a, e, start, ps = wi
        c, p, ms = self.state()
        if not 0 <= a <= c or e not in ([c, c - 1] if c else [0]) or e != a + len(ps):
            return False
        # Historical proofs first, then the recent buffers (spec section 11.1 order).
        if not historical(self, x, a, e, start, ps):
            return False
        b = x >> 252
        for q in ([p, 1 - p] if e == c - 1 else [p]):
            if x in self.slots[q][b][:ms[q][2][b]]:
                return False
        return True

    def pay(self, real_x, real_a, claim_x, wi):
        if not self.early(claim_x, wi):
            return False
        if (real_x, real_a) != (claim_x, wi[0]):
            return False
        assert real_x not in self.reference
        self.reference.add(real_x)
        c, p, ms = self.state()
        g, m, qs = ms[p]
        b = real_x >> 252
        self.slots[p][b][qs[b]] = real_x
        qs[b] += 1
        m += 1
        self.meta[p] = pack(g, m, qs)
        if m == self.k:
            z = []
            for b in range(16):
                z.extend(sorted(self.slots[p][b][:qs[b]]))
            assert z == sorted(z) and len(z) == len(set(z)) == self.k
            root = build(z)[1][-1][0]
            self.segs.append(z)
            self.heads.append(H(b'archive', w(c), self.heads[-1], root))
            self.meta[1 - p] = pack(g + 1, 0, [0] * 16)
        self.state()
        return True


def workload(v, seed=15, rounds=200):
    """The cited scenario: severe grinding into bucket 0, out-of-order payment, replay and forged-claim probes."""
    rng = Random(seed)
    burns = {}
    paid_checks = 0
    pending = []
    log = []
    for i in range(1, rounds + 1):
        c = v.current()
        x = ((0 if i % 3 else i % 16) << 252) + i
        a = max(0, c - rng.randrange(0, min(c, 4) + 1))
        burns[x] = a
        pending.append((x, a, v.witness(x, a)))
        if len(pending) > 7:
            x, a, wi = pending.pop(rng.randrange(len(pending)))
            first = v.pay(x, a, x, wi)
            log.append(first)
            if not first:
                assert v.pay(x, a, x, v.witness(x, a))
            for old in list(v.reference):
                r = v.pay(old, burns[old], old, v.witness(old, burns[old]))
                log.append(r)
                assert not r
                paid_checks += 1
            forged = (15 << 252) + 100000 + i
            wi2 = v.witness(forged, 0)
            assert v.early(forged, wi2)
            before = deepcopy(v.__dict__)
            assert not v.pay(x, a, forged, wi2)
            assert before == v.__dict__
            paid_checks += 1
    return paid_checks, log


def boundary_checks(cls):
    v = cls(4)
    workload(v, rounds=40)
    # An unsigned start-head error is repairable for exactly the same burn.
    x = (10 << 252) + 99999
    wi = v.witness(x, 0)
    bad = (wi[0], wi[1], H(b'wrong'), wi[3])
    assert not v.pay(x, 0, x, bad)
    assert v.pay(x, 0, x, wi)
    # Current snapshots span one rollover, but after two are stale.
    u = cls(4)
    ws = {i: u.witness(i, 0) for i in range(1, 10)}
    for i in range(1, 9):
        assert u.pay(i, 0, i, ws[i])
    assert not u.pay(9, 0, 9, ws[9])
    assert u.pay(9, 0, 9, u.witness(9, 0))
    # A genuine high index cannot redeem yet; it is not implicitly repaired.
    assert not u.pay(1000, 1000, 1000, (1000, 1000, None, []))


v = Vault(4)
paid_checks, v2_log = workload(v)
boundary_checks(Vault)
for n in (0, 1, MASK64):
    for q in (0, 1, MASK192):
        A = (n << 192) | q
        assert A >> 192 == n and A & MASK192 == q
        if q:
            assert ((A - 1) >> 192) == n
try:
    pack(1, 256, [256] + [0] * 15)
except AssertionError:
    pass
else:
    raise AssertionError('8-bit count overflow accepted')
part1 = {'gap_cases': checks, 'replay_or_header_checks': paid_checks, 'sealed_segments': len(v.segs)}
assert part1 == {'gap_cases': 12672, 'replay_or_header_checks': 18914, 'sealed_segments': 48}, part1


# ---- Part 2: position tags (R2), seal-receipt index (R1), packed accounting -----------------------------------------

# A = n (56 bits) || c (48) || m (8) || Q (144), the baseline widths of the spec for K=64, B=16.
N_BITS, C_BITS, M_BITS, Q_BITS = 56, 48, 8, 144
Q_SHIFT, M_SHIFT, C_SHIFT, N_SHIFT = 0, Q_BITS, Q_BITS + M_BITS, Q_BITS + M_BITS + C_BITS
assert N_SHIFT + N_BITS == 256


def field(A, shift, bits):
    return (A >> shift) & ((1 << bits) - 1)


def put(A, shift, bits, value):
    assert 0 <= value < 1 << bits, 'field overflow'
    return (A & ~(((1 << bits) - 1) << shift)) | (value << shift)


class TagVault:
    """R2 layout: flat arrival-order buffers S0, S1 and one packed tag word per buffer (b bits per position)."""

    def __init__(self, k, bucket_bits=4):
        self.k = k
        self.bb = bucket_bits
        self.per_word = 256 // bucket_bits
        self.A = 0
        self.T = [[0] * -(-k // self.per_word) for _ in range(2)]
        self.S = [[None] * k for _ in range(2)]
        self.heads = [H(b'genesis')]
        self.segs = []
        self.receipts = []  # SegmentSealed(j, H_j, H_{j+1}) as a wallet would hold verified receipts
        self.reference = set()

    def current(self):
        return field(self.A, C_SHIFT, C_BITS)

    def tag(self, p, i):
        return (self.T[p][i // self.per_word] >> (self.bb * (i % self.per_word))) & ((1 << self.bb) - 1)

    def set_tag(self, p, i, t):
        wi, sh = i // self.per_word, self.bb * (i % self.per_word)
        word = self.T[p][wi] & ~(((1 << self.bb) - 1) << sh)
        self.T[p][wi] = word | (t << sh)

    def bucket(self, x):
        return x >> (256 - self.bb)

    witness = Vault.witness

    def early(self, x, wi):
        a, e, start, ps = wi
        c = self.current()
        m = field(self.A, M_SHIFT, M_BITS)
        if not 0 <= a <= c or e not in ([c, c - 1] if c else [0]) or e != a + len(ps):
            return False
        if not historical(self, x, a, e, start, ps):
            return False
        b = self.bucket(x)
        p = c % 2
        for q, pop in ([(p, m), (1 - p, self.k)] if e == c - 1 else [(p, m)]):
            for i in range(pop):
                if self.tag(q, i) == b and self.S[q][i] == x:
                    return False
        return True

    def pay(self, real_x, real_a, claim_x, wi):
        if not self.early(claim_x, wi):
            return False
        if (real_x, real_a) != (claim_x, wi[0]):
            return False
        assert real_x not in self.reference
        self.reference.add(real_x)
        c = self.current()
        m = field(self.A, M_SHIFT, M_BITS)
        p = c % 2
        self.S[p][m] = real_x
        self.set_tag(p, m, self.bucket(real_x))
        m += 1
        if m == self.k:
            buckets = [[] for _ in range(1 << self.bb)]
            for i in range(self.k):
                buckets[self.tag(p, i)].append(self.S[p][i])
            z = [x for bk in buckets for x in sorted(bk)]
            assert z == sorted(z) and len(z) == len(set(z)) == self.k
            root = build(z)[1][-1][0]
            self.segs.append(z)
            self.heads.append(H(b'archive', w(c), self.heads[-1], root))
            self.receipts.append((c, self.heads[-2], self.heads[-1]))
            self.A = put(put(self.A, C_SHIFT, C_BITS, c + 1), M_SHIFT, M_BITS, 0)
        else:
            self.A = put(self.A, M_SHIFT, M_BITS, m)
        return True

    def index_from_receipt(self, hidden=0):
        """R1: sign a = j+1 from the newest verified SegmentSealed receipt; a provider may hide the newest `hidden`."""
        held = self.receipts[:len(self.receipts) - hidden] if hidden else self.receipts
        if not held:
            return 0, self.heads[0]
        j, _, after = held[-1]
        return j + 1, after


u = TagVault(4)
tag_checks, tag_log = workload(u)
boundary_checks(TagVault)
assert tag_checks == paid_checks and tag_log == v2_log, 'position tags and v2 buckets disagree'
assert u.heads == v.heads and u.segs == v.segs, 'archive chains differ between layouts'

# R1: an index taken from a verified seal receipt never exceeds c, equals c when nothing newer sealed, and its head is
# the chain head the wallet's gap folding starts from. Hiding receipts only lowers the index.
r1 = 0
for hidden in range(len(u.receipts) + 1):
    a, head = u.index_from_receipt(hidden)
    assert a <= u.current() and head == u.heads[a]
    if hidden == 0:
        assert a == u.current()
    r1 += 1
x = (7 << 252) + 424242
a, _ = u.index_from_receipt()
assert u.pay(x, a, x, u.witness(x, a))
a, _ = u.index_from_receipt(hidden=3)
x2 = (8 << 252) + 424243
assert u.pay(x2, a, x2, u.witness(x2, a))

# Concentrated buckets at K=8: every ID in one bucket, then alternating hot buckets; all three layouts agree with the
# reference set, and the worst previous-endpoint scan touches K + m <= 2K - 1 positions.
for hot in ([0] * 64, [i % 2 * 15 for i in range(64)]):
    va, vb = Vault(8), TagVault(8)
    for i, b in enumerate(hot, 1):
        x = (b << 252) + i
        for vv in (va, vb):
            c = vv.current()
            assert vv.pay(x, c, x, vv.witness(x, c))
            assert not vv.pay(x, c, x, vv.witness(x, max(0, vv.current() - 1)))
    assert va.heads == vb.heads and va.reference == vb.reference == {(b << 252) + i for i, b in enumerate(hot, 1)}

# Packed accounting: widths, no carry or borrow into a neighbouring field, checked exhaustion.
acct = 0
for shift, bits in ((N_SHIFT, N_BITS), (C_SHIFT, C_BITS), (M_SHIFT, M_BITS), (Q_SHIFT, Q_BITS)):
    for value in (0, 1, (1 << bits) - 1):
        A = put((1 << 256) - 1, shift, bits, value)
        assert field(A, shift, bits) == value
        for s2, b2 in ((N_SHIFT, N_BITS), (C_SHIFT, C_BITS), (M_SHIFT, M_BITS), (Q_SHIFT, Q_BITS)):
            if s2 != shift:
                assert field(A, s2, b2) == (1 << b2) - 1
        acct += 1
    try:
        put(0, shift, bits, 1 << bits)
    except AssertionError:
        acct += 1
    else:
        raise AssertionError('accounting field overflow accepted')

# Tag-word packing: tags per word is floor(256/b); words per buffer for every candidate (K, B).
words = {}
for k in (32, 64, 128):
    for bb in (3, 4, 5):
        t = TagVault(k, bb)
        for i in range(k):
            t.set_tag(0, i, (i * 7) % (1 << bb))
        assert all(t.tag(0, i) == (i * 7) % (1 << bb) for i in range(k))
        assert all(x < 1 << 256 for x in t.T[0])
        words[(k, 1 << bb)] = len(t.T[0])
assert words[(64, 16)] == 1 and words[(128, 16)] == 2 and words[(128, 32)] == 3 and words[(32, 8)] == 1

print({**part1, 'position_tag_layout': 'equal outcomes and heads', 'r1_index_checks': r1, 'accounting_checks': acct,
       'tag_words': {f'K={k},B={b}': n for (k, b), n in sorted(words.items())},
       'result': 'PASS', 'scope': 'structural model only; SHA-256 stand-in, no production vectors or EVM gas'})
