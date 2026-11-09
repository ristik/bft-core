"""What the three public SDK clients must report (bft-core #430 row 2), as plain checks with no dependency on the rehearsal: the driver
(bridge/sdk_clients.py) feeds each (ok, what, detail) to self.expect, and test/run_local.sh to test/check_local.py.

The clients verify the trust-base entry objects their SDK supports (TrustBaseSession + its file store); they are not bridge verifiers."""

# The typed refusal each SDK gives, by the name the client records. Rust has one error enum per layer, so its name is the path to the variant.
NEGATIVES = ('missingMiddle', 'belowQuorum', 'wrongNetwork')
TYPED = {
    'js': {'missingMiddle': 'TrustBaseGapError', 'belowQuorum': 'TrustBaseSignatureError', 'wrongNetwork': 'TrustBaseNetworkError'},
    'rust': {'missingMiddle': 'Refused(Gap)', 'belowQuorum': 'Refused(Entry(Signature))', 'wrongNetwork': 'Refused(WrongNetwork)'},
    'java': {'missingMiddle': 'TrustBaseGapException', 'belowQuorum': 'TrustBaseSignatureException', 'wrongNetwork': 'TrustBaseNetworkException'},
}


def check_runs(sdk, commit, runs, served, tip_range, min_tip=3, genesis=1):
    """runs: {'cold': json, 'warm': json, 'restart': json}; served: {epoch: entry id hex} of the aggregator's complete served history;
    tip_range: (lowest, highest) tip epoch the aggregator served around the runs. Returns [(ok, what, detail)]."""
    out = []

    def add(ok, what, detail=''):
        out.append((bool(ok), f'sdk-{sdk}: {what}', str(detail)))

    for mode in ('cold', 'warm', 'restart'):
        r = runs.get(mode)
        add(r is not None and 'error' not in r, f'{mode} run completed', (r or {}).get('error', 'missing') + ': ' + (r or {}).get('message', '') if not r or 'error' in r else '')
        if r is None or 'error' in r:
            continue
        ids = {int(k): v for k, v in r.get('entryIds', {}).items()}
        tip = r.get('tipEpoch')
        add(r.get('sdk') == sdk and r.get('commit') == commit, f'{mode}: the client is the pinned SDK commit', f"{r.get('sdk')} {r.get('commit')}")
        add(r.get('genesisEpoch') == min(ids, default=None) == genesis, f'{mode}: the history starts at the genesis epoch {genesis}', f"{r.get('genesisEpoch')}")
        add(isinstance(tip, int) and tip >= min_tip, f'{mode}: the verified tip is at least epoch {min_tip}', tip)
        add(isinstance(tip, int) and tip_range[0] <= tip <= tip_range[1], f'{mode}: the tip is the one the roots served', f'{tip} in {tip_range}')
        add(sorted(ids) == list(range(genesis, (tip or 0) + 1)), f'{mode}: a contiguous chain genesis..tip', sorted(ids))
        add(all(served.get(e) == i for e, i in ids.items()), f'{mode}: every reported EntryID is the roots\' served one', {e: i[:12] for e, i in ids.items() if served.get(e) != i})
        add(r.get('persisted') is True and r.get('flush', {}).get('status') == 'saved', f'{mode}: the history is persisted and re-verifies from the store', r.get('flush'))
    cold, warm, restart = (runs.get(m) or {} for m in ('cold', 'warm', 'restart'))
    if cold.get('tipEpoch') and 'error' not in cold:
        add(cold.get('heldAtOpen') == 1 and cold.get('fetched') == cold['tipEpoch'] - genesis, 'cold: empty store, trusts only the genesis pin, fetched every later entry', f"held {cold.get('heldAtOpen')}, fetched {cold.get('fetched')}")
    if warm.get('tipEpoch') and 'error' not in warm:
        add(warm.get('heldAtOpen') == 1 and warm.get('diagnostics') == [] and warm.get('fetched') == warm['tipEpoch'] - genesis,
            'warm: the seeded store holds the epoch-1 entry only and the rest is fetched', f"held {warm.get('heldAtOpen')}, fetched {warm.get('fetched')}, diagnostics {warm.get('diagnostics')}")
    if restart.get('tipEpoch') and cold.get('tipEpoch') and 'error' not in restart:
        # a fresh process reloads the history the cold run wrote; it fetches only what is newer than that (nothing, unless the chain advanced meanwhile)
        add(restart.get('heldAtOpen') == cold['tipEpoch'], 'restart: a fresh process reloads the held history from the store', f"held {restart.get('heldAtOpen')}, cold tip {cold['tipEpoch']}")
        add(restart.get('fetched') == restart['tipEpoch'] - restart.get('heldAtOpen', 0), 'restart: it fetched only the entries newer than the reloaded tip', f"fetched {restart.get('fetched')}")
        add(all(restart['entryIds'].get(k) == v for k, v in cold.get('entryIds', {}).items()), 'restart: the reloaded entries are the cold run\'s', '')
    neg = cold.get('negatives')
    add(isinstance(neg, dict), 'the typed negatives and their controls ran', '')
    for name in NEGATIVES:
        n = (neg or {}).get(name, {})
        add(n.get('refused') is True and n.get('typed') is True and n.get('error') == TYPED[sdk][name], f'negative {name}: refused with the SDK\'s typed error {TYPED[sdk][name]}', f"{n.get('error')}: {n.get('message')}")
        add(n.get('tipAfter') == genesis, f'negative {name}: nothing was appended by the refused entry', n.get('tipAfter'))
        c = n.get('control', {})
        add(c.get('accepted') is True, f'control {name}: the same path accepts the unmodified input', c)
    if sdk == 'rust':
        w = (neg or {}).get('wrongNetwork', {}).get('openWithOtherNetwork', {})
        add(w.get('refused') is True and w.get('error') == 'PinMismatch', 'negative wrongNetwork (rust): a session opened for another network id than its pin is refused (PinMismatch)', w)
    return out
