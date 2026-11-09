// The public JS SDK's trust-base acceptance client (bft-core #430 row 2): the SDK's own TrustBaseSession + FileTrustBaseStore against a live aggregator.
// It verifies the trust-base entries the SDK supports; it is NOT a bridge verifier. One JSON object on stdout.
//   node client.mjs --agg-url URL --network-id N --genesis-pin HEX --genesis FILE --store DIR --mode cold|warm|restart [--negatives DIR]
//   node client.mjs --negatives DIR   (the offline negatives alone)
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const SDK = process.env.SDK_DIR ?? '/sdk';
const SDK_COMMIT = process.env.SDK_COMMIT ?? 'unknown';
const load = (p) => import(pathToFileURL(join(SDK, 'lib', p)).href);
const { TrustBaseSession } = await load('api/bft/trustbase/TrustBaseSession.js');
const { MemoryTrustBaseStore } = await load('api/bft/trustbase/TrustBaseStore.js');
const { FileTrustBaseStore } = await load('api/bft/trustbase/node/FileTrustBaseStore.js');
const { TrustBaseBundle } = await load('api/bft/trustbase/TrustBaseBundle.js');
const { TrustBaseHistory } = await load('api/bft/trustbase/TrustBaseHistory.js');
const { RootTrustBaseV2 } = await load('api/bft/trustbase/RootTrustBaseV2.js');
const E = await load('api/bft/trustbase/TrustBaseError.js');
const { AggregatorClient } = await load('api/AggregatorClient.js');
const { HexConverter } = await load('util/HexConverter.js');
const LIMITS = { maxBytes: 16 * 1024 * 1024, maxEntries: 4096 };

function args() {
  const a = {};
  for (let i = 2; i < process.argv.length; i += 2) a[process.argv[i].replace(/^--/, '')] = process.argv[i + 1];
  return a;
}
const hex = (b) => HexConverter.encode(b);
const idsOf = async (history) => Object.fromEntries(await Promise.all(history.entries.map(async (e) => [String(e.epoch), hex(await e.entryId())])));
const readBytes = (p) => new Uint8Array(readFileSync(p));

async function live(a, out) {
  const genesisBundle = readBytes(a.genesis);
  const store = new FileTrustBaseStore(a.store);
  if (a.mode === 'cold' && existsSync(a.store) && readdirSync(a.store).length) throw new Error('cold needs an empty store');
  if (a.mode === 'warm') {
    // seed the store through the SDK's own store API with the epoch-1 entry alone (the shipped genesis bundle); the session reopened below must load it
    const probe = await TrustBaseSession.openLocal(genesisBundle, store);
    const seeded = await store.compareAndSwap(probe.session.key, null, genesisBundle);
    if (seeded !== 'written') throw new Error(`the warm seed was not written: ${seeded}`);
  }
  const { session, diagnostics } = await TrustBaseSession.openLocal(genesisBundle, store);
  const genesis = session.history.entries[0];
  out.genesisEpoch = Number(genesis.epoch);
  if (session.networkId.id !== Number(a['network-id'])) throw new Error(`the genesis is of network ${session.networkId.id}, not ${a['network-id']}`);
  if (hex(await genesis.entryId()) !== a['genesis-pin'].toLowerCase().replace(/^0x/, '')) throw new Error('the shipped genesis is not the pinned EntryID');
  out.heldAtOpen = session.history.entries.length;
  out.diagnostics = diagnostics.map((d) => d.code + (d.reason ? `:${d.reason}` : ''));
  const { appended, flush } = await session.refresh([new AggregatorClient(a['agg-url'])]);
  out.fetched = appended;
  out.flush = flush.status === 'saved' ? { status: 'saved', wrote: flush.wrote } : { status: 'pending', error: String(flush.error) };
  out.tipEpoch = Number(session.tip.epoch);
  out.entryIds = await idsOf(session.history);
  // what the store holds now, re-verified strictly from the pin by the SDK's own decoder
  const stored = await store.read(session.key, LIMITS.maxBytes);
  const reloaded = await TrustBaseHistory.fromBundle(await TrustBaseBundle.decode(stored.bytes, LIMITS), await genesis.entryId());
  out.persisted = reloaded.entries.length === session.history.entries.length && hex(await reloaded.tip.entryId()) === hex(await session.tip.entryId());
}

async function negatives(dir) {
  const f = (n) => readBytes(join(dir, n));
  const entry = (n) => RootTrustBaseV2.decode(f(n));
  const open = async (bundle) => (await TrustBaseSession.openLocal(bundle, new MemoryTrustBaseStore())).session;
  const name = (e) => e?.constructor?.name ?? String(e);
  const tried = async (fn, expected) => {
    try {
      await fn();
      return { refused: false };
    } catch (e) {
      return { refused: true, error: name(e), errorClass: e?.errorClass ?? null, typed: expected.some((c) => e instanceof c), message: String(e?.message).slice(0, 160) };
    }
  };
  const control = async (fn) => {
    try {
      return { accepted: true, outcome: await fn() };
    } catch (e) {
      return { accepted: false, error: name(e), message: String(e?.message).slice(0, 160) };
    }
  };
  const res = {};
  // 1. missing middle, nothing fetched: the session holds the genesis only and is offered the epoch-3 entry
  let s = await open(f('genesis.bundle.cbor'));
  res.missingMiddle = { ...(await tried(() => s.append(entry('entry-3.cbor')), [E.TrustBaseGapError])), tipAfter: Number(s.tip.epoch) };
  s = await open(f('genesis.bundle.cbor'));
  res.missingMiddle.control = await control(async () => [await s.append(entry('entry-2.cbor')), await s.append(entry('entry-3.cbor')), Number(s.tip.epoch)]);
  // 2. entry 2 with its signatures reduced below the predecessor's quorum
  s = await open(f('genesis.bundle.cbor'));
  res.belowQuorum = { ...(await tried(() => s.append(entry('entry-2.weak.cbor')), [E.TrustBaseSignatureError])), tipAfter: Number(s.tip.epoch) };
  s = await open(f('genesis.bundle.cbor'));
  res.belowQuorum.control = await control(async () => [await s.append(entry('entry-2.cbor')), Number(s.tip.epoch)]);
  // 3. a session of another network than the entries' (its genesis is the real genesis with another network id)
  s = await open(f('genesis.othernet.bundle.cbor'));
  res.wrongNetwork = { ...(await tried(() => s.append(entry('entry-2.cbor')), [E.TrustBaseNetworkError])), tipAfter: Number(s.tip.epoch) };
  s = await open(f('genesis.bundle.cbor'));
  res.wrongNetwork.control = await control(async () => [await s.append(entry('entry-2.cbor')), Number(s.tip.epoch)]);
  return res;
}

const a = args();
const out = { sdk: 'js', commit: SDK_COMMIT, mode: a.mode ?? null };
try {
  if (a.mode) await live(a, out);
  if (a.negatives) out.negatives = await negatives(a.negatives);
  console.log(JSON.stringify(out));
} catch (e) {
  console.log(JSON.stringify({ sdk: 'js', commit: SDK_COMMIT, mode: a.mode ?? null, error: e?.constructor?.name ?? 'Error', message: String(e?.message ?? e) }));
  process.exit(1);
}
