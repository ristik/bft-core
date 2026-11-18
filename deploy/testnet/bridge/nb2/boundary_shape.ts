/**
 * The boundary stage's counterfactuals (driver.ts shapeOf, boundary_search.ts shapeHolds): the token with one more transfer of its own shape
 * and the token with one fewer, as tokens the plug-in's gas bound (MeasuredGasModel, estimate-nb2-1179) prices like any other. One more repeats
 * the part's last transfer pair to a fresh key from a fresh state (the same UC and path, so no new claim); one fewer drops it. The
 * bound counts what the verifier counts (proofs, bytes, items, siblings, distinct claims, keys, memory), so each step is the model's own
 * answer on that token, not an average (bft-core#1179 replaced the per-hop arithmetic of the measured-nb2-05 schedule).
 *
 * These are diagnostics, not valid transitions: the repeated pair is not signed or certified for its new state, and nothing here stands in
 * for the preflight on an actual token or for a worst-case table occupancy. They are recorded beside each probe and never gate.
 *
 * Pure: only the plug-in's token type, so the unit tests run without a chain (boundary_shape.test.ts).
 */
import type { Token } from '../../../packages/native-bridge-plugin/src/nb2/token.js';

/** BYTES with its last two bytes xored with the counter N: a distinct digest or key of the same size (the bound hashes it, never verifies it). */
export function varied(bytes: Uint8Array, n: number): Uint8Array {
  const b = Uint8Array.from(bytes);
  b[b.length - 1] ^= n & 0xff;
  b[b.length - 2] ^= (n >> 8) & 0xff;
  return b;
}

/**
 * PART with one more transfer of its own shape: its last pair repeated, from its last owner to a fresh key and with a fresh source state,
 * so the bound replays a new state ID and a key decompression as a real next transfer has them (the same UC: no new claim). Null when it
 * has no transfer of its own.
 */
export function withOneMore(part: Token): Token | null {
  const n = part.transfers.length;
  if (n === 0) return null;
  const tx = part.transfers[n - 1];
  const pr = part.proofs[n - 1];
  const next = { ...tx, recipient: { ...tx.recipient, params: varied(tx.recipient.params, n + 1) } };
  const proof = { ...pr, cd: { ...pr.cd, source: tx.recipient, sourceHash: varied(pr.cd.sourceHash, n + 1) } };
  return { ...part, transfers: [...part.transfers, next], proofs: [...part.proofs, proof], transfersRaw: [...part.transfersRaw, part.transfersRaw[n - 1]] };
}

/** PART without its last transfer pair; null when it has no transfer of its own to remove. */
export function withOneFewer(part: Token): Token | null {
  const n = part.transfers.length;
  if (n === 0) return null;
  return { ...part, transfers: part.transfers.slice(0, -1), proofs: part.proofs.slice(0, -1), transfersRaw: part.transfersRaw.slice(0, -1) };
}

/**
 * up: G(one more) - G(token); down: G(token) - G(one fewer); null where the counterfactual does not exist or the bound is null. G is the
 * caller's bound of a part (the preflight's, its pending burn and reserve included).
 */
export function marginals(part: Token, G: (t: Token) => bigint | null): { up: bigint | null; down: bigint | null } {
  const g = G(part);
  if (g === null) return { up: null, down: null };
  const more = withOneMore(part);
  const fewer = withOneFewer(part);
  const gm = more === null ? null : G(more);
  const gf = fewer === null ? null : G(fewer);
  return { up: gm === null ? null : gm - g, down: gf === null ? null : g - gf };
}
