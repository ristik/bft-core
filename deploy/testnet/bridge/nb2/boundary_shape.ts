/**
 * The boundary stage's counterfactuals (driver.ts shapeOf, boundary_search.ts shapeHolds): the token with one more transfer of its own shape
 * and the token with one fewer, as tokens the plug-in's gas bound (MeasuredGasModel, bound-nb2-1179) prices like any other. One more repeats
 * the part's last transfer pair (its transaction and inclusion proof: the same UC, path and keys, so no new claim); one fewer drops it. The
 * bound counts what the verifier counts (proofs, bytes, items, siblings, distinct claims, keys, memory), so each step is the model's own
 * answer on that token, not an average (bft-core#1179 replaced the per-hop arithmetic of the measured-nb2-05 schedule).
 *
 * Pure: only the plug-in's token type, so the unit tests run without a chain (boundary_shape.test.ts).
 */
import type { Token } from '../../../packages/native-bridge-plugin/src/nb2/token.js';

/** PART with its last transfer pair repeated; null when it has no transfer of its own. */
export function withOneMore(part: Token): Token | null {
  const n = part.transfers.length;
  if (n === 0) return null;
  return {
    ...part,
    transfers: [...part.transfers, part.transfers[n - 1]],
    proofs: [...part.proofs, part.proofs[n - 1]],
    transfersRaw: [...part.transfersRaw, part.transfersRaw[n - 1]],
  };
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
