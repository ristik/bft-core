/**
 * The boundary stage's counterfactuals (driver.ts marginalOf, boundary_search.ts shapeHolds): the gas of a token with one more and with one
 * fewer transfer of its own average shape, by the terms of the plug-in's MeasuredGasModel (measured-nb2-05): a hop, the evidence bytes beyond
 * the measured shape (clipped at zero), the seal signatures beyond the measured 3. The two steps differ where the clip binds: a token at or
 * under its measured bytes pays nothing for its excess, so one more pair of more than the measured bytes costs its excess, while removing
 * one saves only the hop (sol's review r8 of #1126: 1,100-byte pairs at zero excess, +200,064 forward, -190,000 back).
 *
 * Pure, with the model's constants passed in (MEASURED_VERIFIER), so the arithmetic is tested against the model itself
 * (boundary_shape.test.ts).
 */

/** The terms of MEASURED_VERIFIER the counterfactuals use. */
export interface ShapeModel {
  perTransfer: bigint;
  perExcessByte: bigint;
  perExtraSignature: bigint;
  baseBytes: number;
  bytesPerTransfer: number;
  bytesPerSplitLevel: number;
}

/** A token as the model sees it: the evidence length the preflight charges, its hops and split levels, and its transfers' average shape. */
export interface TokenShape {
  evidenceBytes: number;
  hops: number;
  levels: number;
  pairBytes: number; // a transfer's pair (transaction and inclusion proof), averaged over the token, rounded down
  extraSignatures: number; // a transfer certificate's seal signatures beyond the measured, averaged likewise, rounded down
}

/**
 * up: G(one more transfer) - G(token); down: G(token) - G(one fewer transfer); null when there is no transfer to remove. Both are rounded
 * down (the averages are), which makes each side of shapeHolds stricter: a smaller up keeps a pass's counterfactual within the limit, a
 * smaller down keeps a refusal's over it.
 */
export function marginals(s: TokenShape, m: ShapeModel): { up: bigint; down: bigint | null } {
  const shaped = (hops: number): number => m.baseBytes + m.bytesPerTransfer * hops + m.bytesPerSplitLevel * s.levels;
  const excess = (bytes: number, hops: number): number => Math.max(0, bytes - shaped(hops));
  const now = excess(s.evidenceBytes, s.hops);
  const sig = m.perExtraSignature * BigInt(s.extraSignatures);
  const up = m.perTransfer + m.perExcessByte * BigInt(excess(s.evidenceBytes + s.pairBytes, s.hops + 1) - now) + sig;
  const down = s.hops < 1 ? null : m.perTransfer + m.perExcessByte * BigInt(now - excess(s.evidenceBytes - s.pairBytes, s.hops - 1)) + sig;
  return { up, down };
}
