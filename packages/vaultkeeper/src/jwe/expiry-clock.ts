/** Wall time and the matching monotonic reading, both in milliseconds. */
let anchor: { wallMs: number; steadyMs: number } | undefined

/**
 * Read the shared JWE expiry clock in epoch seconds, including fractions.
 * Elapsed monotonic time carries the clock forward while wall time is behind.
 * Expired state can be reclaimed safely, and new tokens still age normally.
 */
export function tokenExpiryTime(): number {
  const wallMs = Date.now()
  const steadyMs = performance.now()
  const projectedMs =
    anchor === undefined ? wallMs : anchor.wallMs + Math.floor(steadyMs - anchor.steadyMs)
  if (wallMs >= projectedMs) {
    anchor = { wallMs, steadyMs }
  }
  return Math.max(wallMs, projectedMs) / 1000
}

/** Reset the clock between tests after discarding their enforcement state. @internal */
export function resetTokenExpiryClockForTests(): void {
  anchor = undefined
}
