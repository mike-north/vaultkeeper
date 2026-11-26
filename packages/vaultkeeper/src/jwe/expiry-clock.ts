/** The latest epoch second observed by this module's token enforcement. */
let latestSecond = Number.NEGATIVE_INFINITY

/**
 * Read the authorization clock in epoch seconds. Once observed, an instant
 * remains past even if the system clock is corrected backwards. Discarding
 * state at this instant therefore cannot make an expired token usable again.
 */
export function tokenExpiryTime(): number {
  latestSecond = Math.max(latestSecond, Math.floor(Date.now() / 1000))
  return latestSecond
}

/** Reset the clock between tests after discarding their enforcement state. @internal */
export function resetTokenExpiryClockForTests(): void {
  latestSecond = Number.NEGATIVE_INFINITY
}
