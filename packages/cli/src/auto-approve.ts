/**
 * Determine whether an untrusted caller's approval prompt should be skipped
 * non-interactively for this invocation.
 *
 * Checks the `--yes` flag value and the `VAULTKEEPER_YES` env var. This is an
 * explicit, opt-in escape hatch for non-interactive/CI use — it is never the
 * default. It only applies to a caller that is not yet in the trust manifest;
 * a caller whose recorded hash changed (identity mismatch) is never
 * auto-approved and must be re-approved with `vaultkeeper approve`.
 *
 * @param flagValue - The parsed `--yes` flag value from parseArgs.
 * @returns `true` if the interactive approval should be skipped and the caller
 *   approved for this invocation.
 * @internal
 */
export function shouldAutoApprove(flagValue: boolean): boolean {
  return flagValue || process.env.VAULTKEEPER_YES === '1'
}
