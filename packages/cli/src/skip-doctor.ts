/**
 * Determine whether doctor checks should be skipped.
 *
 * Checks the --skip-doctor flag value and the VAULTKEEPER_SKIP_DOCTOR env var.
 *
 * @param flagValue - The parsed --skip-doctor flag value from parseArgs
 * @returns true if doctor checks should be skipped
 * @internal
 */
export function shouldSkipDoctor(flagValue: boolean): boolean {
  return flagValue || process.env.VAULTKEEPER_SKIP_DOCTOR === '1'
}
