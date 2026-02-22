/**
 * Doctor/preflight system types.
 */

import type { PreflightCheck } from '../types.js'

export type { PreflightCheckStatus, PreflightCheck, PreflightResult } from '../types.js'

/**
 * A function that runs a named preflight check.
 * @internal
 */
export type DoctorCheckFn = (check: { name: string }) => Promise<PreflightCheck>
