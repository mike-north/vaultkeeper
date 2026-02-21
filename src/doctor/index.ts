/**
 * Doctor/preflight system barrel export.
 *
 * @packageDocumentation
 */

export { runDoctor } from './runner.js'
export type { RunDoctorOptions } from './runner.js'
export type { DoctorCheckFn } from './types.js'
export type { PreflightCheckStatus, PreflightCheck, PreflightResult } from './types.js'
export {
  checkOpenssl,
  checkBash,
  checkPowershell,
  checkSecurity,
  checkSecretTool,
  checkOp,
  checkYkman,
} from './checks.js'
