/**
 * Re-exported types for the access patterns module.
 */

export type {
  FetchRequest,
  ExecRequest,
  ExecResult,
  SecretAccessor,
} from '../types.js'

/**
 * Result from a delegated fetch call.
 * @internal
 */
export interface DelegatedFetchResult {
  response: Response
}

/**
 * Result from a delegated exec call (alias for ExecResult).
 * @internal
 */
export type { ExecResult as DelegatedExecResult } from '../types.js'
