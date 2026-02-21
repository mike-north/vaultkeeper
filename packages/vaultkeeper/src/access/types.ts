/**
 * Re-exported types for the access patterns module.
 */

export type {
  FetchRequest,
  ExecRequest,
  ExecResult,
  SecretAccessor,
} from '../types.js'

/** Result from a delegated fetch call. */
export interface DelegatedFetchResult {
  response: Response
}

/** Result from a delegated exec call (alias for ExecResult). */
export type { ExecResult as DelegatedExecResult } from '../types.js'
