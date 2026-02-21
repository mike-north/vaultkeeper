/**
 * Access patterns for secret consumption.
 */

export { delegatedFetch } from './delegated-fetch.js'
export { delegatedExec } from './delegated-exec.js'
export { createSecretAccessor } from './controlled-direct.js'
export type {
  FetchRequest,
  ExecRequest,
  ExecResult,
  SecretAccessor,
  DelegatedFetchResult,
  DelegatedExecResult,
} from './types.js'
