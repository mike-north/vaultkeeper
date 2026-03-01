/**
 * Types for the backend setup protocol.
 *
 * @packageDocumentation
 */

/**
 * A question yielded by a backend setup generator.
 * @public
 */
export interface SetupQuestion {
  /** Machine key for BackendConfig.options */
  readonly key: string
  /** Human-readable prompt */
  readonly prompt: string
  /** Present for selection questions; when absent, the answer is a free-form string. */
  readonly choices?: readonly SetupChoice[]
}

/**
 * A choice within a setup question.
 * @public
 */
export interface SetupChoice {
  /** Persisted value */
  readonly value: string
  /** Display label */
  readonly label: string
}

/**
 * Result returned when a backend setup generator completes.
 * @public
 */
export interface SetupResult {
  /** Merge into BackendConfig.options */
  readonly options: Record<string, string>
}

/**
 * Factory that creates a backend setup generator.
 * @public
 */
export type BackendSetupFactory = () => AsyncGenerator<SetupQuestion, SetupResult, string>
