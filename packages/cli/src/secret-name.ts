/**
 * Shared name validation for secrets and signing keys.
 *
 * @internal
 */

/**
 * Allowed characters for a `--name`: letters, digits, `.`, `_`, `-`, and `/`
 * (for path-like names such as `env/prod/db-password`). A colon is deliberately
 * excluded so a caller-supplied name can never collide with the internal
 * `signing-key:<name>` namespace. The `+` quantifier rejects the empty string.
 */
export const SECRET_NAME_PATTERN = /^[A-Za-z0-9._/-]+$/

/** Human-readable description of {@link SECRET_NAME_PATTERN} for help/errors. */
export const SECRET_NAME_RULE = 'must be non-empty and contain only letters, digits, and . _ - /'
