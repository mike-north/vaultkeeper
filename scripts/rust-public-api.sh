#!/usr/bin/env bash
# Regenerates or checks the committed vaultkeeper-core public-API listing
# (docs/specs/001 §3.1). Wired as `pnpm check:rust-api` / `pnpm
# generate:rust-api` (see root package.json) — the same regeneration-diff
# pattern as `check:api-report`/`generate:api-report` for the TS packages.
#
# Usage: scripts/rust-public-api.sh <check|generate>
#
# Requires the pinned nightly toolchain and `cargo-public-api` version from
# crates/vaultkeeper-core/rust-api-toolchain.env to be installed:
#   rustup toolchain install <RUST_API_NIGHTLY_TOOLCHAIN>
#   cargo install cargo-public-api --version <CARGO_PUBLIC_API_VERSION> --locked
set -euo pipefail

mode="${1:-}"
if [[ "${mode}" != "check" && "${mode}" != "generate" ]]; then
  echo "Usage: scripts/rust-public-api.sh <check|generate>" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
toolchain_env="${repo_root}/crates/vaultkeeper-core/rust-api-toolchain.env"
committed_file="${repo_root}/crates/vaultkeeper-core/public-api.txt"

# shellcheck disable=SC1090
source <(grep -v '^[[:space:]]*#' "${toolchain_env}" | grep -v '^[[:space:]]*$')

if ! command -v cargo >/dev/null 2>&1; then
  echo "::error::cargo not found on PATH" >&2
  exit 1
fi

if ! cargo "+${RUST_API_NIGHTLY_TOOLCHAIN}" --version >/dev/null 2>&1; then
  echo "::error::Pinned toolchain '${RUST_API_NIGHTLY_TOOLCHAIN}' is not installed. Run: rustup toolchain install ${RUST_API_NIGHTLY_TOOLCHAIN}" >&2
  exit 1
fi

if ! command -v cargo-public-api >/dev/null 2>&1; then
  echo "::error::cargo-public-api not found on PATH. Run: cargo install cargo-public-api --version ${CARGO_PUBLIC_API_VERSION} --locked" >&2
  exit 1
fi

installed_version="$(cargo public-api --version | awk '{print $2}')"
if [[ "${installed_version}" != "${CARGO_PUBLIC_API_VERSION}" ]]; then
  echo "::error::Installed cargo-public-api version (${installed_version}) does not match the pinned version (${CARGO_PUBLIC_API_VERSION}) in crates/vaultkeeper-core/rust-api-toolchain.env. Run: cargo install cargo-public-api --version ${CARGO_PUBLIC_API_VERSION} --locked --force" >&2
  exit 1
fi

fresh_file="$(mktemp)"
stderr_file="$(mktemp)"
trap 'rm -f "${fresh_file}" "${stderr_file}"' EXIT

# -sss omits blanket impls, auto trait impls (Send/Sync/Unpin/...), and
# auto-derived impls — noise that changes with the compiler/dependency
# versions without being a real surface change, while still catching every
# real addition/removal/rename of a public item or trait impl.
#
# stderr is captured (not discarded) so that a failure still surfaces its
# diagnostic output below; on success it's suppressed to keep the normal
# rustdoc-build chatter out of `check`/`generate` output.
if ! cargo "+${RUST_API_NIGHTLY_TOOLCHAIN}" public-api \
  --manifest-path "${repo_root}/crates/vaultkeeper-core/Cargo.toml" \
  -p vaultkeeper-core \
  -sss \
  > "${fresh_file}" 2>"${stderr_file}"; then
  echo "::error::cargo public-api failed:" >&2
  cat "${stderr_file}" >&2
  exit 1
fi

if [[ "${mode}" == "generate" ]]; then
  cp "${fresh_file}" "${committed_file}"
  echo "Wrote ${committed_file}"
  exit 0
fi

if ! diff -u "${committed_file}" "${fresh_file}"; then
  echo "::error::crates/vaultkeeper-core/public-api.txt is stale — the crate's public API has changed. Regenerate it: pnpm generate:rust-api, then commit the result. Per docs/specs/001 §3.5, a diff touching this listing is a surface change and requires a spec update in the same PR." >&2
  exit 1
fi

echo "crates/vaultkeeper-core/public-api.txt is up to date."
