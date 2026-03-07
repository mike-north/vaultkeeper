#!/usr/bin/env bash
# Changeset version script that also syncs Cargo.toml workspace version.
#
# Called by changesets/action as the "version" command. Runs changeset version
# to bump npm packages, then reads the new version from the @vaultkeeper/wasm
# package.json and updates the Cargo workspace version to match.
#
# We sync with @vaultkeeper/wasm (not the main vaultkeeper TS library) because
# the WASM SDK directly wraps the Rust core — their versions should track
# together. The TS library has its own independent version history.

set -euo pipefail

# 1. Run changeset version (bumps npm package.json files)
pnpm exec changeset version

# 2. Read the new version from the WASM SDK package
WASM_PKG="packages/vaultkeeper-wasm/package.json"

if [ ! -f "$WASM_PKG" ]; then
  echo "Error: ${WASM_PKG} not found"
  exit 1
fi

VERSION=$(node -e "console.log(require('./${WASM_PKG}').version)" 2>/dev/null) || {
  echo "Error: Could not read version from ${WASM_PKG}"
  exit 1
}

echo "Syncing Cargo workspace version to ${VERSION} (from @vaultkeeper/wasm)"

# 3. Update the workspace version in Cargo.toml
sed -i "s/^version = \".*\"/version = \"${VERSION}\"/" Cargo.toml

echo "Version sync complete: npm @vaultkeeper/wasm + Cargo.toml → ${VERSION}"
