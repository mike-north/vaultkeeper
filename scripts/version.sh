#!/usr/bin/env bash
# Changeset version script that also syncs Cargo.toml workspace version.
#
# Called by changesets/action as the "version" command. Runs changeset version
# to bump npm packages, then reads the new version from the main vaultkeeper
# package.json and updates the Cargo workspace version to match.

set -euo pipefail

# 1. Run changeset version (bumps npm package.json files)
pnpm exec changeset version

# 2. Read the new version from the main vaultkeeper package
if [ ! -f packages/vaultkeeper/package.json ]; then
  echo "Error: packages/vaultkeeper/package.json not found"
  exit 1
fi

VERSION=$(node -e "console.log(require('./packages/vaultkeeper/package.json').version)" 2>/dev/null) || {
  echo "Error: Could not read version from packages/vaultkeeper/package.json"
  exit 1
}

echo "Syncing Cargo workspace version to ${VERSION}"

# 3. Update the workspace version in Cargo.toml
sed -i "s/^version = \".*\"/version = \"${VERSION}\"/" Cargo.toml

echo "Version sync complete: npm + Cargo.toml → ${VERSION}"
