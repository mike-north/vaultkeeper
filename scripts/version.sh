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

# 3. Guard: all packages must stay in the 0.x stream
#    0.x semver lets us cut breaking changes as minor bumps.
#    Reaching 1.0 is an intentional decision, not an accident.
ALL_VERSIONS=$(node -e "
  const fs = require('fs');
  const glob = require('fs').readdirSync('packages');
  glob.forEach(dir => {
    try {
      const pkg = JSON.parse(fs.readFileSync('packages/' + dir + '/package.json', 'utf8'));
      if (!pkg.private) console.log(pkg.name + '@' + pkg.version);
    } catch(e) {}
  });
" 2>/dev/null)

VIOLATIONS=""
while IFS= read -r line; do
  if [ -z "$line" ]; then continue; fi
  pkg_version="${line#*@}"
  major="${pkg_version%%.*}"
  if [ "$major" -ge 1 ] 2>/dev/null; then
    VIOLATIONS="${VIOLATIONS}  ${line}\n"
  fi
done <<< "$ALL_VERSIONS"

if [ -n "$VIOLATIONS" ]; then
  echo "Error: version guard failed — all packages must stay in 0.x"
  echo "The following packages have version >= 1.0.0:"
  printf "$VIOLATIONS"
  echo ""
  echo "If you intentionally want to release 1.0, remove the guard in scripts/version.sh"
  exit 1
fi

echo "Syncing Cargo workspace version to ${VERSION} (from @vaultkeeper/wasm)"

# 4. Update the workspace version in Cargo.toml
sed -i "s/^version = \".*\"/version = \"${VERSION}\"/" Cargo.toml

echo "Version sync complete: npm @vaultkeeper/wasm + Cargo.toml → ${VERSION}"
