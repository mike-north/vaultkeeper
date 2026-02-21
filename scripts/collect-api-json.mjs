/**
 * Collects .api.json files from all packages into a single directory
 * for api-documenter to consume.
 */
import { cpSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';

const outputDir = 'tmp/api-documenter';
const packages = ['packages/vaultkeeper', 'packages/test-helpers'];

rmSync(outputDir, { recursive: true, force: true });
mkdirSync(outputDir, { recursive: true });

for (const pkg of packages) {
  const apiExtractorDir = join(pkg, 'tmp', 'api-extractor');
  let files;
  try {
    files = readdirSync(apiExtractorDir);
  } catch {
    throw new Error(
      `Missing api-extractor output for ${pkg}. Run "pnpm build && pnpm generate:api-report" first.`
    );
  }
  for (const file of files) {
    if (file.endsWith('.api.json')) {
      cpSync(join(apiExtractorDir, file), join(outputDir, file));
      console.log(`Collected ${file} from ${pkg}`);
    }
  }
}
