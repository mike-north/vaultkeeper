/**
 * Collects .api.json files from all packages into a single directory
 * for api-documenter to consume.
 */
import { cpSync, mkdirSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const outputDir = 'tmp/api-documenter';
const packages = ['packages/vaultkeeper', 'packages/test-helpers'];

mkdirSync(outputDir, { recursive: true });

for (const pkg of packages) {
  const apiExtractorDir = join(pkg, 'tmp', 'api-extractor');
  let files;
  try {
    files = readdirSync(apiExtractorDir);
  } catch {
    console.warn(`Skipping ${pkg}: no api-extractor output found`);
    continue;
  }
  for (const file of files) {
    if (file.endsWith('.api.json')) {
      cpSync(join(apiExtractorDir, file), join(outputDir, file));
      console.log(`Collected ${file} from ${pkg}`);
    }
  }
}
