import { readFileSync } from 'node:fs';

/**
 * Single source of truth for the package version. Reads package.json at
 * runtime: dist/core/version.js → ../../package.json resolves correctly both
 * in the repo and in the published npm package (package.json is always packed).
 */
export const VERSION: string = (
  JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')) as { version: string }
).version;
