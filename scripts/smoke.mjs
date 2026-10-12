#!/usr/bin/env node
/**
 * Smoke test: the scanner MUST flag the planted leaks in tests/fixtures/web.
 * A dogfood step that can never fail is worse than none — assert exact hits.
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan, builtinRules } from '../dist/index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.join(HERE, '..', 'tests', 'fixtures', 'web');

const result = await scan(fixtures, builtinRules);

const expectations = [
  { ruleId: 'web/sourcemap-file', path: 'app.js.map', severity: 'high' },
  { ruleId: 'web/sourcemap-url', path: 'app.js', severity: 'warn' },
];

let failed = false;
for (const exp of expectations) {
  const hit = result.findings.find((f) => f.ruleId === exp.ruleId && f.path === exp.path);
  if (!hit) {
    console.error(`SMOKE FAIL: expected ${exp.ruleId} on ${exp.path}, not found`);
    failed = true;
  } else if (hit.severity !== exp.severity) {
    console.error(`SMOKE FAIL: ${exp.ruleId} on ${exp.path} severity ${hit.severity}, expected ${exp.severity}`);
    failed = true;
  }
}
const cleanHits = result.findings.filter((f) => f.path === 'clean.js');
if (cleanHits.length > 0) {
  console.error(`SMOKE FAIL: clean.js should have no findings, got ${cleanHits.map((f) => f.ruleId).join(', ')}`);
  failed = true;
}

if (failed) process.exit(1);
console.log(`smoke ok: ${expectations.length} expected findings hit, clean.js clean`);
