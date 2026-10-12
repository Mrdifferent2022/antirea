import { describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { scan } from '../src/core/engine.js';
import { builtinRules } from '../src/rules/index.js';

async function scanFiles(
  files: Record<string, string | Buffer>,
  options: Parameters<typeof scan>[2] = {},
): Promise<Awaited<ReturnType<typeof scan>>> {
  const dir = await mkdtemp(path.join(tmpdir(), 'antirea-r-'));
  try {
    for (const [name, data] of Object.entries(files)) {
      await writeFile(path.join(dir, name), data);
    }
    return await scan(dir, builtinRules, options);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

function inlineMapUrl(map: object): string {
  return `data:application/json;base64,${Buffer.from(JSON.stringify(map)).toString('base64')}`;
}

const MAP_WITH_SOURCES = {
  version: 3,
  sources: ['../src/secret-logic.ts'],
  sourcesContent: ['// ACME proprietary\nexport const secret = 42;\n'],
  mappings: 'AAAA',
};

const MAP_WITHOUT_SOURCES = { version: 3, sources: ['../src/a.ts', '../src/b.ts'], mappings: 'AAAA' };

describe('inline sourcemap severity (review #1)', () => {
  it('inline data URL with sourcesContent is critical', async () => {
    const result = await scanFiles({ 'bundle.js': `!function(){}();\n//# sourceMappingURL=${inlineMapUrl(MAP_WITH_SOURCES)}\n` });
    const hit = result.findings.find((f) => f.ruleId === 'web/sourcemap-url');
    expect(hit).toBeDefined();
    expect(hit!.severity).toBe('critical');
    expect(hit!.evidence).toContain('secret-logic.ts');
  });

  it('inline data URL without sourcesContent is high', async () => {
    const result = await scanFiles({ 'bundle.js': `!function(){}();\n//# sourceMappingURL=${inlineMapUrl(MAP_WITHOUT_SOURCES)}\n` });
    const hit = result.findings.find((f) => f.ruleId === 'web/sourcemap-url');
    expect(hit!.severity).toBe('high');
  });

  it('relative reference stays warn', async () => {
    const result = await scanFiles({ 'bundle.js': '!function(){}();\n//# sourceMappingURL=bundle.js.map\n' });
    const hit = result.findings.find((f) => f.ruleId === 'web/sourcemap-url');
    expect(hit!.severity).toBe('warn');
  });
});

describe('.map without sourcesContent (review #3)', () => {
  it('is warn, not high', async () => {
    const result = await scanFiles({ 'app.js.map': JSON.stringify(MAP_WITHOUT_SOURCES) });
    const hit = result.findings.find((f) => f.ruleId === 'web/sourcemap-file');
    expect(hit!.severity).toBe('warn');
    expect(hit!.message).toContain('paths and structure');
  });
});

describe('ignore wiring (review #4)', () => {
  const files = {
    'app.js.map': JSON.stringify(MAP_WITH_SOURCES),
    'app.js': '!function(){}();\n//# sourceMappingURL=app.js.map\n',
  };

  it('--ignore option suppresses exact names and globs', async () => {
    const byName = await scanFiles(files, { ignore: ['app.js.map'] });
    expect(byName.findings.filter((f) => f.ruleId === 'web/sourcemap-file')).toEqual([]);

    const byGlob = await scanFiles(files, { ignore: ['*.map'] });
    expect(byGlob.findings.filter((f) => f.ruleId === 'web/sourcemap-file')).toEqual([]);
    expect(byGlob.findings.some((f) => f.ruleId === 'web/sourcemap-url')).toBe(true); // app.js still scanned
  });

  it('.antireaignore in the scan root applies', async () => {
    const result = await scanFiles({ ...files, '.antireaignore': '# known accepted\napp.js.map\n' });
    expect(result.findings.filter((f) => f.ruleId === 'web/sourcemap-file')).toEqual([]);
    expect(result.summary.filesScanned).toBe(1); // ignore file itself is not scanned
  });
});

describe('go buildinfo anchored parsing (review #2)', () => {
  it('does not harvest unrelated build\\t text without a modinfo block', async () => {
    const fake = Buffer.concat([
      Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]),
      Buffer.alloc(56, 0),
      Buffer.from('\xff Go buildinf:', 'latin1'),
      Buffer.alloc(32, 0),
      // Looks like a build setting but there is no "\nmod\t" anchor nearby.
      Buffer.from('\nbuild\tGOARCH=amd64\nbuild\tvcs.revision=deadbeef\n', 'latin1'),
      Buffer.alloc(64, 0),
    ]);
    const result = await scanFiles({ 'app': fake });
    const hit = result.findings.find((f) => f.ruleId === 'go/buildinfo-leak');
    expect(hit).toBeDefined(); // magic alone still reports at base severity
    expect(hit!.severity).toBe('warn');
    expect(hit!.evidence).not.toContain('vcs');
    expect(hit!.evidence).toContain('no parseable modinfo');
  });
});
