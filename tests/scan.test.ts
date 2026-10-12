import { describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { scan } from '../src/core/engine.js';
import { builtinRules } from '../src/rules/index.js';

const WEB_FIXTURES = path.join(__dirname, 'fixtures', 'web');

/** Build a synthetic Go binary: ELF magic + buildinf magic + modinfo text. */
function fakeGoBinary(modinfo: string): Buffer {
  const header = Buffer.concat([
    Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]), // ELF 64-bit
    Buffer.alloc(56, 0),
    Buffer.from('\xff Go buildinf:', 'latin1'),
    Buffer.from([8, 0]), // ptrSize, endianness
    Buffer.alloc(32, 0),
    Buffer.from('go1.22.5\0', 'latin1'),
  ]);
  return Buffer.concat([header, Buffer.from(modinfo, 'latin1'), Buffer.alloc(64, 0)]);
}

describe('web rules', () => {
  it('flags a shipped .map file with sourcesContent', async () => {
    const result = await scan(WEB_FIXTURES, builtinRules);
    const hit = result.findings.find((f) => f.ruleId === 'web/sourcemap-file' && f.path === 'app.js.map');
    expect(hit).toBeDefined();
    expect(hit!.severity).toBe('high');
    expect(hit!.evidence).toContain('sourcesContent');
  });

  it('flags sourceMappingURL in a bundle, but not in a clean bundle', async () => {
    const result = await scan(WEB_FIXTURES, builtinRules);
    const urls = result.findings.filter((f) => f.ruleId === 'web/sourcemap-url');
    expect(urls.map((f) => f.path)).toEqual(['app.js']);
    expect(urls[0].evidence).toContain('app.js.map');
    expect(result.findings.some((f) => f.path === 'clean.js')).toBe(false);
  });
});

describe('go/buildinfo-leak', () => {
  it('extracts module path, version and VCS settings from a Go binary', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'shiplint-'));
    try {
      const modinfo =
        'path\tcorp.example/internal/billing\n' +
        'mod\tcorp.example/internal/billing\tv0.3.1\th1:abc=\n' +
        'build\t-buildmode=exe\nbuild\tGOARCH=amd64\n' +
        'build\tvcs=git\nbuild\tvcs.revision=deadbeef\n';
      await writeFile(path.join(dir, 'billing'), fakeGoBinary(modinfo));

      const result = await scan(dir, builtinRules);
      const hit = result.findings.find((f) => f.ruleId === 'go/buildinfo-leak');
      expect(hit).toBeDefined();
      expect(hit!.severity).toBe('high'); // upgraded: VCS info present
      expect(hit!.evidence).toContain('go1.22.5');
      expect(hit!.evidence).toContain('corp.example/internal/billing');
      expect(hit!.evidence).toContain('vcs.revision=deadbeef');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('reports base severity when no VCS info is embedded', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'shiplint-'));
    try {
      await writeFile(path.join(dir, 'app'), fakeGoBinary('path\texample.com/app\nmod\texample.com/app\tv1.0.0\n'));
      const result = await scan(dir, builtinRules);
      const hit = result.findings.find((f) => f.ruleId === 'go/buildinfo-leak');
      expect(hit).toBeDefined();
      expect(hit!.severity).toBe('warn');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('ignores non-Go files', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'shiplint-'));
    try {
      await writeFile(path.join(dir, 'notes.txt'), 'just some text\n');
      const result = await scan(dir, builtinRules);
      expect(result.findings).toEqual([]);
      expect(result.summary.filesScanned).toBe(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
