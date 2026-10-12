import { describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/core/engine.js';
import { builtinRules } from '../src/rules/index.js';
import { renderSarif } from '../src/reporters/sarif.js';
import { VERSION } from '../src/core/version.js';

const PKG = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
) as { version: string };

const HERE = path.dirname(fileURLToPath(import.meta.url));

async function scanFiles(files: Record<string, Buffer>): Promise<Awaited<ReturnType<typeof scan>>> {
  const dir = await mkdtemp(path.join(tmpdir(), 'antirea-r2-'));
  try {
    for (const [name, data] of Object.entries(files)) {
      await writeFile(path.join(dir, name), data);
    }
    return await scan(dir, builtinRules);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/** ELF64-LE with given section names, optionally containing Go buildinf magic. */
function fakeElf64(sectionNames: string[], goMagic: boolean): Buffer {
  const strtab = Buffer.from('\0' + sectionNames.map((n) => n + '\0').join(''), 'latin1');
  const strtabOff = 0x100;
  const shnum = sectionNames.length + 2;
  const shstrndx = shnum - 1;
  const shentsize = 64;
  const shoff = strtabOff + ((strtab.length + 7) & ~7);

  const buf = Buffer.alloc(shoff + shnum * shentsize + 64);
  buf.writeUInt32BE(0x7f454c46, 0);
  buf[4] = 2;
  buf[5] = 1;
  buf.writeBigUInt64LE(BigInt(shoff), 0x28);
  buf.writeUInt16LE(shentsize, 0x3a);
  buf.writeUInt16LE(shnum, 0x3c);
  buf.writeUInt16LE(shstrndx, 0x3e);
  const nameOffsets: number[] = [];
  let cursor = 1;
  for (const n of sectionNames) {
    nameOffsets.push(cursor);
    cursor += n.length + 1;
  }
  sectionNames.forEach((_, i) => buf.writeUInt32LE(nameOffsets[i], shoff + (i + 1) * shentsize));
  buf.writeUInt32LE(1, shoff + shstrndx * shentsize);
  buf.writeBigUInt64LE(BigInt(strtabOff), shoff + shstrndx * shentsize + 0x18);
  strtab.copy(buf, strtabOff);
  if (goMagic) Buffer.from('\xff Go buildinf:', 'latin1').copy(buf, buf.length - 32);
  return buf;
}

function fakeElectronBinary(wire: string): Buffer {
  const sentinel = Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX', 'latin1');
  return Buffer.concat([
    Buffer.from('MZ'),
    Buffer.alloc(62, 0),
    sentinel,
    Buffer.from([1, wire.length]),
    Buffer.from(wire, 'latin1'),
    Buffer.alloc(16, 0),
  ]);
}

describe('version single source (review #1)', () => {
  it('VERSION matches package.json', () => {
    expect(VERSION).toBe(PKG.version);
  });
});

describe('sarif fingerprints (review #2)', () => {
  it('emits stable partialFingerprints across runs', async () => {
    const fixtures = path.join(HERE, 'fixtures', 'web');
    const sarif1 = JSON.parse(renderSarif(await scan(fixtures, builtinRules)));
    const sarif2 = JSON.parse(renderSarif(await scan(fixtures, builtinRules)));
    const fp = sarif1.runs[0].results[0].partialFingerprints;
    expect(fp).toBeDefined();
    expect(fp['antirea/v1']).toMatch(/^[0-9a-f]{16}$/);
    expect(JSON.stringify(sarif1.runs[0].results.map((r: any) => r.partialFingerprints))).toBe(
      JSON.stringify(sarif2.runs[0].results.map((r: any) => r.partialFingerprints)),
    );
    expect(sarif1.runs[0].tool.driver.version).toBe(PKG.version);
  });
});

describe('go binaries also get symbol checks (review #3)', () => {
  it('go-binary with .symtab hits both go and symbols rules', async () => {
    const result = await scanFiles({ 'app': fakeElf64(['.text', '.symtab'], true) });
    const ruleIds = result.findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('go/buildinfo-leak');
    expect(ruleIds).toContain('bin/unstripped-symbols');
  });

  it('stripped go-binary only hits the buildinfo rule', async () => {
    const result = await scanFiles({ 'app': fakeElf64(['.text', '.rodata'], true) });
    expect(result.findings.map((f) => f.ruleId)).toEqual(['go/buildinfo-leak']);
  });
});

describe('fuse RunAsNode check (review #4)', () => {
  it('RunAsNode=1 produces a warn finding', async () => {
    // hardened integrity (011) but RunAsNode on
    const result = await scanFiles({ 'myapp.exe': fakeElectronBinary('111100') });
    const hits = result.findings.filter((f) => f.ruleId === 'electron/fuse-integrity');
    expect(hits).toHaveLength(1);
    expect(hits[0].severity).toBe('warn');
    expect(hits[0].message).toContain('RunAsNode');
  });

  it('fully hardened wire produces no findings', async () => {
    const result = await scanFiles({ 'myapp.exe': fakeElectronBinary('011100') });
    expect(result.findings.filter((f) => f.ruleId === 'electron/fuse-integrity')).toEqual([]);
  });
});
