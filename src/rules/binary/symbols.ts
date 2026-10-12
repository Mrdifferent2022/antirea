import type { Finding, Rule } from '../../core/types.js';

function isElf(data: Buffer): boolean {
  return data.length > 4 && data[0] === 0x7f && data[1] === 0x45 && data[2] === 0x4c && data[3] === 0x46;
}

function isPe(data: Buffer): boolean {
  return data.length > 2 && data[0] === 0x4d && data[1] === 0x5a;
}

/**
 * List ELF section names. Supports 32/64-bit little-endian (the common case).
 * Returns null when the layout can't be parsed.
 */
export function elfSectionNames(data: Buffer): string[] | null {
  if (!isElf(data) || data.length < 64) return null;
  const is64 = data[4] === 2;
  if (data[5] !== 1) return null; // little-endian only

  const shoff = is64 ? Number(data.readBigUInt64LE(0x28)) : data.readUInt32LE(0x20);
  const shentsize = data.readUInt16LE(is64 ? 0x3a : 0x2e);
  const shnum = data.readUInt16LE(is64 ? 0x3c : 0x30);
  const shstrndx = data.readUInt16LE(is64 ? 0x3e : 0x32);
  if (shoff === 0 || shnum === 0 || shstrndx >= shnum) return null;
  if (shoff + shnum * shentsize > data.length) return null;

  const sectionOffset = (i: number): number => {
    const base = shoff + i * shentsize;
    return is64 ? Number(data.readBigUInt64LE(base + 0x18)) : data.readUInt32LE(base + 0x10);
  };
  const strtabOff = sectionOffset(shstrndx);
  if (strtabOff >= data.length) return null;

  const names: string[] = [];
  for (let i = 0; i < shnum; i++) {
    const nameOff = strtabOff + data.readUInt32LE(shoff + i * shentsize);
    if (nameOff >= data.length) continue;
    const end = data.indexOf(0, nameOff);
    names.push(data.subarray(nameOff, end === -1 ? data.length : end).toString('latin1'));
  }
  return names;
}

/** Extract a printable CodeView PDB path from a PE binary. */
export function pePdbPath(data: Buffer): string | null {
  const rsds = data.indexOf('RSDS');
  if (rsds === -1) return null;
  // After RSDS: 16-byte GUID, 4-byte age, then NUL-terminated PDB path.
  const pathAt = rsds + 24;
  if (pathAt >= data.length) return null;
  const end = data.indexOf(0, pathAt);
  const p = data.subarray(pathAt, end === -1 ? data.length : end).toString('latin1');
  return /^[\x20-\x7e]{3,}\.pdb$/i.test(p) ? p : null;
}

/**
 * Unstripped binaries hand disassemblers (Ghidra/IDA/Hopper — and REA's
 * bridges to them) full symbol names and debug line info.
 */
export const unstrippedSymbolsRule: Rule = {
  id: 'bin/unstripped-symbols',
  title: 'Binary ships symbols or debug info',
  severity: 'high',
  // go-binary included: a Go build without -ldflags="-s -w" ships .symtab too.
  appliesTo: (a) => a.type === 'native-binary' || a.type === 'go-binary',
  check(a): Finding[] {
    if (isElf(a.data)) {
      const sections = elfSectionNames(a.data);
      if (!sections) return [];
      const leaks = sections.filter((s) => s === '.symtab' || s.startsWith('.debug'));
      if (leaks.length === 0) return [];
      return [
        {
          ruleId: this.id,
          severity: leaks.includes('.symtab') ? 'high' : 'warn',
          path: a.path,
          message: `ELF binary ships ${leaks.includes('.symtab') ? 'a full symbol table' : 'debug info'}`,
          evidence: `sections present: ${leaks.join(', ')}`,
          remediation:
            'Strip release binaries (`strip --strip-all`, or `-ldflags="-s -w"` for Go) and split debug info into a separate file (`objcopy --only-keep-debug` / `.debug` packages) that never ships.',
        },
      ];
    }
    if (isPe(a.data)) {
      const pdb = pePdbPath(a.data);
      if (!pdb) return [];
      return [
        {
          ruleId: this.id,
          severity: 'high',
          path: a.path,
          message: 'PE binary references a PDB debug database',
          evidence: `CodeView RSDS record points to ${pdb}`,
          remediation:
            'Ship release builds without embedded PDB references (link with /DEBUG:NONE or strip the debug directory), and keep PDBs on a private symbol server. The leaked path often also reveals build-machine usernames and directory layout.',
        },
      ];
    }
    return [];
  },
};
