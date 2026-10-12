import type { ArtifactType } from './types.js';

const GO_BUILDINFO_MAGIC = Buffer.from('\xff Go buildinf:', 'latin1');

const MACHO_MAGICS = [0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca];

function isElf(data: Buffer): boolean {
  return data.length > 4 && data[0] === 0x7f && data[1] === 0x45 && data[2] === 0x4c && data[3] === 0x46;
}

function isPe(data: Buffer): boolean {
  return data.length > 2 && data[0] === 0x4d && data[1] === 0x5a; // 'MZ'
}

function isMachO(data: Buffer): boolean {
  if (data.length < 4) return false;
  const magic = data.readUInt32BE(0);
  return MACHO_MAGICS.includes(magic);
}

/** Classify a file by extension first, then by binary magic. */
export function detectType(path: string, data: Buffer): ArtifactType {
  const lower = path.toLowerCase();
  if (lower.endsWith('.map')) return 'sourcemap';
  if (/\.(m?js|cjs|jsx|ts|tsx)$/.test(lower)) return 'javascript';

  if (isElf(data) || isPe(data) || isMachO(data)) {
    if (data.includes(GO_BUILDINFO_MAGIC)) return 'go-binary';
    return 'native-binary';
  }
  return 'unknown';
}
