import type { Finding, Rule } from '../../core/types.js';

interface AsarEntry {
  files?: Record<string, AsarEntry>;
  size?: number;
  offset?: string;
}

/**
 * Parse the asar header. Disk layout (chromium pickle):
 *   u32 payloadSize(=4) | u32 headerBufLen | u32 payloadSize | u32 jsonLen | json...
 * Returns the file tree, or null if the header doesn't parse.
 */
export function parseAsarHeader(data: Buffer): string[] | null {
  if (data.length < 16) return null;
  if (data.readUInt32LE(0) !== 4) return null;
  const headerBufLen = data.readUInt32LE(4);
  if (data.readUInt32LE(8) !== headerBufLen - 4) return null;
  const jsonLen = data.readUInt32LE(12);
  if (jsonLen === 0 || jsonLen > data.length - 16) return null;
  let header: { files?: Record<string, AsarEntry> };
  try {
    header = JSON.parse(data.subarray(16, 16 + jsonLen).toString('utf8'));
  } catch {
    return null;
  }
  if (!header.files || typeof header.files !== 'object') return null;

  const paths: string[] = [];
  const walk = (files: Record<string, AsarEntry>, prefix: string): void => {
    for (const [name, entry] of Object.entries(files)) {
      const p = prefix ? `${prefix}/${name}` : name;
      paths.push(p);
      if (entry.files) walk(entry.files, p);
    }
  };
  walk(header.files, '');
  return paths;
}

/**
 * An asar archive is plaintext by design — anyone can list and extract it
 * with one command (`npx asar extract`). This is what REA's Electron
 * analysis feeds on.
 */
export const plaintextAsarRule: Rule = {
  id: 'electron/plaintext-asar',
  title: 'Electron asar archive is plaintext-readable',
  severity: 'high',
  appliesTo: (a) => a.type === 'electron-asar',
  check(a): Finding[] {
    const paths = parseAsarHeader(a.data);
    if (!paths) return []; // Not a parseable asar — nothing proven.
    const sample = paths.slice(0, 8).join(', ');
    return [
      {
        ruleId: this.id,
        severity: this.severity,
        path: a.path,
        message: 'Electron asar archive can be listed and extracted in plaintext',
        evidence: `asar header parsed: ${paths.length} entries, e.g. ${sample}${paths.length > 8 ? ', …' : ''}`,
        remediation:
          'Asar offers no confidentiality — assume every byte is public. Move secrets/proprietary logic server-side, enable Electron fuses (EnableEmbeddedAsarIntegrityValidation + OnlyLoadAppFromAsar), and obfuscate the JS before packaging.',
      },
    ];
  },
};
