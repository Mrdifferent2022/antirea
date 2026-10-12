import type { Finding, Rule } from '../../core/types.js';

// Electron embeds a "fuse wire" in the main binary: sentinel + version + length
// + one ASCII byte per fuse ('1' enabled, '0' disabled, 'r' removed).
const FUSE_SENTINEL = Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX', 'latin1');

// FuseV1Options order from electron/fuses.
const FUSE = {
  RunAsNode: 0,
  EnableCookieEncryption: 1,
  EnableEmbeddedAsarIntegrityValidation: 2,
  OnlyLoadAppFromAsar: 3,
} as const;

export function readFuseWire(data: Buffer): { offset: number; wire: string } | null {
  const at = data.indexOf(FUSE_SENTINEL);
  if (at === -1) return null;
  const wireAt = at + FUSE_SENTINEL.length;
  if (wireAt + 2 > data.length) return null;
  const wireLength = data[wireAt + 1];
  if (wireLength === 0 || wireAt + 2 + wireLength > data.length) return null;
  return { offset: at, wire: data.subarray(wireAt + 2, wireAt + 2 + wireLength).toString('latin1') };
}

/**
 * Without EnableEmbeddedAsarIntegrityValidation, anyone can swap app.asar
 * contents and the app will run them — tampering, not just reading.
 */
export const fuseIntegrityRule: Rule = {
  id: 'electron/fuse-integrity',
  title: 'Electron asar integrity validation fuse is disabled',
  severity: 'high',
  // Cheap type gate only; the sentinel lookup happens once, inside check().
  appliesTo: (a) => a.type === 'native-binary',
  check(a): Finding[] {
    const found = readFuseWire(a.data);
    if (!found) return [];
    const { wire } = found;
    const findings: Finding[] = [];

    const integrity = wire[FUSE.EnableEmbeddedAsarIntegrityValidation];
    const onlyAsar = wire[FUSE.OnlyLoadAppFromAsar];
    if (integrity !== '1' || onlyAsar !== '1') {
      const problems: string[] = [];
      if (integrity !== '1') problems.push('EnableEmbeddedAsarIntegrityValidation=off');
      if (onlyAsar !== '1') problems.push('OnlyLoadAppFromAsar=off');
      findings.push({
        ruleId: this.id,
        severity: this.severity,
        path: a.path,
        message: `Electron fuses not hardened: ${problems.join(', ')}`,
        evidence: `fuse wire at offset ${found.offset}: "${wire}"`,
        remediation:
          'Flip fuses at packaging time with @electron/fuses: enable EnableEmbeddedAsarIntegrityValidation and OnlyLoadAppFromAsar. Without them, app.asar can be replaced or sideloaded and your app will execute the tampered code.',
      });
    }

    if (wire[FUSE.RunAsNode] === '1') {
      findings.push({
        ruleId: this.id,
        severity: 'warn',
        path: a.path,
        message: 'RunAsNode fuse enabled — the binary can be repurposed as a plain Node.js runtime',
        evidence: `fuse wire at offset ${found.offset}: "${wire}" (RunAsNode=1)`,
        remediation:
          'Disable RunAsNode with @electron/fuses. With it on, anyone can run arbitrary JS under your app binary via ELECTRON_RUN_AS_NODE, inheriting its identity and entitlements.',
      });
    }

    return findings;
  },
};
