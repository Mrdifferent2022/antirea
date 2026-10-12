import type { Finding, Rule } from '../../core/types.js';

const GO_BUILDINFO_MAGIC = Buffer.from('\xff Go buildinf:', 'latin1');
const MOD_ANCHOR = Buffer.from('\nmod\t', 'latin1');
const GO_VERSION_RE = /go1\.\d+(?:\.\d+)?[a-z0-9]*/;
const MOD_LINE_RE = /^(path|mod|dep|build)\t([^\n]*)$/;
const NON_PRINTABLE_RE = /[^\x09\x20-\x7e]/;

// The modinfo string is referenced by pointer from the buildinfo header, so it
// can live anywhere in the data segment. Parsing raw pointers would require
// VA→file-offset mapping per container format; instead we anchor on the
// "\nmod\t" line grammar and consume the contiguous block around it. This
// bounds both the work and the false-positive surface.
const WINDOW_BEFORE = 2048;
const WINDOW_AFTER = 64 * 1024;

function extractModinfoBlock(data: Buffer): string[] | null {
  let from = 0;
  for (;;) {
    const at = data.indexOf(MOD_ANCHOR, from);
    if (at === -1) return null;

    const winStart = Math.max(0, at - WINDOW_BEFORE);
    const winEnd = Math.min(data.length, at + WINDOW_AFTER);
    const lines = data.subarray(winStart, winEnd).toString('latin1').split('\n');

    // Locate the line containing the anchor ("mod\t..." starts right after it).
    let offset = 0;
    let anchorIdx = -1;
    const anchorPos = at - winStart + 1; // skip the leading '\n'
    for (let i = 0; i < lines.length; i++) {
      if (offset === anchorPos && lines[i].startsWith('mod\t')) {
        anchorIdx = i;
        break;
      }
      offset += lines[i].length + 1;
    }
    if (anchorIdx >= 0) {
      let start = anchorIdx;
      while (start > 0 && MOD_LINE_RE.test(lines[start - 1]) && !NON_PRINTABLE_RE.test(lines[start - 1])) start--;
      let end = anchorIdx;
      while (end + 1 < lines.length && MOD_LINE_RE.test(lines[end + 1]) && !NON_PRINTABLE_RE.test(lines[end + 1])) end++;
      const block = lines.slice(start, end + 1).filter((l) => !NON_PRINTABLE_RE.test(l));
      if (block.some((l) => l.startsWith('mod\t'))) return block;
    }
    from = at + 1;
  }
}

/**
 * Go binaries embed runtime build metadata (module path, dependency list,
 * VCS revision, build flags) unless you opt out — REA's `inspect-go-binary`
 * reads exactly this.
 */
export const goBuildinfoRule: Rule = {
  id: 'go/buildinfo-leak',
  title: 'Go binary embeds build metadata',
  severity: 'warn',
  appliesTo: (a) => a.type === 'go-binary',
  check(a): Finding[] {
    const magicAt = a.data.indexOf(GO_BUILDINFO_MAGIC);
    if (magicAt === -1) return [];

    const modulePaths = new Set<string>();
    const buildSettings = new Set<string>();
    const block = extractModinfoBlock(a.data);
    if (block) {
      for (const line of block) {
        const m = MOD_LINE_RE.exec(line);
        if (!m) continue;
        const firstField = m[2].split('\t')[0].trim();
        if (!firstField) continue;
        if (m[1] === 'mod' || m[1] === 'path') modulePaths.add(firstField);
        else if (m[1] === 'build') buildSettings.add(firstField);
      }
    }

    // The version string sits right after the buildinfo header pointers.
    const versionWindow = a.data
      .subarray(magicAt, Math.min(a.data.length, magicAt + 64 * 1024))
      .toString('latin1');
    const version = GO_VERSION_RE.exec(versionWindow)?.[0];

    const vcsSettings = [...buildSettings].filter((s) => /^vcs\./.test(s));
    const hasVcs = vcsSettings.length > 0;

    const evidenceParts = [
      'Go buildinf magic at offset ' + magicAt,
      version ? `compiler ${version}` : null,
      modulePaths.size > 0 ? `module ${[...modulePaths][0]}` : null,
      hasVcs ? `VCS settings: ${vcsSettings.join(', ')}` : null,
      buildSettings.size > 0 ? `${buildSettings.size} build settings embedded` : null,
      !block ? 'no parseable modinfo block found' : null,
    ].filter(Boolean);

    return [
      {
        ruleId: this.id,
        severity: hasVcs ? 'high' : this.severity,
        path: a.path,
        message: hasVcs
          ? 'Go binary embeds build metadata including VCS revision'
          : 'Go binary embeds build metadata (module path, deps, build flags)',
        evidence: evidenceParts.join('; '),
        remediation:
          'Build with `-trimpath -buildvcs=false -ldflags="-s -w"` to drop local paths, VCS stamps, and symbol tables. Module path itself is intrinsic to Go binaries — avoid leaking internal domains in module names.',
      },
    ];
  },
};
