import type { Finding, Rule } from '../../core/types.js';

const GO_BUILDINFO_MAGIC = Buffer.from('\xff Go buildinf:', 'latin1');
const GO_VERSION_RE = /go1\.\d+(?:\.\d+)?[a-z0-9]*/;
// modinfo lines look like: "mod\texample.com/mod\tv1.2.3\th1:..." / "build\tGOARCH=amd64"
const MOD_LINE_RE = /(?:^|\n)(path|mod|dep|build)\t([^\n]+)/g;

function extractPrintableRegion(data: Buffer, from: number, length: number): string {
  const slice = data.subarray(from, Math.min(data.length, from + length));
  return slice.toString('latin1');
}

/**
 * Go binaries embed runtime build metadata (module path, dependency list,
 * VCS revision, build flags) unless you opt out — REA's go module reads
 * exactly this. We locate the magic, then parse the printable modinfo text
 * stored nearby in the data segment.
 */
export const goBuildinfoRule: Rule = {
  id: 'go/buildinfo-leak',
  title: 'Go binary embeds build metadata',
  severity: 'warn',
  appliesTo: (a) => a.type === 'go-binary',
  check(a): Finding[] {
    const magicAt = a.data.indexOf(GO_BUILDINFO_MAGIC);
    if (magicAt === -1) return [];

    // The modinfo string is referenced by pointer from the header, so it lives
    // elsewhere in the data segment; scan the whole binary for its line grammar.
    const text = extractPrintableRegion(a.data, 0, a.data.length);
    const modulePaths: string[] = [];
    const buildSettings: string[] = [];
    for (const m of text.matchAll(MOD_LINE_RE)) {
      const [_, key, value] = m;
      const firstField = value.split('\t')[0].trim();
      if (key === 'mod' || key === 'path') {
        if (firstField && !/[^\x20-\x7e]/.test(firstField)) modulePaths.push(firstField);
      } else if (key === 'build') {
        if (!/[^\x20-\x7e]/.test(firstField)) buildSettings.push(firstField);
      }
    }
    const version = GO_VERSION_RE.exec(text)?.[0];

    const vcsSettings = buildSettings.filter((s) => /^vcs\./.test(s));
    const hasVcs = vcsSettings.length > 0;

    const evidenceParts = [
      'Go buildinf magic at offset ' + magicAt,
      version ? `compiler ${version}` : null,
      modulePaths.length > 0 ? `module ${modulePaths[0]}` : null,
      hasVcs ? `VCS settings: ${vcsSettings.join(', ')}` : null,
      buildSettings.length > 0 ? `${buildSettings.length} build settings embedded` : null,
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
