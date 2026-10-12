import type { Finding, Rule } from '../../core/types.js';

const SOURCEMAP_URL_RE = /\/{2}#\s*sourceMappingURL=(\S+)|\/\*#\s*sourceMappingURL=([^*]+)\*\//;

/**
 * A sourceMappingURL comment in a shipped bundle tells every reverse-engineering
 * tool exactly where to fetch the map — even if the map itself lives elsewhere.
 */
export const sourcemapUrlRule: Rule = {
  id: 'web/sourcemap-url',
  title: 'Bundle references a source map',
  severity: 'warn',
  appliesTo: (a) => a.type === 'javascript',
  check(a): Finding[] {
    // The directive is always at the end of the file; scan the last 4 KiB.
    const tail = a.data.subarray(Math.max(0, a.data.length - 4096)).toString('utf8');
    const match = SOURCEMAP_URL_RE.exec(tail);
    if (!match) return [];
    const url = (match[1] ?? match[2] ?? '').trim();
    const isRemote = /^https?:\/\//.test(url);
    return [
      {
        ruleId: this.id,
        severity: isRemote ? 'high' : this.severity,
        path: a.path,
        message: isRemote
          ? 'Bundle points to a remotely fetchable source map'
          : 'Bundle contains a sourceMappingURL reference',
        evidence: `sourceMappingURL=${url}`,
        remediation: isRemote
          ? 'Strip the sourceMappingURL comment from production builds, or require authentication on the map origin. Anyone can now download your full sources.'
          : 'Strip the sourceMappingURL comment from production builds (e.g. terser/esbuild `drop` or a post-build pass), and make sure the referenced map is not deployed alongside.',
      },
    ];
  },
};
