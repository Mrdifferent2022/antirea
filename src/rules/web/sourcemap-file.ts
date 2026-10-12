import type { Finding, Rule } from '../../core/types.js';

/**
 * A shipped .map file is what REA's sourcemaps module exploits. Severity
 * depends on what's inside: sourcesContent means full source reconstruction
 * (high); without it the map still leaks original file paths and module
 * structure (warn).
 */
export const sourcemapFileRule: Rule = {
  id: 'web/sourcemap-file',
  title: 'Source map file shipped with artifacts',
  severity: 'high',
  appliesTo: (a) => a.type === 'sourcemap',
  check(a): Finding[] {
    let hasSourcesContent = false;
    try {
      const parsed = JSON.parse(a.data.toString('utf8')) as { sourcesContent?: unknown };
      hasSourcesContent = Array.isArray(parsed.sourcesContent) && parsed.sourcesContent.some((s) => typeof s === 'string' && s.length > 0);
    } catch {
      // Not parseable as JSON — still a .map file by name, report conservatively.
    }
    if (!hasSourcesContent) {
      return [
        {
          ruleId: this.id,
          severity: 'warn',
          path: a.path,
          message: 'Source map shipped without embedded sources — leaks original file paths and structure',
          evidence: `${a.path} (${a.size} bytes), no sourcesContent`,
          remediation:
            'Do not deploy .map files to public targets even without sourcesContent — original paths and module structure aid reconstruction. Exclude maps from release artifacts entirely.',
        },
      ];
    }
    return [
      {
        ruleId: this.id,
        severity: this.severity,
        path: a.path,
        message: 'Source map with embedded sourcesContent ships full original source code',
        evidence: `${a.path} contains sourcesContent — original sources can be fully reconstructed`,
        remediation:
          'Do not deploy .map files to public targets. Upload them to your error tracker at build time, then exclude them from the release artifact; or serve them only from an authenticated origin.',
      },
    ];
  },
};
