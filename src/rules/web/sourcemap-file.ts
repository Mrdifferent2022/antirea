import type { Finding, Rule } from '../../core/types.js';

/**
 * A shipped .map file lets anyone fully reconstruct your original sources —
 * this is exactly what REA's sourcemaps module exploits.
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
    return [
      {
        ruleId: this.id,
        severity: this.severity,
        path: a.path,
        message: hasSourcesContent
          ? 'Source map with embedded sourcesContent ships full original source code'
          : 'Source map file shipped with artifacts',
        evidence: hasSourcesContent
          ? `${a.path} contains sourcesContent — original sources can be fully reconstructed`
          : `${a.path} (${a.size} bytes)`,
        remediation:
          'Do not deploy .map files to public targets. Upload them to your error tracker at build time, then exclude them from the release artifact; or serve them only from an authenticated origin.',
      },
    ];
  },
};
