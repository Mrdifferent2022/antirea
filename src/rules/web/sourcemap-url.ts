import type { Finding, Rule } from '../../core/types.js';

const SOURCEMAP_URL_RE = /\/{2}#\s*sourceMappingURL=(\S+)|\/\*#\s*sourceMappingURL=([^*]+)\*\//;
const INLINE_DATA_RE = /^data:application\/json[^,]*;base64,(.+)$/;
// Inline maps are self-contained; cap the tail window and decode size to
// defend against memory amplification on huge bundles.
const TAIL_WINDOW = 32 * 1024 * 1024;
const MAX_INLINE_B64_LEN = ((16 * 1024 * 1024) / 3) * 4;

interface InlineMapInfo {
  decoded: boolean;
  hasSourcesContent: boolean;
  sourceNames: string[];
}

function decodeInlineMap(url: string): InlineMapInfo | null {
  const m = INLINE_DATA_RE.exec(url);
  if (!m) return null;
  if (m[1].length > MAX_INLINE_B64_LEN) {
    return { decoded: false, hasSourcesContent: false, sourceNames: [] };
  }
  try {
    const parsed = JSON.parse(Buffer.from(m[1], 'base64').toString('utf8')) as {
      sources?: unknown;
      sourcesContent?: unknown;
    };
    const sourceNames = Array.isArray(parsed.sources)
      ? parsed.sources.filter((s): s is string => typeof s === 'string')
      : [];
    const hasSourcesContent =
      Array.isArray(parsed.sourcesContent) &&
      parsed.sourcesContent.some((s) => typeof s === 'string' && s.length > 0);
    return { decoded: true, hasSourcesContent, sourceNames };
  } catch {
    return { decoded: false, hasSourcesContent: false, sourceNames: [] };
  }
}

/**
 * A sourceMappingURL comment tells reverse-engineering tools exactly where the
 * map is. Severity scales with how much is handed over:
 *   inline data URL with sourcesContent → critical (full sources, zero requests)
 *   inline data URL without sourcesContent / remote http(s) map → high
 *   relative reference → warn
 */
export const sourcemapUrlRule: Rule = {
  id: 'web/sourcemap-url',
  title: 'Bundle references a source map',
  severity: 'warn',
  appliesTo: (a) => a.type === 'javascript',
  check(a): Finding[] {
    const tail = a.data.subarray(Math.max(0, a.data.length - TAIL_WINDOW)).toString('utf8');
    const match = SOURCEMAP_URL_RE.exec(tail);
    if (!match) return [];
    const url = (match[1] ?? match[2] ?? '').trim();

    const inline = decodeInlineMap(url);
    const isRemote = /^https?:\/\//.test(url);
    const base = { ruleId: this.id, path: a.path };

    if (inline) {
      if (inline.hasSourcesContent) {
        return [
          {
            ...base,
            severity: 'critical',
            message: 'Bundle embeds a complete inline source map with full original sources',
            evidence: `inline data URL decodes to a source map containing sourcesContent for: ${inline.sourceNames.slice(0, 5).join(', ')}${inline.sourceNames.length > 5 ? ', …' : ''}`,
            remediation:
              'Never ship bundles with inline source maps — they hand over your complete original sources with zero extra requests. Remove the inline map from production builds; upload maps to your error tracker at build time instead.',
          },
        ];
      }
      return [
        {
          ...base,
          severity: 'high',
          message: 'Bundle embeds an inline source map',
          evidence: inline.decoded
            ? `inline data URL decodes to a source map (sources: ${inline.sourceNames.slice(0, 5).join(', ') || 'none listed'})`
            : 'inline data URL present but payload could not be decoded',
          remediation:
            'Strip inline source maps from production builds. Even without sourcesContent, the map exposes your original file paths and module structure.',
        },
      ];
    }
    if (isRemote) {
      return [
        {
          ...base,
          severity: 'high',
          message: 'Bundle points to a remotely fetchable source map',
          evidence: `sourceMappingURL=${url}`,
          remediation:
            'Strip the sourceMappingURL comment from production builds, or require authentication on the map origin. Anyone can now download your full sources.',
        },
      ];
    }
    return [
      {
        ...base,
        severity: 'warn',
        message: 'Bundle contains a sourceMappingURL reference',
        evidence: `sourceMappingURL=${url}`,
        remediation:
          'Strip the sourceMappingURL comment from production builds (e.g. terser/esbuild `drop` or a post-build pass), and make sure the referenced map is not deployed alongside.',
      },
    ];
  },
};
