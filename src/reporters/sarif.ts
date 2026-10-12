import type { Finding, ScanResult, Severity } from '../core/types.js';
import { builtinRules } from '../rules/index.js';

const SARIF_LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  warn: 'warning',
  info: 'note',
};

function toSarifResult(f: Finding) {
  return {
    ruleId: f.ruleId,
    level: SARIF_LEVEL[f.severity],
    message: { text: `${f.message}\nEvidence: ${f.evidence}\nFix: ${f.remediation}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.path },
        },
      },
    ],
  };
}

/** SARIF 2.1.0 — uploadable to GitHub Code Scanning and most SAST dashboards. */
export function renderSarif(result: ScanResult): string {
  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'antirea',
            version: '0.2.0',
            informationUri: 'https://github.com/Mrdifferent2022/antirea',
            rules: builtinRules.map((r) => ({
              id: r.id,
              name: r.title,
              shortDescription: { text: r.title },
              defaultConfiguration: { level: SARIF_LEVEL[r.severity] },
            })),
          },
        },
        results: result.findings.map(toSarifResult),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}
