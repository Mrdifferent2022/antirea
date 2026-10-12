import type { ScanResult, Severity } from '../core/types.js';

const SEVERITY_TAG: Record<Severity, string> = {
  critical: 'CRIT',
  high: 'HIGH',
  warn: 'WARN',
  info: 'INFO',
};

/** Plain-text, CI-log-friendly report. No color dependency. */
export function renderConsole(result: ScanResult): string {
  const lines: string[] = [];
  if (result.findings.length === 0) {
    lines.push(`shiplint: no leaks found (${result.summary.filesScanned} files scanned)`);
    return lines.join('\n');
  }
  for (const f of result.findings) {
    lines.push(`[${SEVERITY_TAG[f.severity]}] ${f.path}`);
    lines.push(`  ${f.ruleId} — ${f.message}`);
    lines.push(`  evidence: ${f.evidence}`);
    lines.push(`  fix: ${f.remediation}`);
    lines.push('');
  }
  const s = result.summary.bySeverity;
  lines.push(
    `shiplint: ${result.findings.length} finding(s) across ${result.summary.filesScanned} files ` +
      `(critical ${s.critical}, high ${s.high}, warn ${s.warn}, info ${s.info})`,
  );
  return lines.join('\n');
}
