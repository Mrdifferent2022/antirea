export type Severity = 'info' | 'warn' | 'high' | 'critical';

export const SEVERITY_ORDER: readonly Severity[] = ['info', 'warn', 'high', 'critical'];

export function severityAtLeast(a: Severity, b: Severity): boolean {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b);
}

export type ArtifactType =
  | 'javascript'
  | 'sourcemap'
  | 'go-binary'
  | 'native-binary'
  | 'unknown';

export interface Artifact {
  /** Path relative to the scan root, using forward slashes. */
  path: string;
  type: ArtifactType;
  size: number;
  data: Buffer;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  path: string;
  message: string;
  /** Concrete proof of the leak: a snippet, offset, or extracted value. */
  evidence: string;
  /** Actionable fix, not a generic platitude. */
  remediation: string;
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  appliesTo(artifact: Artifact): boolean;
  check(artifact: Artifact): Finding[];
}

export interface ScanSummary {
  filesScanned: number;
  bySeverity: Record<Severity, number>;
}

export interface ScanResult {
  findings: Finding[];
  summary: ScanSummary;
}
