import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { detectType } from './detect.js';
import type { Artifact, Finding, Rule, ScanResult, Severity } from './types.js';

export interface ScanOptions {
  /** Directories/files to never enter, matched on path segments. */
  ignore?: string[];
  /** Skip files larger than this (bytes). Default 64 MiB. */
  maxFileSize?: number;
}

const DEFAULT_IGNORE = ['.git', 'node_modules'];
const DEFAULT_MAX_FILE_SIZE = 64 * 1024 * 1024;

async function* walk(root: string, ignore: string[]): AsyncGenerator<string> {
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    if (ignore.includes(entry.name)) continue;
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) {
      yield* walk(full, ignore);
    } else if (entry.isFile()) {
      yield full;
    }
  }
}

/** Scan a directory (or single file) with the given rules. */
export async function scan(target: string, rules: Rule[], options: ScanOptions = {}): Promise<ScanResult> {
  const ignore = options.ignore ?? DEFAULT_IGNORE;
  const maxFileSize = options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;

  const rootStat = await stat(target);
  const root = rootStat.isDirectory() ? target : path.dirname(target);
  const files = rootStat.isDirectory() ? walk(target, ignore) : (async function* () { yield target; })();

  const findings: Finding[] = [];
  const bySeverity: Record<Severity, number> = { info: 0, warn: 0, high: 0, critical: 0 };
  let filesScanned = 0;

  for await (const file of files) {
    const fileStat = await stat(file);
    if (fileStat.size > maxFileSize) continue;
    const data = await readFile(file);
    const artifact: Artifact = {
      path: path.relative(root, file).split(path.sep).join('/'),
      type: detectType(file, data),
      size: data.length,
      data,
    };
    filesScanned++;
    for (const rule of rules) {
      if (!rule.appliesTo(artifact)) continue;
      for (const finding of rule.check(artifact)) {
        findings.push(finding);
        bySeverity[finding.severity]++;
      }
    }
  }

  findings.sort((a, b) => a.path.localeCompare(b.path) || a.ruleId.localeCompare(b.ruleId));
  return { findings, summary: { filesScanned, bySeverity } };
}
