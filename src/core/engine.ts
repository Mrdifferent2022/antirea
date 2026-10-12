import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { detectType } from './detect.js';
import type { Artifact, Finding, Rule, ScanResult, Severity } from './types.js';

export interface ScanOptions {
  /** Extra names/globs to never scan, matched on each path segment's basename.
   *  Supports `*` as a single-segment wildcard (e.g. `*.map`). `.git` and
   *  `node_modules` are always ignored. */
  ignore?: string[];
  /** Skip files larger than this (bytes). Default 64 MiB. */
  maxFileSize?: number;
}

const DEFAULT_IGNORE = ['.git', 'node_modules'];
const DEFAULT_MAX_FILE_SIZE = 64 * 1024 * 1024;
const IGNORE_FILE = '.antireaignore';

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Match a basename against patterns; `*` matches within one segment. */
export function matchesIgnore(name: string, patterns: string[]): boolean {
  for (const p of patterns) {
    if (p === name) return true;
    if (p.includes('*')) {
      const re = new RegExp('^' + p.split('*').map(escapeRegExp).join('[^/]*') + '$');
      if (re.test(name)) return true;
    }
  }
  return false;
}

/** Read gitignore-style patterns from <root>/.antireaignore, if present. */
async function readIgnoreFile(root: string): Promise<string[]> {
  try {
    const text = await readFile(path.join(root, IGNORE_FILE), 'utf8');
    return text
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith('#'));
  } catch {
    return [];
  }
}

async function* walk(root: string, ignore: string[]): AsyncGenerator<string> {
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === IGNORE_FILE) continue;
    if (matchesIgnore(entry.name, ignore)) continue;
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
  const maxFileSize = options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;

  const rootStat = await stat(target);
  const root = rootStat.isDirectory() ? target : path.dirname(target);
  const ignore = [...DEFAULT_IGNORE, ...(await readIgnoreFile(root)), ...(options.ignore ?? [])];
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
