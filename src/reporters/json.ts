import type { ScanResult } from '../core/types.js';

export function renderJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}
