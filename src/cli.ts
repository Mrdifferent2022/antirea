#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { builtinRules } from './rules/index.js';
import { scan } from './core/engine.js';
import { renderConsole } from './reporters/console.js';
import { renderJson } from './reporters/json.js';
import { SEVERITY_ORDER, severityAtLeast, type Severity } from './core/types.js';

const USAGE = `antirea — lint your shipped artifacts for information leaks

Usage:
  antirea scan <path> [options]

Options:
  --format <console|json>   Output format (default: console)
  --fail-on <severity>      Exit 1 when any finding reaches this severity
                            (info|warn|high|critical, default: high)
  --version                 Print version
  --help                    Show this help
`;

async function main(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      format: { type: 'string', default: 'console' },
      'fail-on': { type: 'string', default: 'high' },
      version: { type: 'boolean', default: false },
      help: { type: 'boolean', default: false },
    },
  });

  if (values.help) {
    console.log(USAGE);
    return 0;
  }
  if (values.version) {
    console.log('antirea 0.1.0');
    return 0;
  }

  const [command, target] = positionals;
  if (command !== 'scan' || !target) {
    console.error(USAGE);
    return 2;
  }
  if (values.format !== 'console' && values.format !== 'json') {
    console.error(`unknown --format: ${values.format}`);
    return 2;
  }
  if (!SEVERITY_ORDER.includes(values['fail-on'] as Severity)) {
    console.error(`unknown --fail-on severity: ${values['fail-on']}`);
    return 2;
  }
  const failOn = values['fail-on'] as Severity;

  const result = await scan(target, builtinRules);
  console.log(values.format === 'json' ? renderJson(result) : renderConsole(result));

  return result.findings.some((f) => severityAtLeast(f.severity, failOn)) ? 1 : 0;
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err: unknown) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(2);
  },
);
