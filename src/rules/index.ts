import type { Rule } from '../core/types.js';
import { sourcemapFileRule } from './web/sourcemap-file.js';
import { sourcemapUrlRule } from './web/sourcemap-url.js';
import { goBuildinfoRule } from './go/buildinfo.js';
import { plaintextAsarRule } from './electron/asar.js';
import { fuseIntegrityRule } from './electron/fuses.js';
import { unstrippedSymbolsRule } from './binary/symbols.js';

/** All built-in rules, in stable order. */
export const builtinRules: Rule[] = [
  sourcemapFileRule,
  sourcemapUrlRule,
  goBuildinfoRule,
  plaintextAsarRule,
  fuseIntegrityRule,
  unstrippedSymbolsRule,
];
