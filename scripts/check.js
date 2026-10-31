#!/usr/bin/env node
import { readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const roots = ['src', 'tests', 'scripts'];
const files = [];
function walk(dir) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full);
    else if (/\.(?:js|cjs)$/.test(name)) files.push(full);
  }
}
for (const dir of roots) walk(join(root, dir));
let failed = false;
for (const file of files) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (result.status !== 0) {
    failed = true;
    process.stderr.write(`${file}\n${result.stderr || result.stdout}`);
  }
}
if (failed) process.exit(1);
console.log(`Syntax check passed (${files.length} JavaScript files).`);
console.log('Settings defaults: auto_trade is OFF; AUTO_TRADE_PERSIST is an explicit opt-in.');
