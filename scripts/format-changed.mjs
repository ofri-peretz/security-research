#!/usr/bin/env node
// prettier --check, limited to files changed against the base branch (default origin/main).
// The labs predate the formatter. They get formatted when someone next edits them, not in a
// bulk rewrite, the same as the eslint monorepo's format-drift gate.
import { execFileSync, spawnSync } from 'node:child_process';

const base = process.argv[2] ?? 'origin/main';
const changed = execFileSync(
  'git',
  ['diff', '--name-only', '--diff-filter=ACMR', `${base}...HEAD`],
  { encoding: 'utf8' },
)
  .split('\n')
  .filter(Boolean);
if (changed.length === 0) {
  console.log(`format: no files changed against ${base}`);
  process.exit(0);
}
const r = spawnSync(
  'npx',
  ['--no', '--', 'prettier', '--check', '--ignore-unknown', ...changed],
  { stdio: 'inherit' },
);
process.exit(r.status ?? 1);
