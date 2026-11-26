#!/usr/bin/env node
// Refuses a commit or push that names a target of an open (unfiled or unpatched) finding.
//
// The list lives in `.open-findings` at the repo root: one term per line, `#` comments.
// It is gitignored, so the names never reach the remote. An EMPTY file means "no open
// findings"; a MISSING file fails, because a guard with nothing to check would pass silently.
//
//   node scripts/open-finding-guard.mjs --staged         (pre-commit: staged diff + paths)
//   node scripts/open-finding-guard.mjs --range A..B     (pre-push: every commit in range)
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const git = (...args) =>
  execFileSync('git', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
const root = git('rev-parse', '--show-toplevel').trim();
const listFile = path.join(root, '.open-findings');

if (!fs.existsSync(listFile)) {
  console.error(
    'open-finding-guard: no .open-findings file at the repo root.\n' +
      'Create it with one open-finding target per line (it is gitignored), or empty if none.',
  );
  process.exit(1);
}

const terms = fs
  .readFileSync(listFile, 'utf8')
  .split('\n')
  .map((l) => l.replace(/#.*/, '').trim().toLowerCase())
  .filter(Boolean);
if (terms.length === 0) process.exit(0);

const [mode, range] = process.argv.slice(2);
let text;
if (mode === '--staged') {
  text =
    git('diff', '--cached', '--unified=0', '--no-color') +
    git('diff', '--cached', '--name-only');
} else if (mode === '--range' && range) {
  text = git('log', '-p', '--no-color', '--format=%B', range);
} else {
  console.error('usage: open-finding-guard.mjs --staged | --range <A..B>');
  process.exit(2);
}

// Only lines being added count: removing a mention must always be allowed.
const added = text
  .split('\n')
  .filter((l) => !l.startsWith('-'))
  .join('\n')
  .toLowerCase();
const hits = terms.filter((t) => added.includes(t));
if (hits.length > 0) {
  console.error(
    `open-finding-guard: ${hits.length} open-finding term(s) from .open-findings appear in what you are about to publish.\n` +
      'Remove them. Open findings stay in private advisories until fixed and disclosed.',
  );
  process.exit(1);
}
