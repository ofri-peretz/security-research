#!/usr/bin/env node
// Rebuilds the dogfood inputs from the live labs, then renders the report:
//   1. ESLint (our plugins, strict) over the 9 vulnerable servers, converted to SARIF
//   2. merged with manual.sarif (the tester's exploit results)
//   3. `npm run verify` in protocol-ctf, keeping only lab headers and PASS/FAIL lines, as retest evidence
//   4. report/cli.mjs
// The outputs are committed. report.test.mjs re-renders from them and compares with out/.
import { ESLint } from 'eslint';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { stripVTControlCharacters } from 'node:util';
import { eslintToSarifRun } from '../sarif.mjs';

const here = import.meta.dirname;
const root = path.resolve(here, '..', '..');
const lab = path.join(root, 'protocol-ctf');
const servers = fs
  .readdirSync(path.join(lab, 'challenges'))
  .flatMap((t) =>
    fs
      .readdirSync(path.join(lab, 'challenges', t))
      .map((id) => path.join(lab, 'challenges', t, id, 'server.mjs')),
  )
  .sort();

const eslint = new ESLint({
  cwd: root,
  ignore: false,
  overrideConfigFile: path.join(root, 'eslint.config.mjs'),
});
const pkg = (n) =>
  JSON.parse(
    fs.readFileSync(path.join(root, 'node_modules', n, 'package.json'), 'utf8'),
  ).version;
const version = [
  'eslint',
  'eslint-plugin-node-security',
  'eslint-plugin-secure-coding',
  'eslint-plugin-mcp-sdk-security',
]
  .map((n) => `${n}@${pkg(n)}`)
  .join(' ');
const eslintRun = eslintToSarifRun(await eslint.lintFiles(servers), {
  root,
  version,
});
const manual = JSON.parse(
  fs.readFileSync(path.join(here, 'manual.sarif'), 'utf8'),
);
const sarif = { ...manual, runs: [eslintRun, ...manual.runs] };
fs.writeFileSync(
  path.join(here, 'results.sarif'),
  JSON.stringify(sarif, null, 2) + '\n',
);

const raw = execFileSync('npm', ['--prefix', lab, 'run', '-s', 'verify'], {
  encoding: 'utf8',
});
const plain = stripVTControlCharacters(raw);
const kept = plain
  .split('\n')
  .filter((l) => /^\S/.test(l) || /^\s+(PASS|FAIL)\s/.test(l) || l === '')
  .join('\n')
  .replace(/\n{3,}/g, '\n\n');
fs.writeFileSync(path.join(here, 'verify.log'), '\n' + kept.trim() + '\n\n');

fs.mkdirSync(path.join(here, 'out'), { recursive: true });
execFileSync(
  process.execPath,
  [
    path.join(here, '..', 'cli.mjs'),
    '--sarif',
    'results.sarif',
    '--engagement',
    'engagement.json',
    '--findings',
    'findings.json',
    '--log',
    'verify.log',
    '--out',
    'out/report.html',
  ],
  { cwd: here, stdio: 'inherit' },
);
