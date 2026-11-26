#!/usr/bin/env node
// A client engagement, from intake to retest letter. Client data stays in SR_HOME/clients/<slug>
// (default ~/.security-research), never in this repo.
//
//   npm run engagement -- new <slug> "<Client legal name>" --tester "<name>"
//   npm run engagement -- status <slug>
//   npm run engagement -- build <slug> [--previous <earlier report.json>]
//   npm run engagement -- retest <slug> <F-id> --commit <sha> --result pass|fail --by "<name>" --evidence "<what you saw>"
//   npm run engagement -- letter <slug>
//
// Workspace: engagement.json, findings.json, manual.json (manual test results, M-01…),
// tool/*.sarif (scanner output), evidence/, scoping.md and authorization.md (send to the client),
// out/ (report.html, report.json, retest-letter.html).
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { validate } from '../report/validate.mjs';
import { render, enrich, retestLetter } from '../report/render.mjs';
import * as E from './lib/engagement.mjs';

const { values: o, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    tester: { type: 'string' },
    previous: { type: 'string' },
    commit: { type: 'string' },
    result: { type: 'string' },
    by: { type: 'string' },
    evidence: { type: 'string' },
    date: { type: 'string' },
  },
});
const [cmd, slug, ...rest] = positionals;
const today = new Date().toISOString().slice(0, 10);
const fail = (msg) => {
  console.error(msg);
  process.exit(1);
};
if (!slug)
  fail(
    'usage: engagement new|status|build|retest|letter <slug> … (see the header of scripts/engagement.mjs)',
  );
const dir = E.clientDir(slug);
const read = (f) => fs.readFileSync(path.join(dir, f), 'utf8');
const json = (f) => JSON.parse(read(f));
const write = (f, text) =>
  fs.writeFileSync(path.join(dir, f), text, { mode: 0o600 });

const commands = {
  new() {
    const client =
      rest[0] ??
      fail(
        'usage: engagement new <slug> "<Client legal name>" --tester "<name>"',
      );
    const tester =
      o.tester ??
      fail('--tester is required: who performs and signs the assessment');
    E.createWorkspace({ slug, client, tester, today });
    console.log(`${slug}: workspace created at ${dir}`);
    console.log(
      'Next: send scoping.md and authorization.md to the client. Start testing only after authorization.md is signed.',
    );
  },

  status() {
    const e = json('engagement.json');
    const f = json('findings.json');
    const by = (k, xs) =>
      Object.entries(
        xs.reduce((a, x) => ({ ...a, [x[k]]: (a[x[k]] ?? 0) + 1 }), {}),
      );
    console.log(
      `${slug}: ${e.client}, ${e.target.name} at ${e.target.version}`,
    );
    console.log(
      `coverage: ${by('result', e.coverage)
        .map(([k, n]) => `${n} ${k}`)
        .join(', ')}`,
    );
    console.log(
      `findings: ${
        f.findings.length
          ? by('status', f.findings)
              .map(([k, n]) => `${n} ${k}`)
              .join(', ')
          : 'none yet'
      }`,
    );
    console.log(
      `manual results: ${json('manual.json').length}, tool runs: ${fs.readdirSync(path.join(dir, 'tool')).filter((x) => x.endsWith('.sarif')).length}`,
    );
  },

  build() {
    const engagement = json('engagement.json');
    const findings = json('findings.json');
    const sarif = E.mergedSarif(dir, engagement.tester.name);
    const sarifText = JSON.stringify(sarif, null, 2) + '\n';
    write('results.sarif', sarifText);
    const errors = validate({ engagement, sarif, findings });
    if (errors.length)
      fail(
        `${slug}: report refused, ${errors.length} problem(s):\n  ✖ ${errors.join('\n  ✖ ')}`,
      );
    const cur = { engagement, findings: enrich(findings.findings) };
    const changes = o.previous
      ? E.diffReports(JSON.parse(fs.readFileSync(o.previous, 'utf8')), cur)
      : undefined;
    const sha = (t) => crypto.createHash('sha256').update(t).digest('hex');
    const hashes = {
      'results.sarif': sha(sarifText),
      'engagement.json': sha(read('engagement.json')),
      'findings.json': sha(read('findings.json')),
    };
    write(
      path.join('out', 'report.html'),
      render({ engagement, sarif, findings, hashes, changes }),
    );
    write(
      path.join('out', 'report.json'),
      JSON.stringify(
        { ...cur, triage: findings.triage ?? {}, inputs: hashes, changes },
        null,
        2,
      ) + '\n',
    );
    console.log(
      `${slug}: ${findings.findings.length} findings → ${path.join(dir, 'out', 'report.html')}`,
    );
  },

  retest() {
    const id =
      rest[0] ??
      fail(
        'usage: retest <slug> <F-id> --commit … --result pass|fail --by … --evidence …',
      );
    const engagement = json('engagement.json');
    const findings = json('findings.json');
    if (!findings.findings.some((f) => f.id === id))
      fail(`${slug}: no finding ${id}`);
    const attempt = {
      commit: o.commit,
      result: o.result,
      by: o.by,
      evidence: o.evidence,
      date: o.date ?? today,
    };
    try {
      findings.findings = findings.findings.map((f) =>
        f.id === id ? E.applyRetest(f, attempt, engagement.target.version) : f,
      );
    } catch (err) {
      fail(`${slug} ${id}: ${err.message}`);
    }
    write('findings.json', JSON.stringify(findings, null, 2) + '\n');
    console.log(
      `${slug} ${id}: retest ${o.result} against ${o.commit} recorded. Rebuild the report, then: engagement letter ${slug}`,
    );
  },

  letter() {
    const engagement = json('engagement.json');
    const findings = json('findings.json');
    if (!findings.findings.some((f) => f.retestHistory?.length))
      fail(`${slug}: nothing retested yet`);
    write(
      path.join('out', 'retest-letter.html'),
      retestLetter({ engagement, findings, date: o.date ?? today }),
    );
    console.log(`${slug}: ${path.join(dir, 'out', 'retest-letter.html')}`);
  },
};

if (Object.hasOwn(commands, cmd)) commands[cmd]();
else fail(`unknown command ${cmd}`);
