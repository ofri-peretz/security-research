import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as E from './lib/engagement.mjs';
import { resultKey } from '../report/sarif.mjs';

const CLI = path.join(import.meta.dirname, 'engagement.mjs');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'eng-'));

test('a client workspace is private and starts from the templates', () => {
  const h = tmp();
  try {
    const dir = E.createWorkspace({
      slug: 'acme',
      client: 'Acme Inc.',
      tester: 'Tester One',
      today: '2026-12-01',
      h,
    });
    assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
    assert.equal(
      fs.statSync(path.join(dir, 'engagement.json')).mode & 0o777,
      0o600,
    );
    const e = JSON.parse(
      fs.readFileSync(path.join(dir, 'engagement.json'), 'utf8'),
    );
    assert.equal(e.client, 'Acme Inc.');
    assert.equal(e.tester.name, 'Tester One');
    assert.equal(e.coverage.length, 14);
    assert.match(
      fs.readFileSync(path.join(dir, 'authorization.md'), 'utf8'),
      /\*\*Tester One\*\*.*\*\*Acme Inc\.\*\*/s,
    );
    assert.throws(
      () =>
        E.createWorkspace({
          slug: 'acme',
          client: 'x',
          tester: 'y',
          today: '2026-12-01',
          h,
        }),
      /already exists/,
    );
    assert.throws(() => E.clientDir('../etc', h), /slug/);
  } finally {
    fs.rmSync(h, { recursive: true, force: true });
  }
});

test('manual results become a SARIF run with stable keys', () => {
  const run = E.manualToSarifRun(
    [
      {
        id: 'M-01',
        title: 'Tenant B reads tenant A orders',
        location: 'https://api.example.com/v1/orders/{id}',
        detail: 'GET with tenant B token returns 200.',
      },
      {
        id: 'M-02',
        title: 'Hardcoded key',
        location: 'src/config.js:12',
        detail: 'Live key in source.',
      },
    ],
    'Tester One',
  );
  assert.equal(
    resultKey(run, run.results[0]),
    'manual-testing/M-01@https://api.example.com/v1/orders/{id}:1',
  );
  assert.equal(
    resultKey(run, run.results[1]),
    'manual-testing/M-02@src/config.js:12',
  );
  assert.throws(
    () =>
      E.manualToSarifRun(
        [{ id: 'X1', title: '', location: 'a', detail: 'b' }],
        't',
      ),
    /id must look like[\s\S]*title is required/,
  );
});

test('a retest must be of a new commit, and failures stay on the record', () => {
  const f = { id: 'F-01', status: 'open' };
  assert.throws(
    () =>
      E.applyRetest(
        f,
        { commit: 'v1', result: 'pass', by: 'a', evidence: 'b', date: 'd' },
        'v1',
      ),
    /originally tested/,
  );
  assert.throws(
    () =>
      E.applyRetest(
        f,
        { commit: 'v2', result: 'maybe', by: 'a', evidence: 'b', date: 'd' },
        'v1',
      ),
    /pass or fail/,
  );
  const failed = E.applyRetest(
    f,
    {
      commit: 'v2',
      result: 'fail',
      by: 'a',
      evidence: 'still 200',
      date: '2026-12-10',
    },
    'v1',
  );
  assert.equal(failed.status, 'open');
  const passed = E.applyRetest(
    failed,
    {
      commit: 'v3',
      result: 'pass',
      by: 'a',
      evidence: 'now 404',
      date: '2026-12-20',
    },
    'v1',
  );
  assert.equal(passed.status, 'retested');
  assert.deepEqual(passed.fix, { kind: 'client', commit: 'v3' });
  assert.deepEqual(
    passed.retestHistory.map((r) => r.result),
    ['fail', 'pass'],
  );
  assert.equal(f.retestHistory, undefined, 'input is not mutated');
});

test('consecutive reports diff into new, resolved and still open', () => {
  const prev = {
    engagement: { issueDate: '2026-06-01', target: { version: 'v1' } },
    findings: [
      { id: 'F-01', status: 'open' },
      { id: 'F-02', status: 'open' },
      { id: 'F-03', status: 'retested' },
    ],
  };
  const cur = {
    findings: [
      { id: 'F-01', status: 'open' },
      { id: 'F-02', status: 'retested' },
      { id: 'F-04', status: 'open' },
    ],
  };
  assert.deepEqual(E.diffReports(prev, cur), {
    previous: { issueDate: '2026-06-01', version: 'v1' },
    new: ['F-04'],
    resolved: ['F-02'],
    persisting: ['F-01'],
  });
});

test('end to end: new → refused until complete → build → retest → letter → Type II diff', () => {
  const h = tmp();
  const cli = (...args) =>
    spawnSync(process.execPath, [CLI, ...args], {
      encoding: 'utf8',
      env: { ...process.env, SR_HOME: h },
    });
  try {
    assert.equal(
      cli('new', 'acme', 'Acme Inc.', '--tester', 'Tester One').status,
      0,
    );
    const dir = path.join(h, 'clients', 'acme');
    const refused = cli('build', 'acme');
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /still not-tested/);

    const e = JSON.parse(
      fs.readFileSync(path.join(dir, 'engagement.json'), 'utf8'),
    );
    Object.assign(e, {
      target: { name: 'Acme app', version: 'v1.0.0' },
      boundary: 'app.acme.test and api.acme.test, tenants A and B',
      period: { start: '2026-12-01', end: '2026-12-05' },
      methodology: 'Grey box, WSTG v4.2',
      rulesOfEngagement: 'Signed 2026-11-30; staging only',
      levelOfEffort: 'One tester, five days',
      summary: 'One high finding in tenant isolation.',
      tools: [{ name: 'Burp Suite', version: '2026.11' }],
      timeline: [{ date: '2026-12-01', event: 'Testing started' }],
    });
    e.tester.independence = 'Independent of the client and its code';
    e.coverage = e.coverage.map((c) =>
      c.id === 'D-04'
        ? { ...c, result: 'fail', findings: ['F-01'] }
        : { ...c, result: 'out-of-scope', reason: 'not in this engagement' },
    );
    fs.writeFileSync(path.join(dir, 'engagement.json'), JSON.stringify(e));
    fs.writeFileSync(
      path.join(dir, 'manual.json'),
      JSON.stringify([
        {
          id: 'M-01',
          title: 'Tenant B reads tenant A orders',
          location: 'https://api.acme.test/v1/orders/{id}',
          detail: 'GET as tenant B returns tenant A order.',
        },
      ]),
    );
    const finding = {
      id: 'F-01',
      title: 'Cross-tenant order read',
      cwe: 'CWE-639',
      cvss: {
        vector:
          'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N',
        rationale: 'Any tenant user reads any order.',
      },
      difficulty: { level: 'Low', basis: 'Change one ID.' },
      description: 'Order lookup ignores tenant.',
      exploitScenario: 'Tenant B user iterates order IDs.',
      impact: 'All tenants’ orders are readable.',
      remediation: { shortTerm: 'Scope the query by tenant.' },
      status: 'open',
      results: ['manual-testing/M-01@https://api.acme.test/v1/orders/{id}:1'],
    };
    fs.writeFileSync(
      path.join(dir, 'findings.json'),
      JSON.stringify({ findings: [finding], triage: {} }),
    );
    const built = cli('build', 'acme');
    assert.equal(built.status, 0, built.stderr);
    const html = fs.readFileSync(path.join(dir, 'out', 'report.html'), 'utf8');
    assert.match(html, /Cross-tenant order read/);
    fs.copyFileSync(
      path.join(dir, 'out', 'report.json'),
      path.join(h, 'previous.json'),
    );

    assert.equal(
      cli(
        'retest',
        'acme',
        'F-01',
        '--commit',
        'v1.0.0',
        '--result',
        'pass',
        '--by',
        'T',
        '--evidence',
        'x',
      ).status,
      1,
    );
    assert.equal(
      cli('letter', 'acme').status,
      1,
      'no letter before any retest',
    );
    assert.equal(
      cli(
        'retest',
        'acme',
        'F-01',
        '--commit',
        'v1.0.1',
        '--result',
        'pass',
        '--by',
        'Tester One',
        '--evidence',
        'GET as tenant B now returns 404',
        '--date',
        '2026-12-12',
      ).status,
      0,
    );
    const rebuilt = cli(
      'build',
      'acme',
      '--previous',
      path.join(h, 'previous.json'),
    );
    assert.equal(rebuilt.status, 0, rebuilt.stderr);
    const html2 = fs.readFileSync(path.join(dir, 'out', 'report.html'), 'utf8');
    assert.match(html2, /Fixed and retested/);
    assert.match(
      html2,
      /Changes since the previous assessment[\s\S]*Resolved<\/th><td>F-01/,
    );
    assert.equal(cli('letter', 'acme', '--date', '2026-12-13').status, 0);
    const letter = fs.readFileSync(
      path.join(dir, 'out', 'retest-letter.html'),
      'utf8',
    );
    assert.match(
      letter,
      /F-01\. Cross-tenant order read[\s\S]*v1\.0\.1[\s\S]*Resolved/,
    );
    assert.match(letter, /not a SOC 2 report/);
  } finally {
    fs.rmSync(h, { recursive: true, force: true });
  }
});
