import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as F from './lib/findings.mjs';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sr-'));
const complete = (over = {}) => ({
  ...F.newFinding({
    id: 'SR-2026-001',
    repo: 'acme/widget',
    pkg: 'acme-widget',
    title: 'Command injection in widget',
    today: '2026-01-01',
  }),
  authorization:
    'Open-source package, tested locally on a copy; reported through GitHub private vulnerability reporting.',
  cwe: 'CWE-78',
  cvss: {
    vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    rationale: 'Unauthenticated, one request.',
  },
  summary: 'A tool argument reaches a shell.',
  details: 'exec() with an interpolated argument.',
  impact: 'Remote code execution.',
  remediation: 'Use execFile with an argument array.',
  ...over,
});

test('ids count up per year in the private workspace', () => {
  const h = tmp();
  try {
    assert.equal(F.nextId('2026', h), 'SR-2026-001');
    F.saveFinding(complete(), h);
    assert.equal(F.nextId('2026', h), 'SR-2026-002');
    assert.equal(F.nextId('2027', h), 'SR-2027-001');
  } finally {
    fs.rmSync(h, { recursive: true, force: true });
  }
});

test('the private workspace is owner-only', () => {
  const h = tmp();
  try {
    F.saveFinding(complete(), h);
    const mode =
      fs.statSync(path.join(h, 'findings', 'SR-2026-001', 'finding.json'))
        .mode & 0o777;
    assert.equal(mode, 0o600);
  } finally {
    fs.rmSync(h, { recursive: true, force: true });
  }
});

test('opening a finding adds its targets to the guard list once', () => {
  const repo = tmp();
  try {
    fs.writeFileSync(path.join(repo, '.open-findings'), 'existing-target\n');
    assert.deepEqual(F.addOpenTargets(complete(), repo), [
      'acme/widget',
      'acme-widget',
    ]);
    assert.deepEqual(F.addOpenTargets(complete(), repo), []);
    const text = fs.readFileSync(path.join(repo, '.open-findings'), 'utf8');
    assert.match(
      text,
      /existing-target\n# SR-2026-001\nacme\/widget\nacme-widget\n/,
    );
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('publishing removes targets, but keeps any another open finding still names', () => {
  const repo = tmp();
  try {
    const a = complete();
    const b = complete({
      id: 'SR-2026-002',
      target: { repo: 'acme/other', ecosystem: 'npm', package: 'acme-widget' },
    });
    F.addOpenTargets(a, repo);
    F.addOpenTargets(b, repo);
    F.removeOpenTargets(a, [a, b], repo);
    const text = fs.readFileSync(path.join(repo, '.open-findings'), 'utf8');
    assert.ok(!text.includes('acme/widget'));
    assert.ok(text.includes('acme-widget'), 'still named by SR-2026-002');
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('a report needs a complete finding with valid CWE and CVSS', () => {
  assert.deepEqual(F.validateFinding(complete()), []);
  assert.ok(
    F.validateFinding(complete({ cwe: 'CWE-284' })).some((e) =>
      /Pillar/.test(e),
    ),
  );
  assert.ok(
    F.validateFinding(
      complete({ cvss: { vector: 'CVSS:3.1/AV:N', rationale: 'x' } }),
    ).some((e) => /CVSS/.test(e)),
  );
  assert.ok(
    F.validateFinding(complete({ authorization: '' })).some((e) =>
      /authorization/.test(e),
    ),
  );
});

test('the private report carries severity, CWE, range and the disclosure policy', () => {
  const r = F.privateReport(
    complete({ affected: { introduced: '0', fixed: '1.2.3' } }),
  );
  assert.equal(r.severity, 'critical');
  assert.deepEqual(r.cwe_ids, ['CWE-78']);
  assert.deepEqual(r.vulnerabilities[0], {
    package: { ecosystem: 'npm', name: 'acme-widget' },
    vulnerable_version_range: '< 1.2.3',
    patched_versions: '1.2.3',
  });
  assert.match(r.description, /90-day coordinated disclosure/);
  assert.match(r.description, /CVSS v4\.0 9\.3/);
});

test('the disclosure deadline is 90 days after the report', () => {
  assert.equal(F.deadline('2026-01-01'), '2026-04-01');
  assert.equal(F.daysBetween('2026-01-01', '2026-01-31'), 30);
});

test('publishing needs the fix on npm and the GHSA published', () => {
  const reported = complete({
    status: 'reported',
    ghsa: 'GHSA-aaaa-bbbb-cccc',
    affected: { introduced: '0', fixed: '1.2.3' },
    timeline: { opened: '2026-01-01', reported: '2026-01-02' },
  });
  const ok = { fixedOnNpm: true, ghsaPublished: true, today: '2026-02-01' };
  assert.deepEqual(F.publishBlockers(reported, ok), []);
  assert.ok(
    F.publishBlockers(reported, { ...ok, fixedOnNpm: false }).some((b) =>
      /not on npm/.test(b),
    ),
  );
  assert.ok(
    F.publishBlockers(reported, { ...ok, ghsaPublished: false }).some((b) =>
      /not published by the maintainer/.test(b),
    ),
  );
  assert.ok(
    F.publishBlockers(
      { ...reported, timeline: { opened: '2026-01-01', reported: null } },
      ok,
    ).some((b) => /never reported/.test(b)),
  );
  assert.ok(
    F.publishBlockers({ ...reported, status: 'published' }, ok).some((b) =>
      /already published/.test(b),
    ),
  );
});

test('a deadline release is refused before the deadline and allowed after it', () => {
  const unfixed = complete({
    status: 'reported',
    timeline: { opened: '2026-01-01', reported: '2026-01-02' },
  });
  const early = F.publishBlockers(unfixed, {
    fixedOnNpm: false,
    ghsaPublished: false,
    today: '2026-03-01',
    deadlineRelease: true,
  });
  assert.ok(early.some((b) => /deadline is 2026-04-02/.test(b)));
  assert.deepEqual(
    F.publishBlockers(unfixed, {
      fixedOnNpm: false,
      ghsaPublished: false,
      today: '2026-04-02',
      deadlineRelease: true,
    }),
    [],
  );
});

test('OSV output uses the GHSA as id and keeps ours as an alias', () => {
  const f = complete({
    ghsa: 'GHSA-aaaa-bbbb-cccc',
    cve: 'CVE-2026-0001',
    affected: { introduced: '0', fixed: '1.2.3' },
  });
  const o = F.toOsv(f, '2026-02-01');
  assert.equal(o.id, 'GHSA-aaaa-bbbb-cccc');
  assert.deepEqual(o.aliases, ['CVE-2026-0001', 'SR-2026-001']);
  assert.deepEqual(o.affected[0].ranges[0].events, [
    { introduced: '0' },
    { fixed: '1.2.3' },
  ]);
  assert.deepEqual(o.severity, [{ type: 'CVSS_V4', score: f.cvss.vector }]);
  assert.deepEqual(o.database_specific.cwe_ids, ['CWE-78']);
});

test('the advisory write-up states severity, weakness and timeline', () => {
  const f = complete({
    ghsa: 'GHSA-aaaa-bbbb-cccc',
    affected: { introduced: '0', fixed: '1.2.3' },
    timeline: {
      opened: '2026-01-01',
      reported: '2026-01-02',
      fixed: '2026-01-20',
    },
  });
  const md = F.advisoryMarkdown(f, '2026-02-01');
  assert.match(md, /Critical 9\.3/);
  assert.match(
    md,
    /CWE-78\]\(https:\/\/cwe\.mitre\.org\/data\/definitions\/78\.html\) Improper Neutralization/,
  );
  assert.match(
    md,
    /2026-01-02: reported privately[\s\S]*2026-01-20: fix released[\s\S]*2026-02-01: published here/,
  );
});
