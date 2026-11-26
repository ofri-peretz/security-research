import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { score, parseVector } from './cvss.mjs';
import { validate, validateCoverage, CWE } from './validate.mjs';
import { render, statusLabel } from './render.mjs';
import { plainMessage } from './sarif.mjs';

const here = import.meta.dirname;
const dog = (f) => fs.readFileSync(path.join(here, 'dogfood', f), 'utf8');
const base = () => ({
  engagement: JSON.parse(dog('engagement.json')),
  sarif: JSON.parse(dog('results.sarif')),
  findings: JSON.parse(dog('findings.json')),
  log: dog('verify.log'),
});
const refuses = (mutate, pattern) => {
  const input = base();
  mutate(input);
  const errors = validate(input);
  assert.ok(
    errors.some((e) => pattern.test(e)),
    `expected an error matching ${pattern}, got:\n${errors.join('\n')}`,
  );
};

test('CVSS v4.0 scores match the Red Hat implementation on 500 vectors', () => {
  const oracle = JSON.parse(
    fs.readFileSync(path.join(here, 'test', 'cvss-oracle.json'), 'utf8'),
  );
  const wrong = oracle.filter(([v, s]) => score(v).score !== s);
  assert.deepEqual(wrong, []);
});

test('CVSS vectors that are malformed are refused', () => {
  assert.match(parseVector('CVSS:3.1/AV:N').error, /CVSS:4.0/);
  assert.match(parseVector('CVSS:4.0/AV:N/AC:L').error, /missing base/);
  assert.match(
    parseVector(
      'CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    ).error,
    /order/,
  );
  assert.match(
    parseVector(
      'CVSS:4.0/AV:Q/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    ).error,
    /not a valid value/,
  );
});

test('the dogfood inputs validate clean', () => {
  assert.deepEqual(validate(base()), []);
});

test('the dogfood report re-renders byte for byte (golden)', () => {
  const input = base();
  const hashes = Object.fromEntries(
    ['results.sarif', 'engagement.json', 'findings.json', 'verify.log'].map(
      (f) => [f, crypto.createHash('sha256').update(dog(f)).digest('hex')],
    ),
  );
  assert.equal(
    render({ ...input, hashes }),
    dog('out/report.html'),
    'run `node report/dogfood/build.mjs` and review the diff',
  );
});

const F = (input, id) => input.findings.findings.find((f) => f.id === id);
const view = Object.entries(CWE.entries).find(([, e]) => e.kind === 'view')[0];

test('CWE mapping guidance is enforced', () => {
  refuses((i) => (F(i, 'F-01').cwe = 'CWE-284'), /Pillar/);
  refuses((i) => (F(i, 'F-01').cwe = 'CWE-200'), /Discouraged/);
  refuses((i) => (F(i, 'F-01').cwe = `CWE-${view}`), /view, not a weakness/);
  refuses((i) => (F(i, 'F-01').cwe = 'CWE-99999'), /not in CWE/);
  refuses((i) => (F(i, 'F-01').cwe = '78'), /must look like/);
});

test('severity needs a valid vector and a rationale', () => {
  refuses(
    (i) => (F(i, 'F-01').cvss.vector = 'CVSS:4.0/AV:N'),
    /CVSS missing base/,
  );
  refuses((i) => (F(i, 'F-01').cvss.rationale = ' '), /needs a rationale/);
});

test('remediation claims need evidence', () => {
  refuses((i) => (F(i, 'F-01').fix.kind = 'magic'), /fix.kind must be/);
  refuses((i) => delete F(i, 'F-01').fix.path, /reference fix needs fix.path/);
  refuses((i) => delete F(i, 'F-01').retest.by, /retest needs retest.by/);
  refuses(
    (i) => (F(i, 'F-01').retest.date = 'today'),
    /retest.date \(YYYY-MM-DD\)/,
  );
  refuses(
    (i) => (F(i, 'F-01').retest.expect = 'fixed: exploit is ignored'),
    /retest log has no/,
  );
  refuses(
    (i) => (i.log = i.log.replace('ai-1 Tool Time', 'ai-1 Renamed')),
    /retest log has no/,
  );
});

test('a client retest must be of a later commit than the one tested', () => {
  refuses(
    (i) =>
      (F(i, 'F-01').fix = {
        kind: 'client',
        commit: i.engagement.target.version,
      }),
    /equals the tested version/,
  );
  refuses(
    (i) => (F(i, 'F-01').fix = { kind: 'client' }),
    /client fix needs fix.commit/,
  );
  const input = base();
  F(input, 'F-01').fix = { kind: 'client', commit: 'abc1234' };
  assert.deepEqual(validate(input), []);
});

test('reference fixes are never labeled as client retests', () => {
  const input = base();
  assert.equal(statusLabel(F(input, 'F-01')), 'Reference fix verified');
  assert.equal(
    statusLabel({
      ...F(input, 'F-01'),
      fix: { kind: 'client', commit: 'abc' },
    }),
    'Fixed and retested',
  );
  assert.equal(statusLabel({ status: 'risk-accepted' }), 'Risk accepted');
  assert.ok(!render(input).includes('Fixed and retested'));
});

test('risk acceptance needs who accepted it and why', () => {
  refuses((i) => (F(i, 'F-10').status = 'risk-accepted'), /riskAcceptance.by/);
});

test('every finding has difficulty, an exploit scenario and a short-term fix', () => {
  refuses(
    (i) => (F(i, 'F-01').difficulty = { level: 'Trivial', basis: 'x' }),
    /difficulty needs a level/,
  );
  refuses(
    (i) => (F(i, 'F-01').difficulty.basis = ''),
    /difficulty needs a level/,
  );
  refuses(
    (i) => delete F(i, 'F-01').exploitScenario,
    /exploitScenario is required/,
  );
  refuses(
    (i) => (F(i, 'F-01').remediation = 'just fix it'),
    /remediation.shortTerm is required/,
  );
  refuses(
    (i) => (F(i, 'F-01').remediation.targetDate = 'soon'),
    /targetDate must be YYYY-MM-DD/,
  );
});

test('chains and reproducibility must be consistent', () => {
  refuses((i) => (F(i, 'F-01').chainsWith = ['F-99']), /chainsWith names F-99/);
  refuses((i) => (F(i, 'F-01').chainsWith = ['F-01']), /chainsWith names F-01/);
  refuses(
    (i) =>
      (F(i, 'F-02').reproducibility = {
        model: 'm',
        version: '1',
        trials: 5,
        successes: 6,
      }),
    /reproducibility needs/,
  );
  const input = base();
  F(input, 'F-02').reproducibility = {
    model: 'toy',
    version: '1',
    trials: 10,
    successes: 9,
  };
  F(input, 'F-01').chainsWith = ['F-06'];
  assert.deepEqual(validate(input), []);
  assert.match(render(input), /9 of 10 attempts/);
});

test('coverage records every test, and nothing stays not-tested', () => {
  refuses(
    (i) => (i.engagement.coverage[10].result = 'not-tested'),
    /still not-tested/,
  );
  refuses(
    (i) => delete i.engagement.coverage[12].reason,
    /n\/a needs a reason/,
  );
  refuses(
    (i) => (i.engagement.coverage[0].findings = []),
    /failed test must name/,
  );
  refuses(
    (i) => (i.engagement.coverage[0].findings = ['F-77']),
    /unknown finding F-77/,
  );
  refuses((i) => (i.engagement.coverage[0].ref = 'V99.1.1'), /not an ASVS/);
  refuses((i) => (i.engagement.coverage = []), /coverage .* is required/);
});

test('the SaaS template refuses to build until every domain is tested or scoped out', () => {
  const t = JSON.parse(
    fs.readFileSync(
      path.join(here, 'templates', 'saas-engagement.json'),
      'utf8',
    ),
  );
  assert.equal(t.coverage.length, 14);
  const errors = [];
  validateCoverage(t, new Set(), errors);
  assert.equal(errors.filter((e) => /still not-tested/.test(e)).length, 14);
});

test('the engagement needs document control and a dated timeline', () => {
  refuses(
    (i) => delete i.engagement.confidentiality,
    /confidentiality is required/,
  );
  refuses(
    (i) => (i.engagement.issueDate = '26/11/2026'),
    /issueDate must be YYYY-MM-DD/,
  );
  refuses((i) => (i.engagement.timeline = []), /timeline/);
  refuses(
    (i) => (i.engagement.timeline[0].date = 'Tuesday'),
    /needs a YYYY-MM-DD date/,
  );
  refuses(
    (i) => (i.engagement.positiveObservations = [3]),
    /positiveObservations must be a list/,
  );
});

test('nothing ships untriaged, and nothing is claimed twice or invented', () => {
  refuses(
    (i) => (F(i, 'F-10').results = ['eslint/x@nowhere.mjs:1']),
    /not in the SARIF/,
  );
  refuses((i) => (F(i, 'F-10').results = []), /at least one SARIF result/);
  refuses(
    (i) => delete i.findings.triage[Object.keys(i.findings.triage)[0]],
    /untriaged result/,
  );
  refuses(
    (i) => (F(i, 'F-10').results = [...F(i, 'F-01').results]),
    /already claimed/,
  );
  refuses(
    (i) => (Object.values(i.findings.triage)[0].verdict = 'true-positive'),
    /true positives belong in a finding/,
  );
  refuses(
    (i) => (Object.values(i.findings.triage)[0].reason = ''),
    /needs a reason/,
  );
});

test('mappings must exist in the standards they cite', () => {
  refuses((i) => (F(i, 'F-01').asvs = ['V99.9.9']), /not an ASVS/);
  refuses((i) => (F(i, 'F-01').soc2 = ['CC7']), /must look like "CC7.1"/);
});

test('the engagement must say who tested what, when, and against which editions', () => {
  refuses(
    (i) => delete i.engagement.tester.independence,
    /tester.independence is required/,
  );
  refuses(
    (i) => delete i.engagement.target.version,
    /target.version is required/,
  );
  refuses((i) => (i.engagement.standards = []), /standards/);
  refuses(
    (i) => (i.engagement.tools = [{ name: 'eslint' }]),
    /tools must each have name and version/,
  );
});

test('plugin tag prefixes are stripped from tool messages, other messages kept', () => {
  assert.equal(
    plainMessage(
      '🔒 CWE-208 OWASP:A02 CVSS:5.9 | Secret comparison leaks timing | HIGH',
    ),
    'Secret comparison leaks timing',
  );
  assert.equal(
    plainMessage('Unexpected eval | with pipes | inside'),
    'Unexpected eval | with pipes | inside',
  );
});

test('the report escapes everything it is given', () => {
  const input = base();
  F(input, 'F-01').title = '<script>alert(1)</script>';
  assert.ok(!render(input).includes('<script>alert(1)</script>'));
});
