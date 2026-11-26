import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { score, parseVector } from './cvss.mjs';
import { validate, CWE } from './validate.mjs';
import { render } from './render.mjs';
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
  refuses((i) => delete F(i, 'F-01').fix, /needs fix.commit/);
  refuses((i) => delete F(i, 'F-01').retest, /retest.date/);
  refuses(
    (i) => (F(i, 'F-01').retest.expect = 'fixed: exploit is ignored'),
    /retest log has no/,
  );
  refuses(
    (i) => (i.log = i.log.replace('ai-1 Tool Time', 'ai-1 Renamed')),
    /retest log has no/,
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
