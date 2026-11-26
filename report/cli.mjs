#!/usr/bin/env node
// node report/cli.mjs --sarif results.sarif --engagement engagement.json --findings findings.json
//                     [--log retest.log] --out report.html
// Writes report.html and report.json next to each other. Exits 1, writing nothing, if validation fails.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { validate } from './validate.mjs';
import { render, enrich } from './render.mjs';

const { values: a } = parseArgs({
  options: {
    sarif: { type: 'string' },
    engagement: { type: 'string' },
    findings: { type: 'string' },
    log: { type: 'string' },
    out: { type: 'string' },
  },
});
for (const k of ['sarif', 'engagement', 'findings', 'out']) {
  if (!a[k]) {
    console.error(`missing --${k}`);
    process.exit(2);
  }
}

const read = (f) => fs.readFileSync(f, 'utf8');
const files = {
  sarif: a.sarif,
  engagement: a.engagement,
  findings: a.findings,
  ...(a.log ? { log: a.log } : {}),
};
const text = Object.fromEntries(
  Object.entries(files).map(([k, f]) => [k, read(f)]),
);
const input = {
  sarif: JSON.parse(text.sarif),
  engagement: JSON.parse(text.engagement),
  findings: JSON.parse(text.findings),
  log: text.log,
};

const errors = validate(input);
if (errors.length) {
  console.error(`report: refused to build, ${errors.length} problem(s):`);
  for (const e of errors) console.error(`  ✖ ${e}`);
  process.exit(1);
}

const hashes = Object.fromEntries(
  Object.entries(files).map(([k, f]) => [
    path.basename(f),
    crypto.createHash('sha256').update(text[k]).digest('hex'),
  ]),
);
const html = render({ ...input, hashes });
fs.writeFileSync(a.out, html);
const json = {
  engagement: input.engagement,
  findings: enrich(input.findings.findings),
  triage: input.findings.triage ?? {},
  inputs: hashes,
};
fs.writeFileSync(
  a.out.replace(/\.html$/, '') + '.json',
  JSON.stringify(json, null, 2) + '\n',
);
console.log('report: %d findings → %s', input.findings.findings.length, a.out);
