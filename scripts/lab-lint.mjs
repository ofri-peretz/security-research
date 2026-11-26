#!/usr/bin/env node
// Dogfood: lint each protocol-ctf lab with our own ESLint security plugins and compare the
// result with scripts/lab-expectations.json. The vulnerable server must fire its root-cause
// rule (recall). The fixed server must show exactly the listed hits (precision). Drift in
// either direction fails, so a plugin regression and a plugin fix both show up here.
import { ESLint } from 'eslint';
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const lab = path.join(root, 'protocol-ctf');
const { labs } = JSON.parse(
  fs.readFileSync(
    path.join(import.meta.dirname, 'lab-expectations.json'),
    'utf8',
  ),
);

const files = {};
for (const track of fs.readdirSync(path.join(lab, 'challenges'))) {
  for (const id of fs.readdirSync(path.join(lab, 'challenges', track))) {
    files[id] = {
      vulnerable: path.join(lab, 'challenges', track, id, 'server.mjs'),
      fixed: path.join(lab, 'solutions', id, 'fixed-server.mjs'),
    };
  }
}

const problems = [];
const missing = Object.keys(files).filter((id) => !labs[id]);
const stale = Object.keys(labs).filter((id) => !files[id]);
for (const id of missing)
  problems.push(`${id}: lab has no entry in lab-expectations.json`);
for (const id of stale)
  problems.push(`${id}: listed in lab-expectations.json but the lab is gone`);

// Lint the labs with the repo's plugins, ignoring the repo config's lab exclusion.
const eslint = new ESLint({
  cwd: root,
  ignore: false,
  overrideConfigFile: path.join(root, 'eslint.config.mjs'),
});
const all = Object.values(files).flatMap((f) => [f.vulnerable, f.fixed]);
const results = await eslint.lintFiles(all);
const rulesIn = (file) => {
  const r = results.find((x) => x.filePath === file);
  const fatal = r.messages.filter((m) => !m.ruleId);
  if (fatal.length)
    problems.push(
      `${path.relative(root, file)}: parse error: ${fatal[0].message}`,
    );
  return new Set(r.messages.map((m) => m.ruleId).filter(Boolean));
};

let caught = 0;
let applicable = 0;
for (const [id, f] of Object.entries(files)) {
  const want = labs[id];
  if (!want) continue;
  const vuln = rulesIn(f.vulnerable);
  const fixed = rulesIn(f.fixed);
  if (want.rootCauseRule) {
    applicable++;
    if (vuln.has(want.rootCauseRule)) caught++;
    else
      problems.push(
        `${id}: RECALL REGRESSION, ${want.rootCauseRule} no longer fires on the vulnerable server`,
      );
  } else if (!want.gap.startsWith('toy model')) {
    applicable++;
  }
  const allowed = new Set(Object.keys(want.fixedHits));
  for (const rule of fixed) {
    if (!allowed.has(rule))
      problems.push(
        `${id}: NEW HIT on the fixed server: ${rule} (false positive, or the fix is incomplete)`,
      );
  }
  for (const rule of allowed) {
    if (!fixed.has(rule))
      problems.push(
        `${id}: ${rule} no longer fires on the fixed server. If a plugin fix shipped, remove it from fixedHits`,
      );
  }
}

console.log(
  `lab-lint: root causes caught ${caught}/${applicable} applicable labs`,
);
if (problems.length) {
  for (const p of problems) console.error(`  ✖ ${p}`);
  process.exit(1);
}
console.log('lab-lint: every lab matches lab-expectations.json');
