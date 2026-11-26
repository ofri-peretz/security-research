// CVSS v4.0: parse and validate a vector, and score it with FIRST's reference implementation.
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const dir = path.join(import.meta.dirname, 'vendor', 'cvss-v4');
const ctx = vm.createContext({});
for (const f of [
  'metrics.js',
  'cvss_lookup.js',
  'max_composed.js',
  'max_severity.js',
  'cvss_score.js',
]) {
  // eslint-disable-next-line node-security/detect-eval-with-expression -- accepted risk: runs FIRST's vendored scorer, pinned and byte-identical to upstream (vendor/cvss-v4/README.md)
  vm.runInContext(fs.readFileSync(path.join(dir, f), 'utf8'), ctx, {
    filename: f,
  });
}
const ORDER = vm.runInContext('expectedMetricOrder', ctx);
const BASE = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'];

/** Returns { selected } for a valid vector, or { error } saying what is wrong. */
export function parseVector(vector) {
  if (typeof vector !== 'string' || !vector.startsWith('CVSS:4.0/'))
    return { error: 'must start with "CVSS:4.0/"' };
  const selected = Object.fromEntries(
    Object.entries(ORDER).map(([k, v]) => [k, v[0]]),
  );
  const keys = Object.keys(ORDER);
  let last = -1;
  for (const part of vector.slice('CVSS:4.0/'.length).split('/')) {
    const [k, v, extra] = part.split(':');
    const i = keys.indexOf(k);
    if (i < 0 || extra !== undefined)
      return { error: `unknown metric "${part}"` };
    if (i <= last) return { error: `metric ${k} is out of order or repeated` };
    if (!ORDER[k].includes(v))
      return {
        error: `${k}:${v} is not a valid value (${ORDER[k].join(', ')})`,
      };
    // eslint-disable-next-line secure-coding/detect-object-injection -- k passed keys.indexOf(k) >= 0 above (plugin FP: indexOf allowlist guard not seen)
    selected[k] = v;
    last = i;
  }
  const missing = BASE.filter((k) => !vector.includes(`/${k}:`));
  if (missing.length)
    return { error: `missing base metric(s): ${missing.join(', ')}` };
  return { selected };
}

export function severity(score) {
  if (score === 0) return 'None';
  if (score < 4) return 'Low';
  if (score < 7) return 'Medium';
  if (score < 9) return 'High';
  return 'Critical';
}

/** Scores a vector. Throws on an invalid one. */
export function score(vector) {
  const { selected, error } = parseVector(vector);
  if (error) throw new Error(`CVSS vector ${vector}: ${error}`);
  ctx.__sel = selected;
  const s = vm.runInContext(
    'cvss_score(__sel, cvssLookup_global, maxSeverity, macroVector(__sel))',
    ctx,
  );
  return { score: s, severity: severity(s) };
}
