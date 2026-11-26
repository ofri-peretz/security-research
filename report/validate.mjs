// Refuses to build a report an auditor couldn't rely on. Each rule is in the spec:
// docs/specs/2026-11-26-findings-report.md, "Validation".
import fs from 'node:fs';
import path from 'node:path';
import { parseVector } from './cvss.mjs';
import { resultsOf } from './sarif.mjs';

const load = (f) =>
  JSON.parse(
    fs.readFileSync(path.join(import.meta.dirname, 'data', f), 'utf8'),
  );
export const CWE = load('cwe.json');
export const ASVS = load('asvs.json');

const VERDICTS = [
  'true-positive',
  'false-positive',
  'accepted-risk',
  'out-of-scope',
];
const STATUSES = ['open', 'fixed', 'retested'];
const nonEmpty = (v) => typeof v === 'string' && v.trim().length > 0;

export function validateEngagement(e, errors) {
  const need = {
    client: e?.client,
    'target.name': e?.target?.name,
    'target.version': e?.target?.version,
    boundary: e?.boundary,
    'tester.name': e?.tester?.name,
    'tester.independence': e?.tester?.independence,
    'period.start': e?.period?.start,
    'period.end': e?.period?.end,
    methodology: e?.methodology,
  };
  for (const [k, v] of Object.entries(need))
    if (!nonEmpty(v)) errors.push(`engagement: ${k} is required`);
  if (!Array.isArray(e?.standards) || e.standards.length === 0)
    errors.push(
      'engagement: standards (each with name and edition) are required',
    );
  for (const s of e?.standards ?? [])
    if (!nonEmpty(s.name) || !nonEmpty(s.edition))
      errors.push(
        `engagement: standard ${JSON.stringify(s)} needs name and edition`,
      );
  if (
    !Array.isArray(e?.tools) ||
    e.tools.some((t) => !nonEmpty(t.name) || !nonEmpty(t.version))
  )
    errors.push('engagement: tools must each have name and version');
}

export function validateCwe(id, where, errors) {
  const m = /^CWE-(\d+)$/.exec(id ?? '');
  if (!m)
    return errors.push(
      `${where}: cwe must look like "CWE-78", got ${JSON.stringify(id)}`,
    );
  const e = CWE.entries[m[1]];
  if (!e) return errors.push(`${where}: ${id} is not in CWE ${CWE.version}`);
  if (e.kind !== 'weakness')
    errors.push(
      `${where}: ${id} is a ${e.kind}, not a weakness; CWE prohibits mapping to it`,
    );
  else if (e.abstraction === 'Pillar')
    errors.push(
      `${where}: ${id} is a Pillar; map the root cause to a Base or Variant`,
    );
  else if (e.usage === 'Prohibited' || e.usage === 'Discouraged')
    errors.push(
      `${where}: CWE marks ${id} (${e.name}) as ${e.usage} for mapping; pick a more specific weakness`,
    );
}

export function validateFindings(f, sarif, errors) {
  const results = resultsOf(sarif);
  const keys = new Set(results.map((r) => r.key));
  const claimed = new Map();
  const ids = new Set();
  for (const x of f.findings ?? []) {
    const at = `finding ${x.id ?? '?'}`;
    if (!/^F-\d{2,}$/.test(x.id ?? ''))
      errors.push(`${at}: id must look like "F-01"`);
    if (ids.has(x.id)) errors.push(`${at}: duplicate id`);
    ids.add(x.id);
    for (const k of ['title', 'description', 'impact', 'remediation'])
      if (!nonEmpty(x[k])) errors.push(`${at}: ${k} is required`);
    validateCwe(x.cwe, at, errors);
    const v = parseVector(x.cvss?.vector);
    if (v.error) errors.push(`${at}: CVSS ${v.error}`);
    if (!nonEmpty(x.cvss?.rationale))
      errors.push(`${at}: CVSS vector needs a rationale`);
    for (const a of x.asvs ?? [])
      if (!ASVS.requirements[a])
        errors.push(`${at}: ${a} is not an ASVS ${ASVS.version} requirement`);
    for (const c of x.soc2 ?? [])
      if (!/^CC[1-9]\.\d{1,2}$/.test(c))
        errors.push(`${at}: SOC 2 criterion ${c} must look like "CC7.1"`);
    for (const o of x.owasp ?? [])
      if (!nonEmpty(o.list) || !nonEmpty(o.id))
        errors.push(`${at}: OWASP mapping needs list and id`);
    if (!STATUSES.includes(x.status))
      errors.push(`${at}: status must be one of ${STATUSES.join(', ')}`);
    if (
      (x.status === 'fixed' || x.status === 'retested') &&
      !nonEmpty(x.fix?.commit)
    )
      errors.push(`${at}: a ${x.status} finding needs fix.commit`);
    if (x.status === 'retested') {
      if (!nonEmpty(x.retest?.date) || x.retest?.result !== 'pass')
        errors.push(
          `${at}: a retested finding needs retest.date and retest.result "pass"`,
        );
      if (!nonEmpty(x.retest?.expect))
        errors.push(
          `${at}: a retested finding needs retest evidence (retest.expect)`,
        );
    }
    if (!Array.isArray(x.results) || x.results.length === 0)
      errors.push(`${at}: needs at least one SARIF result as evidence`);
    for (const k of x.results ?? []) {
      if (!keys.has(k)) errors.push(`${at}: result ${k} is not in the SARIF`);
      if (claimed.has(k))
        errors.push(
          `${at}: result ${k} is already claimed by ${claimed.get(k)}`,
        );
      claimed.set(k, x.id);
    }
  }
  for (const [k, t] of Object.entries(f.triage ?? {})) {
    if (!keys.has(k)) errors.push(`triage: ${k} is not in the SARIF`);
    if (claimed.has(k))
      errors.push(`triage: ${k} is also evidence for ${claimed.get(k)}`);
    if (!VERDICTS.includes(t.verdict) || t.verdict === 'true-positive')
      errors.push(
        `triage: ${k} verdict must be false-positive, accepted-risk or out-of-scope (true positives belong in a finding)`,
      );
    if (!nonEmpty(t.reason)) errors.push(`triage: ${k} needs a reason`);
    claimed.set(k, 'triage');
  }
  for (const k of keys)
    if (!claimed.has(k))
      errors.push(`untriaged result: ${k} (nothing ships untriaged)`);
}

/** Checks a retest's evidence against a log: the expected line must sit in the named section. */
export function validateRetestEvidence(f, logText, errors) {
  for (const x of f.findings ?? []) {
    if (x.status !== 'retested' || !x.retest?.section) continue;
    const start = logText.indexOf(`\n${x.retest.section}\n`);
    const end = start < 0 ? -1 : logText.indexOf('\n\n', start + 1);
    const section =
      start < 0 ? '' : logText.slice(start, end < 0 ? undefined : end);
    if (!section.includes(x.retest.expect))
      errors.push(
        `finding ${x.id}: retest log has no "${x.retest.expect}" under "${x.retest.section}"`,
      );
  }
}

export function validate({ engagement, sarif, findings, log }) {
  const errors = [];
  validateEngagement(engagement, errors);
  try {
    validateFindings(findings, sarif, errors);
  } catch (err) {
    errors.push(`sarif: ${err.message}`);
  }
  if (log !== undefined) validateRetestEvidence(findings, log, errors);
  return errors;
}
