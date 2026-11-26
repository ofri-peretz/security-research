// Refuses to build a report an auditor couldn't rely on. The rules are in the specs:
// docs/specs/2026-11-26-findings-report.md ("Validation") and docs/specs/2026-11-26-report-v2-saas.md.
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

const VERDICTS = ['false-positive', 'accepted-risk', 'out-of-scope'];
const STATUSES = ['open', 'fixed', 'retested', 'risk-accepted'];
const LEVELS = ['Low', 'Medium', 'High'];
const COVERAGE = ['pass', 'fail', 'n/a', 'out-of-scope', 'not-tested'];
const filled = (v) => typeof v === 'string' && v.trim().length > 0;
const DATE = /^\d{4}-\d{2}-\d{2}$/;

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
    issueDate: e?.issueDate,
    confidentiality: e?.confidentiality,
    rulesOfEngagement: e?.rulesOfEngagement,
    levelOfEffort: e?.levelOfEffort,
  };
  for (const [k, v] of Object.entries(need))
    if (!filled(v)) errors.push(`engagement: ${k} is required`);
  for (const k of ['period.start', 'period.end', 'issueDate']) {
    const v = k === 'issueDate' ? e?.issueDate : e?.period?.[k.split('.')[1]];
    if (filled(v) && !DATE.test(v))
      errors.push(`engagement: ${k} must be YYYY-MM-DD`);
  }
  if (!Array.isArray(e?.standards) || e.standards.length === 0)
    errors.push(
      'engagement: standards (each with name and edition) are required',
    );
  for (const s of e?.standards ?? [])
    if (!filled(s.name) || !filled(s.edition))
      errors.push(
        `engagement: standard ${JSON.stringify(s)} needs name and edition`,
      );
  if (
    !Array.isArray(e?.tools) ||
    e.tools.some((t) => !filled(t.name) || !filled(t.version))
  )
    errors.push('engagement: tools must each have name and version');
  if (!Array.isArray(e?.timeline) || e.timeline.length === 0)
    errors.push('engagement: timeline (dated milestones) is required');
  for (const t of e?.timeline ?? [])
    if (!DATE.test(t.date ?? '') || !filled(t.event))
      errors.push(
        `engagement: timeline entry ${JSON.stringify(t)} needs a YYYY-MM-DD date and an event`,
      );
  for (const k of ['strategicRecommendations', 'positiveObservations'])
    if (e?.[k] !== undefined && (!Array.isArray(e[k]) || !e[k].every(filled)))
      errors.push(`engagement: ${k} must be a list of sentences`);
  if (!Array.isArray(e?.coverage) || e.coverage.length === 0)
    errors.push(
      'engagement: coverage (every test performed, with its result) is required',
    );
}

/** Coverage entries need a known result. Nothing may stay "not-tested", and an ASVS reference must exist. */
export function validateCoverage(e, findingIds, errors) {
  for (const c of e?.coverage ?? []) {
    const at = `coverage ${c.id ?? '?'}`;
    if (!filled(c.id) || !filled(c.test) || !filled(c.ref))
      errors.push(`${at}: needs id, ref and test`);
    if (!COVERAGE.includes(c.result))
      errors.push(`${at}: result must be one of ${COVERAGE.join(', ')}`);
    if (c.result === 'not-tested')
      errors.push(
        `${at}: still not-tested; test it, or mark it out-of-scope with a reason`,
      );
    if (
      (c.result === 'out-of-scope' || c.result === 'n/a') &&
      !filled(c.reason)
    )
      errors.push(`${at}: ${c.result} needs a reason`);
    if (c.result === 'fail') {
      if (!Array.isArray(c.findings) || c.findings.length === 0)
        errors.push(`${at}: a failed test must name the findings it produced`);
      for (const id of c.findings ?? [])
        if (!findingIds.has(id))
          errors.push(`${at}: names unknown finding ${id}`);
    }
    for (const r of String(c.ref ?? '').split(/[,\s]+/))
      if (/^V\d+\.\d+\.\d+$/.test(r) && !ASVS.requirements[r])
        errors.push(`${at}: ${r} is not an ASVS ${ASVS.version} requirement`);
  }
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

function validateRemediationState(x, at, targetVersion, errors) {
  if (!STATUSES.includes(x.status))
    return errors.push(`${at}: status must be one of ${STATUSES.join(', ')}`);
  if (x.status === 'risk-accepted') {
    if (!filled(x.riskAcceptance?.by) || !filled(x.riskAcceptance?.reason))
      errors.push(`${at}: risk-accepted needs riskAcceptance.by and .reason`);
    return;
  }
  if (x.status === 'open') return;
  const fix = x.fix ?? {};
  if (fix.kind !== 'client' && fix.kind !== 'reference')
    errors.push(`${at}: fix.kind must be "client" or "reference"`);
  if (fix.kind === 'client') {
    if (!filled(fix.commit))
      errors.push(`${at}: a client fix needs fix.commit`);
    else if (fix.commit === targetVersion)
      errors.push(
        `${at}: fix.commit equals the tested version (${targetVersion}); a retest must be of a later commit`,
      );
  }
  if (fix.kind === 'reference' && !filled(fix.path))
    errors.push(`${at}: a reference fix needs fix.path`);
  if (x.status === 'retested') {
    const r = x.retest ?? {};
    if (!DATE.test(r.date ?? '') || r.result !== 'pass')
      errors.push(
        `${at}: a retest needs retest.date (YYYY-MM-DD) and retest.result "pass"`,
      );
    if (!filled(r.by)) errors.push(`${at}: a retest needs retest.by`);
    if (!filled(r.evidence) && !filled(r.expect))
      errors.push(
        `${at}: a retest needs evidence (retest.evidence or .expect)`,
      );
  }
}

export function validateFindings(f, sarif, errors, targetVersion) {
  const results = resultsOf(sarif);
  const keys = new Set(results.map((r) => r.key));
  const claimed = new Map();
  const ids = new Set((f.findings ?? []).map((x) => x.id));
  const seen = new Set();
  for (const x of f.findings ?? []) {
    const at = `finding ${x.id ?? '?'}`;
    if (!/^F-\d{2,}$/.test(x.id ?? ''))
      errors.push(`${at}: id must look like "F-01"`);
    if (seen.has(x.id)) errors.push(`${at}: duplicate id`);
    seen.add(x.id);
    for (const k of ['title', 'description', 'impact', 'exploitScenario'])
      if (!filled(x[k])) errors.push(`${at}: ${k} is required`);
    if (!filled(x.remediation?.shortTerm))
      errors.push(`${at}: remediation.shortTerm is required`);
    if (
      x.remediation?.targetDate !== undefined &&
      !DATE.test(x.remediation.targetDate)
    )
      errors.push(`${at}: remediation.targetDate must be YYYY-MM-DD`);
    if (!LEVELS.includes(x.difficulty?.level) || !filled(x.difficulty?.basis))
      errors.push(
        `${at}: difficulty needs a level (${LEVELS.join(', ')}) and a basis`,
      );
    for (const c of x.chainsWith ?? [])
      if (c === x.id || !ids.has(c))
        errors.push(
          `${at}: chainsWith names ${c}, which isn't another finding`,
        );
    const rep = x.reproducibility;
    if (
      rep !== undefined &&
      (!filled(rep.model) ||
        !filled(rep.version) ||
        !Number.isInteger(rep.trials) ||
        rep.trials < 1 ||
        !Number.isInteger(rep.successes) ||
        rep.successes < 0 ||
        rep.successes > rep.trials)
    )
      errors.push(
        `${at}: reproducibility needs model, version, trials >= 1 and 0 <= successes <= trials`,
      );
    validateCwe(x.cwe, at, errors);
    const v = parseVector(x.cvss?.vector);
    if (v.error) errors.push(`${at}: CVSS ${v.error}`);
    if (!filled(x.cvss?.rationale))
      errors.push(`${at}: CVSS vector needs a rationale`);
    for (const a of x.asvs ?? [])
      if (!ASVS.requirements[a])
        errors.push(`${at}: ${a} is not an ASVS ${ASVS.version} requirement`);
    for (const c of x.soc2 ?? [])
      if (!/^CC[1-9]\.\d{1,2}$/.test(c))
        errors.push(`${at}: SOC 2 criterion ${c} must look like "CC7.1"`);
    for (const o of x.owasp ?? [])
      if (!filled(o.list) || !filled(o.id))
        errors.push(`${at}: OWASP mapping needs list and id`);
    validateRemediationState(x, at, targetVersion, errors);
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
    if (!VERDICTS.includes(t.verdict))
      errors.push(
        `triage: ${k} verdict must be false-positive, accepted-risk or out-of-scope (true positives belong in a finding)`,
      );
    if (!filled(t.reason)) errors.push(`triage: ${k} needs a reason`);
    claimed.set(k, 'triage');
  }
  for (const k of keys)
    if (!claimed.has(k))
      errors.push(`untriaged result: ${k} (nothing ships untriaged)`);
  return ids;
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
  let ids = new Set();
  try {
    ids = validateFindings(
      findings,
      sarif,
      errors,
      engagement?.target?.version,
    );
  } catch (err) {
    errors.push(`sarif: ${err.message}`);
  }
  validateCoverage(engagement, ids, errors);
  if (log !== undefined) validateRetestEvidence(findings, log, errors);
  return errors;
}
