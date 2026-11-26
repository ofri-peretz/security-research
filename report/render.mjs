// Renders a validated engagement into one self-contained HTML report: no network, no JS, and
// print CSS, so the PDF path is the browser's "Print → Save as PDF".
import { score } from './cvss.mjs';
import { CWE, ASVS } from './validate.mjs';
import { resultsOf } from './sarif.mjs';

const esc = (s) =>
  String(s ?? '').replace(
    /[&<>"']/g,
    (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[
        c
      ],
  );
const SEV = ['Critical', 'High', 'Medium', 'Low'];
const DIFFICULTY = ['Low', 'Medium', 'High'];

/** Status in words a client and an auditor read the same way. A reference fix is never "fixed". */
export function statusLabel(f) {
  if (f.status === 'open') return 'Open';
  if (f.status === 'risk-accepted') return 'Risk accepted';
  const ref = f.fix?.kind === 'reference';
  if (f.status === 'fixed')
    return ref ? 'Reference fix provided' : 'Fixed, not yet retested';
  return ref ? 'Reference fix verified' : 'Fixed and retested';
}

/** Findings with their computed score, most severe first; easier to exploit first among equals. */
export function enrich(findings) {
  return findings
    .map((f) => ({ ...f, ...score(f.cvss.vector) }))
    .sort(
      (a, b) =>
        b.score - a.score ||
        DIFFICULTY.indexOf(a.difficulty.level) -
          DIFFICULTY.indexOf(b.difficulty.level) ||
        a.id.localeCompare(b.id),
    );
}

const badge = (sev) =>
  `<span class="sev sev-${sev.toLowerCase()}">${sev}</span>`;
const cweLink = (id) => {
  const n = id.slice(4);
  return `<a href="https://cwe.mitre.org/data/definitions/${n}.html">${esc(id)}</a> ${esc(CWE.entries[n]?.name ?? '')}`;
};
const list = (items) =>
  items?.length
    ? `<ul>${items.map((s) => `<li>${esc(s)}</li>`).join('')}</ul>`
    : '';
const row = (label, value) =>
  value ? `<tr><th>${label}</th><td>${value}</td></tr>` : '';

const GLOSSARY = [
  [
    'Critical',
    '9.0–10.0',
    'Full compromise of the component or its data, reachable with little effort. Fix immediately.',
  ],
  [
    'High',
    '7.0–8.9',
    'Serious impact on confidentiality, integrity or availability under realistic conditions. Fix before the next release.',
  ],
  [
    'Medium',
    '4.0–6.9',
    'Limited impact, or impact that depends on conditions an attacker cannot easily arrange. Plan a fix.',
  ],
  [
    'Low',
    '0.1–3.9',
    'Minor impact or hard to exploit; defense in depth. Fix when convenient.',
  ],
];
const DIFFICULTY_GLOSSARY = [
  ['Low', 'Exploitable with public knowledge and no special position.'],
  ['Medium', 'Needs specific conditions, knowledge of the system, or timing.'],
  [
    'High',
    'Needs a privileged position, significant resources, or rare conditions.',
  ],
];

export function render({
  engagement: e,
  sarif,
  findings: input,
  hashes = {},
  changes,
}) {
  const findings = enrich(input.findings);
  const byKey = new Map(resultsOf(sarif).map((r) => [r.key, r]));
  const count = (pred) => findings.filter(pred).length;
  const criteria = [...new Set(findings.flatMap((f) => f.soc2 ?? []))].sort(
    (a, b) => a.localeCompare(b, 'en', { numeric: true }),
  );
  const triage = Object.entries(input.triage ?? {});
  const cov = e.coverage ?? [];
  const covCount = (r) => cov.filter((c) => c.result === r).length;

  const evidence = (f) =>
    f.results
      .map((k) => {
        const r = byKey.get(k);
        const loc = r.result.locations?.[0]?.physicalLocation;
        return `<li><code>${esc(loc?.artifactLocation?.uri)}:${esc(loc?.region?.startLine)}</code>. Tool output (${esc(r.run.tool.driver.name)}, <code>${esc(r.result.ruleId)}</code>): ${esc(r.result.message?.text)}</li>`;
      })
      .join('');

  const remediationState = (f) => {
    const parts = [esc(statusLabel(f))];
    if (f.fix?.commit) parts.push(`fix in <code>${esc(f.fix.commit)}</code>`);
    if (f.fix?.path) parts.push(`<code>${esc(f.fix.path)}</code>`);
    if (f.retest)
      parts.push(
        `retested ${esc(f.retest.date)} by ${esc(f.retest.by)}: ${esc(f.retest.evidence ?? f.retest.expect)}`,
      );
    if (f.riskAcceptance)
      parts.push(
        `accepted by ${esc(f.riskAcceptance.by)}: ${esc(f.riskAcceptance.reason)}`,
      );
    return parts.join('; ');
  };

  const detail = (f) => {
    const rep = f.reproducibility;
    const rem = f.remediation;
    return `
<section class="finding" id="${esc(f.id)}">
  <h3>${esc(f.id)}. ${esc(f.title)} ${badge(f.severity)}</h3>
  <table class="kv">
    ${row('Severity', `${badge(f.severity)} ${f.score.toFixed(1)}, <code>${esc(f.cvss.vector)}</code>`)}
    ${row('Why this score', esc(f.cvss.rationale))}
    ${row('Difficulty', `${esc(f.difficulty.level)}: ${esc(f.difficulty.basis)}`)}
    ${rep ? row('Reproducibility', `${rep.successes} of ${rep.trials} attempts (${esc(rep.model)} ${esc(rep.version)})`) : ''}
    ${row('Weakness', cweLink(f.cwe))}
    ${f.owasp?.length ? row('OWASP', f.owasp.map((o) => `${esc(o.list)} ${esc(o.id)}${o.name ? `, ${esc(o.name)}` : ''}`).join('<br>')) : ''}
    ${f.asvs?.length ? row(`ASVS ${esc(ASVS.version)}`, f.asvs.map((a) => `${esc(a)} (L${ASVS.requirements[a].level}, ${esc(ASVS.requirements[a].section)})`).join('<br>')) : ''}
    ${f.soc2?.length ? row('SOC 2 criteria', f.soc2.map(esc).join(', ')) : ''}
    ${f.chainsWith?.length ? row('Chains with', f.chainsWith.map((c) => `<a href="#${esc(c)}">${esc(c)}</a>`).join(', ')) : ''}
    ${row('Status', remediationState(f))}
  </table>
  <h4>Description</h4><p>${esc(f.description)}</p>
  <h4>Exploit scenario</h4><p>${esc(f.exploitScenario)}</p>
  <h4>Impact</h4><p>${esc(f.impact)}</p>
  <h4>Evidence</h4><ul>${evidence(f)}</ul>
  ${
    f.reproduction
      ? `<h4>Reproduction</h4><ul>${Object.entries(f.reproduction)
          .map(([k, v]) => `<li>${esc(k)}: <code>${esc(v)}</code></li>`)
          .join('')}</ul>`
      : ''
  }
  <h4>Remediation</h4>
  <table class="kv">
    ${row('Short term', esc(rem.shortTerm))}
    ${row('Long term', esc(rem.longTerm))}
    ${row('Owner', esc(rem.owner))}
    ${row('Target date', esc(rem.targetDate))}
  </table>
</section>`;
  };

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(e.title ?? 'Security assessment')}: ${esc(e.target.name)} ${esc(e.target.version)}</title>
<style>
  :root { --ink:#1a1d21; --muted:#5b6470; --line:#d9dde3; --bg:#fff; --accent:#1f4e79;
    --crit:#7a0d1a; --high:#b3261e; --med:#8a5a00; --low:#245b2e; --none:#5b6470; }
  * { box-sizing: border-box; }
  body { font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: var(--ink); background: var(--bg); margin: 0; }
  main { max-width: 52rem; margin: 0 auto; padding: 2.5rem 1.25rem 4rem; }
  h1 { font-size: 2rem; line-height: 1.2; margin: 0 0 .5rem; color: var(--accent); }
  h2 { font-size: 1.35rem; margin: 2.5rem 0 .75rem; padding-bottom: .3rem; border-bottom: 2px solid var(--accent); }
  h3 { font-size: 1.1rem; margin: 1.75rem 0 .5rem; }
  h4 { font-size: .95rem; margin: 1rem 0 .25rem; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
  p, li { max-width: 46rem; }
  code { font: .85em/1.4 ui-monospace, SFMono-Regular, Menlo, monospace; background: #f3f5f7; padding: .05em .3em; border-radius: 3px; overflow-wrap: anywhere; }
  table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; font-size: .92rem; }
  th, td { text-align: left; vertical-align: top; padding: .4rem .55rem; border-bottom: 1px solid var(--line); }
  thead th { background: #f3f5f7; }
  .nowrap { white-space: nowrap; }
  .num { text-align: center; }
  .kv th { width: 11rem; color: var(--muted); font-weight: 600; }
  .cover { border-bottom: 1px solid var(--line); padding-bottom: 1.5rem; margin-bottom: 1rem; }
  .cover dl { display: grid; grid-template-columns: max-content 1fr; gap: .25rem 1rem; margin: 1rem 0; }
  .cover dt { color: var(--muted); }
  .notice { border-left: 4px solid var(--accent); background: #eef3f8; padding: .75rem 1rem; margin: 1rem 0; }
  .sev { display: inline-block; font-size: .75rem; font-weight: 700; padding: .1em .5em; border-radius: 3px; color: #fff; vertical-align: middle; }
  .sev-critical { background: var(--crit); } .sev-high { background: var(--high); } .sev-medium { background: var(--med); }
  .sev-low { background: var(--low); } .sev-none { background: var(--none); }
  .counts { display: flex; flex-wrap: wrap; gap: .75rem; margin: .75rem 0; padding: 0; list-style: none; }
  .counts li { border: 1px solid var(--line); border-radius: 6px; padding: .5rem .9rem; min-width: 7rem; }
  .counts b { display: block; font-size: 1.5rem; }
  a { color: var(--accent); }
  footer { margin-top: 3rem; color: var(--muted); font-size: .85rem; }
  @media print {
    body { font-size: 10.5pt; } main { max-width: none; padding: 0; }
    h2, h3, h4 { break-after: avoid-page; } table, .counts { break-inside: avoid-page; }
    .counts li { min-width: 5.5rem; padding: .35rem .6rem; } .counts b { font-size: 1.2rem; }
    a { color: inherit; text-decoration: none; }
    @page { size: A4; margin: 18mm 16mm; }
  }
</style>
</head>
<body>
<main>
<header class="cover">
  <h1>${esc(e.title ?? 'Security assessment')}</h1>
  <p><strong>${esc(e.target.name)}</strong> at <code>${esc(e.target.version)}</code></p>
  <dl>
    <dt>Prepared for</dt><dd>${esc(e.client)}</dd>
    <dt>Prepared by</dt><dd>${esc(e.tester.name)}</dd>
    <dt>Test period</dt><dd>${esc(e.period.start)} to ${esc(e.period.end)}</dd>
    <dt>Issued</dt><dd>${esc(e.issueDate)}, version ${esc(e.reportVersion ?? '1.0')}</dd>
  </dl>
  <p class="notice"><strong>${esc(e.confidentiality)}</strong></p>
  <p class="notice"><strong>This is not a SOC 2 report.</strong> Only a licensed CPA firm can issue a SOC 2 report.
  This assessment is evidence of vulnerability identification and remediation that the client's auditor may choose to rely on.
  The SOC 2 criteria named here are the tester's mapping, not the auditor's conclusion.</p>
</header>

<h2>Executive summary</h2>
<p>${esc(e.summary ?? '')}</p>
<ul class="counts">
  ${SEV.map((s) => `<li>${badge(s)}<b>${count((f) => f.severity === s)}</b>findings</li>`).join('')}
  ${[...new Set(findings.map(statusLabel))].map((l) => `<li><span>${esc(l)}</span><b>${count((f) => statusLabel(f) === l)}</b>of ${findings.length}</li>`).join('')}
</ul>
<h3>Severity and difficulty</h3>
<table>
  <thead><tr><th>Severity</th>${DIFFICULTY.map((d) => `<th class="num">${d} difficulty</th>`).join('')}</tr></thead>
  <tbody>
  ${SEV.map(
    (s) =>
      `<tr><td>${badge(s)}</td>${DIFFICULTY.map(
        (d) =>
          `<td class="num">${
            findings
              .filter((f) => f.severity === s && f.difficulty.level === d)
              .map((f) => `<a href="#${esc(f.id)}">${esc(f.id)}</a>`)
              .join(', ') || '–'
          }</td>`,
      ).join('')}</tr>`,
  ).join('')}
  </tbody>
</table>
<h3>Highest risks</h3>
<ol>${findings
    .slice(0, 3)
    .map(
      (f) =>
        `<li>${badge(f.severity)} <a href="#${esc(f.id)}">${esc(f.id)}. ${esc(f.title)}</a> (${esc(f.difficulty.level.toLowerCase())} difficulty): ${esc(statusLabel(f))}.</li>`,
    )
    .join('')}</ol>
${e.strategicRecommendations?.length ? `<h3>Strategic recommendations</h3>${list(e.strategicRecommendations)}` : ''}
${e.positiveObservations?.length ? `<h3>What is working well</h3>${list(e.positiveObservations)}` : ''}
${
  changes
    ? `<h3>Changes since the previous assessment</h3>
<p>Compared with the report issued ${esc(changes.previous.issueDate)} on <code>${esc(changes.previous.version)}</code>.</p>
<table class="kv">
  ${row('New', changes.new.map((id) => `<a href="#${esc(id)}">${esc(id)}</a>`).join(', ') || 'none')}
  ${row('Resolved', changes.resolved.map(esc).join(', ') || 'none')}
  ${row('Still open', changes.persisting.map((id) => `<a href="#${esc(id)}">${esc(id)}</a>`).join(', ') || 'none')}
</table>`
    : ''
}

<h2>Engagement</h2>
<table class="kv">
  ${row('System boundary', esc(e.boundary))}
  ${row('Target version', `<code>${esc(e.target.version)}</code>`)}
  ${row('Assessment type', esc(e.type ?? 'Point in time'))}
  ${row('Methodology', esc(e.methodology))}
  ${row('Rules of engagement', esc(e.rulesOfEngagement))}
  ${row('Level of effort', esc(e.levelOfEffort))}
  ${row('Tester independence', esc(e.tester.independence))}
  ${row('Limitations', esc(e.limitations))}
  ${row('Not tested', esc(e.outOfScope))}
</table>
<h3>Timeline</h3>
<table>
  <thead><tr><th>Date</th><th>Event</th></tr></thead>
  <tbody>${e.timeline.map((t) => `<tr><td class="nowrap">${esc(t.date)}</td><td>${esc(t.event)}</td></tr>`).join('')}</tbody>
</table>

<h2>Standards</h2>
<table>
  <thead><tr><th>Standard</th><th>Edition</th><th>Used for</th></tr></thead>
  <tbody>
  ${e.standards.map((s) => `<tr><td>${s.url ? `<a href="${esc(s.url)}">${esc(s.name)}</a>` : esc(s.name)}</td><td>${esc(s.edition)}</td><td>${esc(s.use ?? '')}</td></tr>`).join('')}
  </tbody>
</table>

<h2>Coverage</h2>
<p>Every test performed and its result, including the ones that passed, so it is clear what was examined and found sound.
${covCount('pass')} passed, ${covCount('fail')} failed, ${covCount('n/a')} not applicable, ${covCount('out-of-scope')} out of scope.</p>
<table>
  <thead><tr><th>ID</th><th>Reference</th><th>Test</th><th>Result</th></tr></thead>
  <tbody>
  ${cov.map((c) => `<tr><td class="nowrap">${esc(c.id)}</td><td>${esc(c.ref)}</td><td>${esc(c.test)}${c.reason ? ` <em>(${esc(c.reason)})</em>` : ''}</td><td class="nowrap">${esc(c.result)}${c.findings?.length ? `: ${c.findings.map((id) => `<a href="#${esc(id)}">${esc(id)}</a>`).join(', ')}` : ''}</td></tr>`).join('')}
  </tbody>
</table>

<h2>Findings overview</h2>
<table>
  <thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Difficulty</th><th>CWE</th><th>Status</th></tr></thead>
  <tbody>
  ${findings.map((f) => `<tr><td class="nowrap"><a href="#${esc(f.id)}">${esc(f.id)}</a></td><td>${esc(f.title)}</td><td class="nowrap">${badge(f.severity)} ${f.score.toFixed(1)}</td><td>${esc(f.difficulty.level)}</td><td class="nowrap">${esc(f.cwe)}</td><td>${esc(statusLabel(f))}</td></tr>`).join('')}
  </tbody>
</table>

<h2>Finding details</h2>
${findings.map(detail).join('')}

<h2>SOC 2 evidence matrix</h2>
<p>For the auditor: each Common Criterion this assessment provides evidence for, with the findings behind it and where they stand.</p>
<table>
  <thead><tr><th>Criterion</th><th>Findings</th><th>Open</th><th>Fix verified</th></tr></thead>
  <tbody>
  ${criteria
    .map((c) => {
      const fs = findings.filter((f) => f.soc2?.includes(c));
      return `<tr><td>${esc(c)}</td><td>${fs.map((f) => `<a href="#${esc(f.id)}">${esc(f.id)}</a>`).join(', ')}</td><td>${fs.filter((f) => f.status === 'open').length}</td><td>${fs.filter((f) => f.status === 'retested').length}</td></tr>`;
    })
    .join('')}
  </tbody>
</table>

<h2>Appendix</h2>
<h3>Severity and difficulty ratings</h3>
<table>
  <thead><tr><th>Severity</th><th>CVSS v4.0</th><th>Meaning</th></tr></thead>
  <tbody>${GLOSSARY.map(([s, band, m]) => `<tr><td>${badge(s)}</td><td class="nowrap">${band}</td><td>${esc(m)}</td></tr>`).join('')}</tbody>
</table>
<table>
  <thead><tr><th>Difficulty</th><th>Meaning</th></tr></thead>
  <tbody>${DIFFICULTY_GLOSSARY.map(([d, m]) => `<tr><td>${d}</td><td>${esc(m)}</td></tr>`).join('')}</tbody>
</table>
<h3>Tool results triaged out</h3>
<p>Every tool result is either evidence for a finding or listed here with a reason.</p>
<table>
  <thead><tr><th>Result</th><th>Verdict</th><th>Reason</th></tr></thead>
  <tbody>
  ${triage.map(([k, t]) => `<tr><td><code>${esc(k)}</code></td><td>${esc(t.verdict)}</td><td>${esc(t.reason)}</td></tr>`).join('') || '<tr><td colspan="3">None</td></tr>'}
  </tbody>
</table>
<h3>Tools and reference data</h3>
<ul>${e.tools.map((t) => `<li>${esc(t.name)} ${esc(t.version)}</li>`).join('')}
<li>CWE ${esc(CWE.version)} (${esc(CWE.date)}): weakness mappings are checked against MITRE's mapping guidance</li>
<li>CVSS v4.0 scores are computed with FIRST's reference implementation</li></ul>
${
  e.revisions?.length
    ? `<h3>Document control</h3>
<table>
  <thead><tr><th>Version</th><th>Date</th><th>Change</th></tr></thead>
  <tbody>${e.revisions.map((r) => `<tr><td>${esc(r.version)}</td><td class="nowrap">${esc(r.date)}</td><td>${esc(r.change)}</td></tr>`).join('')}</tbody>
</table>`
    : ''
}
<h3>Inputs</h3>
<p>The SHA-256 of each input file, so this report can be reproduced.</p>
<ul>${Object.entries(hashes)
    .map(([f, h]) => `<li><code>${esc(f)}</code>: <code>${esc(h)}</code></li>`)
    .join('')}</ul>
<footer>Prepared by ${esc(e.tester.name)}. ${esc(e.confidentiality)}</footer>
</main>
</body>
</html>
`;
}

/**
 * A retest letter: one page an auditor can file, stating each finding's state after the client's
 * fixes. Only findings with a retest attempt appear. Failed attempts show as still open.
 */
export function retestLetter({ engagement: e, findings: input, date }) {
  const findings = enrich(input.findings).filter(
    (f) => f.retestHistory?.length,
  );
  const latest = (f) => f.retestHistory.at(-1);
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Retest letter: ${esc(e.client)}</title>
<style>
  body { font: 15px/1.55 system-ui, sans-serif; color: #1a1d21; max-width: 46rem; margin: 2.5rem auto; padding: 0 1.25rem; }
  h1 { color: #1f4e79; font-size: 1.6rem; } table { border-collapse: collapse; width: 100%; font-size: .92rem; }
  th, td { text-align: left; vertical-align: top; padding: .4rem .55rem; border-bottom: 1px solid #d9dde3; } thead th { background: #f3f5f7; }
  code { font: .85em ui-monospace, Menlo, monospace; background: #f3f5f7; padding: .05em .3em; }
  @page { size: A4; margin: 18mm 16mm; }
</style></head><body>
<h1>Retest letter</h1>
<p>${esc(date)}</p>
<p>To ${esc(e.client)}:</p>
<p>${esc(e.tester.name)} performed a security assessment of <strong>${esc(e.target.name)}</strong> at <code>${esc(e.target.version)}</code>
between ${esc(e.period.start)} and ${esc(e.period.end)} (report issued ${esc(e.issueDate)}). We then retested the following findings
against the fixes you deployed. The results are below.</p>
<table>
  <thead><tr><th>Finding</th><th>Severity</th><th>Retested against</th><th>Date</th><th>Result</th></tr></thead>
  <tbody>${findings
    .map((f) => {
      const r = latest(f);
      return `<tr><td>${esc(f.id)}. ${esc(f.title)}</td><td>${esc(f.severity)} ${f.score.toFixed(1)}</td><td><code>${esc(r.commit)}</code></td><td>${esc(r.date)}</td><td>${r.result === 'pass' ? 'Resolved' : 'Not resolved'}</td></tr>`;
    })
    .join('')}</tbody>
</table>
<p>A finding is resolved when the original exploit no longer works and the feature still behaves as intended.
Findings not listed were not retested. This letter is not a SOC 2 report. Only a licensed CPA firm can issue one.</p>
<p>${esc(e.tester.name)}</p>
</body></html>
`;
}
