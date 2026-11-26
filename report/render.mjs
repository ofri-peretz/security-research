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
const SEV = ['Critical', 'High', 'Medium', 'Low', 'None'];
const STATUS_LABEL = {
  open: 'Open',
  fixed: 'Fixed, not retested',
  retested: 'Fixed and retested',
};

/** Findings enriched with their computed score, sorted most severe first. */
export function enrich(findings) {
  return findings
    .map((f) => ({ ...f, ...score(f.cvss.vector) }))
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
}

const badge = (sev) =>
  `<span class="sev sev-${sev.toLowerCase()}">${sev}</span>`;
const cweLink = (id) => {
  const n = id.slice(4);
  return `<a href="https://cwe.mitre.org/data/definitions/${n}.html">${esc(id)}</a> ${esc(CWE.entries[n]?.name ?? '')}`;
};

export function render({ engagement: e, sarif, findings: input, hashes = {} }) {
  const findings = enrich(input.findings);
  const byKey = new Map(resultsOf(sarif).map((r) => [r.key, r]));
  const count = (pred) => findings.filter(pred).length;
  const top = findings.slice(0, 3);
  const criteria = [...new Set(findings.flatMap((f) => f.soc2 ?? []))].sort(
    (a, b) => a.localeCompare(b, 'en', { numeric: true }),
  );
  const triage = Object.entries(input.triage ?? {});

  const evidence = (f) =>
    f.results
      .map((k) => {
        const r = byKey.get(k);
        const loc = r.result.locations?.[0]?.physicalLocation;
        return `<li><code>${esc(loc?.artifactLocation?.uri)}:${esc(loc?.region?.startLine)}</code>, ${esc(r.run.tool.driver.name)} <code>${esc(r.result.ruleId)}</code>: ${esc(r.result.message?.text)}</li>`;
      })
      .join('');

  const detail = (f) => `
<section class="finding" id="${esc(f.id)}">
  <h3>${esc(f.id)}. ${esc(f.title)} ${badge(f.severity)}</h3>
  <table class="kv">
    <tr><th>Severity</th><td>${badge(f.severity)} ${f.score.toFixed(1)}, <code>${esc(f.cvss.vector)}</code></td></tr>
    <tr><th>Why this score</th><td>${esc(f.cvss.rationale)}</td></tr>
    <tr><th>Weakness</th><td>${cweLink(f.cwe)}</td></tr>
    ${f.owasp?.length ? `<tr><th>OWASP</th><td>${f.owasp.map((o) => `${esc(o.list)} ${esc(o.id)}${o.name ? `, ${esc(o.name)}` : ''}`).join('<br>')}</td></tr>` : ''}
    ${f.asvs?.length ? `<tr><th>ASVS ${esc(ASVS.version)}</th><td>${f.asvs.map((a) => `${esc(a)} (L${ASVS.requirements[a].level}, ${esc(ASVS.requirements[a].section)})`).join('<br>')}</td></tr>` : ''}
    ${f.soc2?.length ? `<tr><th>SOC 2 criteria</th><td>${f.soc2.map(esc).join(', ')}</td></tr>` : ''}
    <tr><th>Status</th><td>${esc(STATUS_LABEL[f.status])}${f.fix?.commit ? `, fix in <code>${esc(f.fix.commit)}</code>${f.fix.path ? ` (<code>${esc(f.fix.path)}</code>)` : ''}` : ''}${f.retest ? `; retested ${esc(f.retest.date)}: ${esc(f.retest.expect)}` : ''}</td></tr>
  </table>
  <h4>Description</h4><p>${esc(f.description)}</p>
  <h4>Impact</h4><p>${esc(f.impact)}</p>
  <h4>Evidence</h4><ul>${evidence(f)}</ul>
  ${
    f.reproduction
      ? `<h4>Reproduction</h4><ul>${Object.entries(f.reproduction)
          .map(([k, v]) => `<li>${esc(k)}: <code>${esc(v)}</code></li>`)
          .join('')}</ul>`
      : ''
  }
  <h4>Remediation</h4><p>${esc(f.remediation)}</p>
</section>`;

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
  .finding { break-inside: avoid-page; }
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
    <dt>Tester</dt><dd>${esc(e.tester.name)}</dd>
    <dt>Test period</dt><dd>${esc(e.period.start)} to ${esc(e.period.end)}</dd>
    <dt>Report version</dt><dd>${esc(e.reportVersion ?? '1.0')}</dd>
  </dl>
  <p class="notice"><strong>This is not a SOC 2 report.</strong> Only a licensed CPA firm can issue a SOC 2 report.
  This assessment is evidence of vulnerability identification and remediation that the client's auditor may choose to rely on.
  The SOC 2 criteria named here are the tester's mapping, not the auditor's conclusion.</p>
</header>

<h2>Executive summary</h2>
<p>${esc(e.summary ?? '')}</p>
<ul class="counts">
  ${SEV.filter((s) => s !== 'None')
    .map(
      (s) =>
        `<li>${badge(s)}<b>${count((f) => f.severity === s)}</b>findings</li>`,
    )
    .join('')}
  <li><span>Open</span><b>${count((f) => f.status === 'open')}</b>of ${findings.length}</li>
  <li><span>Retested</span><b>${count((f) => f.status === 'retested')}</b>of ${findings.length}</li>
</ul>
<h3>Highest risks</h3>
<ol>${top.map((f) => `<li>${badge(f.severity)} <a href="#${esc(f.id)}">${esc(f.id)}. ${esc(f.title)}</a>: ${esc(STATUS_LABEL[f.status])}.</li>`).join('')}</ol>

<h2>Scope and methodology</h2>
<table class="kv">
  <tr><th>System boundary</th><td>${esc(e.boundary)}</td></tr>
  <tr><th>Target version</th><td><code>${esc(e.target.version)}</code></td></tr>
  <tr><th>Assessment type</th><td>${esc(e.type ?? 'Point in time')}</td></tr>
  <tr><th>Methodology</th><td>${esc(e.methodology)}</td></tr>
  <tr><th>Tester independence</th><td>${esc(e.tester.independence)}</td></tr>
  ${e.limitations ? `<tr><th>Limitations</th><td>${esc(e.limitations)}</td></tr>` : ''}
  ${e.outOfScope ? `<tr><th>Not tested</th><td>${esc(e.outOfScope)}</td></tr>` : ''}
</table>

<h2>Standards</h2>
<table>
  <thead><tr><th>Standard</th><th>Edition</th><th>Used for</th></tr></thead>
  <tbody>
  ${e.standards.map((s) => `<tr><td>${s.url ? `<a href="${esc(s.url)}">${esc(s.name)}</a>` : esc(s.name)}</td><td>${esc(s.edition)}</td><td>${esc(s.use ?? '')}</td></tr>`).join('')}
  <tr><td>CWE (validation catalog)</td><td>${esc(CWE.version)} (${esc(CWE.date)})</td><td>Every weakness is checked against MITRE's mapping guidance</td></tr>
  </tbody>
</table>

<h2>Findings overview</h2>
<table>
  <thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>CWE</th><th>Status</th></tr></thead>
  <tbody>
  ${findings.map((f) => `<tr><td class="nowrap"><a href="#${esc(f.id)}">${esc(f.id)}</a></td><td>${esc(f.title)}</td><td class="nowrap">${badge(f.severity)} ${f.score.toFixed(1)}</td><td class="nowrap">${esc(f.cwe)}</td><td>${esc(STATUS_LABEL[f.status])}</td></tr>`).join('')}
  </tbody>
</table>

<h2>Finding details</h2>
${findings.map(detail).join('')}

<h2>SOC 2 evidence matrix</h2>
<p>For the auditor: each Common Criterion this assessment provides evidence for, with the findings behind it and where they stand.</p>
<table>
  <thead><tr><th>Criterion</th><th>Findings</th><th>Open</th><th>Retested</th></tr></thead>
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
<h3>Results triaged out</h3>
<p>Every tool result is either evidence for a finding or listed here with a reason. Nothing is dropped silently.</p>
<table>
  <thead><tr><th>Result</th><th>Verdict</th><th>Reason</th></tr></thead>
  <tbody>
  ${triage.map(([k, t]) => `<tr><td><code>${esc(k)}</code></td><td>${esc(t.verdict)}</td><td>${esc(t.reason)}</td></tr>`).join('') || '<tr><td colspan="3">None</td></tr>'}
  </tbody>
</table>
<h3>Tools</h3>
<ul>${e.tools.map((t) => `<li>${esc(t.name)} ${esc(t.version)}</li>`).join('')}</ul>
<h3>Inputs</h3>
<p>This report was generated from these files. Each one's SHA-256 is listed so the report can be reproduced.</p>
<ul>${Object.entries(hashes)
    .map(([f, h]) => `<li><code>${esc(f)}</code>: <code>${esc(h)}</code></li>`)
    .join('')}</ul>
<footer>Generated by security-research/report from SARIF ${esc(sarif.version)}. Severity is CVSS v4.0, scored with FIRST's reference implementation.</footer>
</main>
</body>
</html>
`;
}
