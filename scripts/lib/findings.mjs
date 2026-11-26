// The hunting pipeline's shared core: where private findings live, what a complete finding is,
// and the pure transforms each stage needs (private report, disclosure clock, OSV, write-up).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseVector, score } from '../../report/cvss.mjs';
import { validateCwe, CWE } from '../../report/validate.mjs';

export const REPO = path.resolve(import.meta.dirname, '..', '..');
export const home = () =>
  process.env.SR_HOME ?? path.join(os.homedir(), '.security-research');
export const DISCLOSURE_DAYS = 90;
const DAY = 86_400_000;

// ── private workspace ─────────────────────────────────────────────────────────────────────────

const findingsDir = (h = home()) => path.join(h, 'findings');
const findingFile = (id, h = home()) =>
  path.join(findingsDir(h), id, 'finding.json');

export function listFindings(h = home()) {
  if (!fs.existsSync(findingsDir(h))) return [];
  return fs
    .readdirSync(findingsDir(h))
    .filter((d) => fs.existsSync(findingFile(d, h)))
    .sort()
    .map((d) => loadFinding(d, h));
}

export function loadFinding(id, h = home()) {
  if (!/^SR-\d{4}-\d{3,}$/.test(id)) throw new Error(`not a finding id: ${id}`);
  return JSON.parse(fs.readFileSync(findingFile(id, h), 'utf8'));
}

export function saveFinding(f, h = home()) {
  fs.mkdirSync(path.dirname(findingFile(f.id, h)), {
    recursive: true,
    mode: 0o700,
  });
  fs.writeFileSync(findingFile(f.id, h), JSON.stringify(f, null, 2) + '\n', {
    mode: 0o600,
  });
}

export function nextId(year, h = home()) {
  const n =
    listFindings(h).filter((f) => f.id.startsWith(`SR-${year}-`)).length + 1;
  return `SR-${year}-${String(n).padStart(3, '0')}`;
}

export function newFinding({ id, repo, pkg, title, today }) {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo))
    throw new Error(`repo must be owner/name, got ${repo}`);
  return {
    id,
    title,
    target: { repo, ecosystem: 'npm', package: pkg },
    authorization: '',
    status: 'triage',
    cwe: '',
    cvss: { vector: '', rationale: '' },
    affected: { introduced: '0', fixed: null },
    summary: '',
    details: '',
    impact: '',
    remediation: '',
    credits: [],
    references: [],
    ghsa: null,
    cve: null,
    report: null,
    timeline: { opened: today, reported: null, fixed: null, published: null },
  };
}

// ── open-finding guard list (repo/.open-findings, gitignored) ─────────────────────────────────

const listFile = (repo = REPO) => path.join(repo, '.open-findings');
const termsOf = (f) =>
  [f.target.repo, f.target.package].filter(Boolean).map((t) => t.toLowerCase());

export function addOpenTargets(f, repo = REPO) {
  const file = listFile(repo);
  const text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
  const have = new Set(
    text.split('\n').map((l) => l.replace(/#.*/, '').trim().toLowerCase()),
  );
  const add = termsOf(f).filter((t) => !have.has(t));
  if (add.length)
    fs.writeFileSync(
      file,
      text +
        (text && !text.endsWith('\n') ? '\n' : '') +
        `# ${f.id}\n` +
        add.join('\n') +
        '\n',
    );
  return add;
}

/** Removes a published finding's targets, unless another open finding still names them. */
export function removeOpenTargets(f, stillOpen, repo = REPO) {
  const keep = new Set(stillOpen.filter((o) => o.id !== f.id).flatMap(termsOf));
  const drop = new Set(termsOf(f).filter((t) => !keep.has(t)));
  const file = listFile(repo);
  if (!fs.existsSync(file)) return [];
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  const out = lines.filter(
    (l) => !drop.has(l.trim().toLowerCase()) && l.trim() !== `# ${f.id}`,
  );
  fs.writeFileSync(file, out.join('\n'));
  return [...drop];
}

// ── completeness ─────────────────────────────────────────────────────────────────────────────

const filled = (v) => typeof v === 'string' && v.trim().length > 0;

/** Errors that block a private report. Publishing adds its own checks on top. */
export function validateFinding(f) {
  const errors = [];
  for (const k of [
    'title',
    'summary',
    'details',
    'impact',
    'remediation',
    'authorization',
  ]) {
    if (!filled(f[k])) errors.push(`${k} is empty`);
  }
  validateCwe(f.cwe, f.id, errors);
  const v = parseVector(f.cvss?.vector);
  if (v.error) errors.push(`CVSS ${v.error}`);
  if (!filled(f.cvss?.rationale)) errors.push('CVSS rationale is empty');
  if (!filled(f.affected?.introduced))
    errors.push('affected.introduced is empty');
  return errors;
}

// ── disclosure clock ─────────────────────────────────────────────────────────────────────────

export function deadline(reported) {
  return new Date(Date.parse(reported) + DISCLOSURE_DAYS * DAY)
    .toISOString()
    .slice(0, 10);
}

export function daysBetween(from, to) {
  return Math.floor((Date.parse(to) - Date.parse(from)) / DAY);
}

/**
 * What still blocks publishing. `checks` are looked up by the caller (network), so this stays pure:
 * { fixedOnNpm: boolean, ghsaPublished: boolean, today: 'YYYY-MM-DD', deadlineRelease: boolean }
 */
export function publishBlockers(
  f,
  { fixedOnNpm, ghsaPublished, today, deadlineRelease = false },
) {
  const blockers = validateFinding(f);
  if (f.status === 'published') blockers.push('already published');
  if (!f.timeline?.reported) blockers.push('never reported to the maintainer');
  const pastDeadline =
    f.timeline?.reported && today >= deadline(f.timeline.reported);
  if (deadlineRelease) {
    if (!pastDeadline)
      blockers.push(
        `deadline release requested, but the deadline is ${f.timeline?.reported ? deadline(f.timeline.reported) : 'unknown'}`,
      );
  } else {
    if (!f.affected?.fixed)
      blockers.push('no fixed version recorded (affected.fixed)');
    else if (!fixedOnNpm)
      blockers.push(
        `${f.target.package}@${f.affected.fixed} is not on npm yet`,
      );
    if (!f.ghsa) blockers.push('no GHSA id recorded');
    else if (!ghsaPublished)
      blockers.push(`${f.ghsa} is not published by the maintainer yet`);
  }
  return blockers;
}

// ── outputs ──────────────────────────────────────────────────────────────────────────────────

const GH_SEVERITY = {
  Critical: 'critical',
  High: 'high',
  Medium: 'medium',
  Low: 'low',
  None: 'low',
};

/** Body for POST /repos/{owner}/{repo}/security-advisories/reports (GitHub private vulnerability reporting). */
export function privateReport(f) {
  const s = score(f.cvss.vector);
  const range = f.affected.fixed
    ? `< ${f.affected.fixed}`
    : `>= ${f.affected.introduced}`;
  return {
    summary: f.title,
    description: [
      f.summary,
      '## Details',
      f.details,
      '## Impact',
      f.impact,
      '## Suggested fix',
      f.remediation,
      '## Severity',
      `CVSS v4.0 ${s.score} (${s.severity}): \`${f.cvss.vector}\`. ${f.cvss.rationale}`,
      '## Disclosure',
      `We follow a ${DISCLOSURE_DAYS}-day coordinated disclosure policy from the date of this report, and publish only after a fix ships or the deadline passes. We're happy to adjust the timeline if you're actively working on a fix.`,
    ].join('\n\n'),
    severity: GH_SEVERITY[s.severity],
    cwe_ids: [f.cwe],
    vulnerabilities: [
      {
        package: { ecosystem: f.target.ecosystem, name: f.target.package },
        vulnerable_version_range: range,
        ...(f.affected.fixed ? { patched_versions: f.affected.fixed } : {}),
      },
    ],
  };
}

/** An OSV record (https://ossf.github.io/osv-schema/). The GHSA id is canonical; ours is an alias. */
export function toOsv(f, published) {
  return {
    schema_version: '1.6.0',
    id: f.ghsa ?? f.id,
    modified: `${published}T00:00:00Z`,
    published: `${published}T00:00:00Z`,
    aliases: [f.cve, f.ghsa ? f.id : null].filter(Boolean),
    summary: f.title,
    details: [f.summary, f.details].join('\n\n'),
    severity: [{ type: 'CVSS_V4', score: f.cvss.vector }],
    affected: [
      {
        package: { ecosystem: f.target.ecosystem, name: f.target.package },
        ranges: [
          {
            type: 'SEMVER',
            events: [
              { introduced: f.affected.introduced },
              ...(f.affected.fixed ? [{ fixed: f.affected.fixed }] : []),
            ],
          },
        ],
      },
    ],
    references: [
      ...(f.ghsa
        ? [
            {
              type: 'ADVISORY',
              url: `https://github.com/${f.target.repo}/security/advisories/${f.ghsa}`,
            },
          ]
        : []),
      ...(f.references ?? []).map((url) => ({ type: 'WEB', url })),
    ],
    credits: (f.credits ?? []).map((name) => ({ name, type: 'FINDER' })),
    database_specific: { cwe_ids: [f.cwe] },
  };
}

export function advisoryMarkdown(f, published) {
  const s = score(f.cvss.vector);
  const n = f.cwe.slice(4);
  const t = f.timeline;
  return `# ${f.id}: ${f.title}

| | |
|---|---|
| Package | \`${f.target.package}\` (${f.target.ecosystem}), [${f.target.repo}](https://github.com/${f.target.repo}) |
| Affected | \`>= ${f.affected.introduced}${f.affected.fixed ? `, < ${f.affected.fixed}` : ''}\` |
| Fixed in | ${f.affected.fixed ? `\`${f.affected.fixed}\`` : 'not fixed (published at the disclosure deadline)'} |
| Severity | ${s.severity} ${s.score}, \`${f.cvss.vector}\` |
| Weakness | [${f.cwe}](https://cwe.mitre.org/data/definitions/${n}.html) ${CWE.entries[n]?.name ?? ''} |
| Advisory | ${f.ghsa ? `[${f.ghsa}](https://github.com/${f.target.repo}/security/advisories/${f.ghsa})` : 'none'}${f.cve ? `, ${f.cve}` : ''} |

${f.summary}

## Details

${f.details}

## Impact

${f.impact}

## Remediation

${f.remediation}

Why this score: ${f.cvss.rationale}

## Timeline

- ${t.reported}: reported privately to the maintainer
${t.fixed ? `- ${t.fixed}: fix released (\`${f.affected.fixed}\`)\n` : ''}- ${published}: published here
`;
}
