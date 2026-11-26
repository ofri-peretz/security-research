// Client engagements: a private workspace per client, manual findings as SARIF, retests against
// the client's fix commits, and the diff between consecutive reports (SOC 2 Type II).
// Client data lives under SR_HOME/clients/<slug>, outside this repo, owner-only.
import fs from 'node:fs';
import path from 'node:path';
import { home, REPO } from './findings.mjs';

const TEMPLATES = path.join(REPO, 'report', 'templates');

export function clientDir(slug, h = home()) {
  if (!/^[a-z0-9][a-z0-9-]{1,62}$/.test(slug))
    throw new Error(
      `client slug must be lowercase letters, digits and dashes: ${slug}`,
    );
  return path.join(h, 'clients', slug);
}

/** Creates the workspace from the templates. Refuses to overwrite an existing client. */
export function createWorkspace({ slug, client, tester, today, h = home() }) {
  const dir = clientDir(slug, h);
  if (fs.existsSync(dir)) throw new Error(`${dir} already exists`);
  for (const d of ['', 'tool', 'evidence', 'out'])
    fs.mkdirSync(path.join(dir, d), { recursive: true, mode: 0o700 });
  const write = (f, text) =>
    fs.writeFileSync(path.join(dir, f), text, { mode: 0o600 });
  const id = `${slug}-${today}`;

  const e = JSON.parse(
    fs.readFileSync(path.join(TEMPLATES, 'saas-engagement.json'), 'utf8'),
  );
  delete e.$comment;
  Object.assign(e, {
    id,
    client,
    title: `Security assessment: ${client}`,
    issueDate: today,
  });
  e.tester.name = tester;
  e.revisions = [{ version: '1.0', date: today, change: 'First issue' }];
  write('engagement.json', JSON.stringify(e, null, 2) + '\n');
  write(
    'findings.json',
    JSON.stringify({ findings: [], triage: {} }, null, 2) + '\n',
  );
  write('manual.json', '[]\n');
  write(
    'scoping.md',
    fs.readFileSync(path.join(TEMPLATES, 'scoping-questionnaire.md'), 'utf8'),
  );
  write(
    'authorization.md',
    fs
      .readFileSync(path.join(TEMPLATES, 'authorization.md'), 'utf8')
      .replaceAll('{{client}}', client)
      .replaceAll('{{tester}}', tester)
      .replaceAll('{{engagementId}}', id),
  );
  return dir;
}

/**
 * Manual test results, written by the tester, as a SARIF run. Each entry:
 * { id: 'M-01', title, location: 'https://api.example.com/v1/orders/{id}' | 'src/a.js:42', detail }
 */
export function manualToSarifRun(manual, tester) {
  const errors = [];
  const ids = new Set();
  const results = manual.map((m, i) => {
    const at = `manual.json[${i}]`;
    if (!/^M-\d{2,}$/.test(m.id ?? ''))
      errors.push(`${at}: id must look like "M-01"`);
    if (ids.has(m.id)) errors.push(`${at}: duplicate id ${m.id}`);
    ids.add(m.id);
    for (const k of ['title', 'location', 'detail'])
      if (typeof m[k] !== 'string' || !m[k].trim())
        errors.push(`${at}: ${k} is required`);
    const [, uri = m.location, line] =
      /^(?!https?:)(.+):(\d+)$/.exec(m.location ?? '') ?? [];
    return {
      ruleId: m.id,
      level: 'error',
      message: { text: `${m.title}. ${m.detail}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri },
            region: { startLine: line ? Number(line) : 1 },
          },
        },
      ],
    };
  });
  if (errors.length) throw new Error(errors.join('\n'));
  return {
    tool: {
      driver: {
        name: 'manual-testing',
        version: tester,
        rules: results.map((r) => ({ id: r.ruleId })),
      },
    },
    results,
  };
}

/** All tool SARIF in tool/*.sarif plus manual.json, merged into one log. */
export function mergedSarif(dir, tester) {
  const runs = fs
    .readdirSync(path.join(dir, 'tool'))
    .filter((f) => f.endsWith('.sarif'))
    .sort()
    .flatMap(
      (f) =>
        JSON.parse(fs.readFileSync(path.join(dir, 'tool', f), 'utf8')).runs ??
        [],
    );
  const manual = JSON.parse(
    fs.readFileSync(path.join(dir, 'manual.json'), 'utf8'),
  );
  if (manual.length) runs.push(manualToSarifRun(manual, tester));
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs,
  };
}

/**
 * Records a retest of the client's fix. A pass marks the finding retested. A fail keeps it open.
 * Either way the attempt goes into retestHistory, so the audit trail keeps failed retests too.
 */
export function applyRetest(
  finding,
  { commit, result, by, date, evidence },
  targetVersion,
) {
  if (!commit)
    throw new Error(
      '--commit is required: the client commit or release the fix is in',
    );
  if (commit === targetVersion)
    throw new Error(
      `${commit} is the version originally tested; retest the fix's commit`,
    );
  if (result !== 'pass' && result !== 'fail')
    throw new Error('--result must be pass or fail');
  if (!by || !evidence) throw new Error('--by and --evidence are required');
  const attempt = { date, commit, result, by, evidence };
  const f = structuredClone(finding);
  f.retestHistory = [...(f.retestHistory ?? []), attempt];
  if (result === 'pass') {
    f.status = 'retested';
    f.fix = { kind: 'client', commit };
    f.retest = { date, by, result: 'pass', evidence };
  } else {
    f.status = 'open';
    delete f.retest;
  }
  return f;
}

/**
 * What changed since the previous report for the same client (finding ids stay stable across
 * engagements). `prev` and `cur` are report.json contents.
 */
export function diffReports(prev, cur) {
  const before = new Map(prev.findings.map((f) => [f.id, f]));
  const after = new Map(cur.findings.map((f) => [f.id, f]));
  const closed = (f) =>
    f.status === 'retested' ||
    f.status === 'fixed' ||
    f.status === 'risk-accepted';
  return {
    previous: {
      issueDate: prev.engagement.issueDate,
      version: prev.engagement.target.version,
    },
    new: cur.findings.filter((f) => !before.has(f.id)).map((f) => f.id),
    resolved: prev.findings
      .filter(
        (f) => !closed(f) && (!after.has(f.id) || closed(after.get(f.id))),
      )
      .map((f) => f.id),
    persisting: cur.findings
      .filter(
        (f) => before.has(f.id) && !closed(f) && !closed(before.get(f.id)),
      )
      .map((f) => f.id),
  };
}
