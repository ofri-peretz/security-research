#!/usr/bin/env node
// The bug-hunting pipeline: hunt → finding → report → disclosure → publish.
// Intent: docs/intents/2026-11-26-hunting-pipeline.md. Commands that reach outside this
// machine (report, publish) print a dry run unless given --send / --pr.
//
//   node scripts/sr.mjs hunt <npm-package>[@version] [--strict]
//   node scripts/sr.mjs finding new <owner/repo> <npm-package> "<title>"
//   node scripts/sr.mjs finding list
//   node scripts/sr.mjs report <SR-id> [--send]
//   node scripts/sr.mjs disclosure [--offline]
//   node scripts/sr.mjs publish <SR-id> [--deadline-release] [--pr]
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { ESLint } from 'eslint';
import nodeSecurity from 'eslint-plugin-node-security';
import secureCoding from 'eslint-plugin-secure-coding';
import mcpSdkSecurity from 'eslint-plugin-mcp-sdk-security';
import { eslintToSarifRun } from '../report/sarif.mjs';
import * as F from './lib/findings.mjs';

const PLUGINS = {
  'eslint-plugin-node-security': nodeSecurity,
  'eslint-plugin-secure-coding': secureCoding,
  'eslint-plugin-mcp-sdk-security': mcpSdkSecurity,
};
const [cmd, ...rest] = process.argv.slice(2);
const flags = new Set(rest.filter((a) => a.startsWith('--')));
const args = rest.filter((a) => !a.startsWith('--'));
const today = new Date().toISOString().slice(0, 10);
const run = (bin, a, opts = {}) =>
  execFileSync(bin, a, {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    ...opts,
  });
const fail = (msg) => {
  console.error(msg);
  process.exit(1);
};

const commands = {
  async hunt() {
    const spec = args[0] ?? fail('usage: hunt <npm-package>[@version]');
    const { name, version } = JSON.parse(
      run('npm', ['view', spec, 'name', 'version', '--json']),
    );
    const dir = path.join(
      F.home(),
      'hunts',
      `${name.replace('/', '__')}@${version}`,
    );
    const src = path.join(dir, 'src');
    fs.rmSync(dir, { recursive: true, force: true });
    fs.mkdirSync(src, { recursive: true, mode: 0o700 });
    // Published source is untrusted: download without lifecycle scripts, extract into its own
    // directory, and only ever parse it.
    const [{ filename }] = JSON.parse(
      run('npm', [
        'pack',
        `${name}@${version}`,
        '--pack-destination',
        dir,
        '--ignore-scripts',
        '--json',
      ]),
    );
    run('tar', ['-xzf', path.join(dir, filename), '-C', src]);

    // recommended by default: strict is 10x noisier on third-party code (371 vs 34 hits on mcp-remote@0.1.15).
    const level = flags.has('--strict') ? 'strict' : 'recommended';
    const flat = (c) => (Array.isArray(c) ? c : [c]);
    const eslint = new ESLint({
      cwd: src,
      overrideConfigFile: true,
      overrideConfig: [
        {
          files: ['**/*.js', '**/*.mjs'],
          languageOptions: { ecmaVersion: 'latest', sourceType: 'module' },
        },
        {
          files: ['**/*.cjs'],
          languageOptions: { ecmaVersion: 'latest', sourceType: 'commonjs' },
        },
        ...Object.values(PLUGINS).flatMap((p) => flat(p.configs[level])),
      ],
    });
    const files = sourceFiles(src);
    const results = await eslint.lintFiles(files);
    const versions = Object.keys(PLUGINS)
      .map(
        (p) =>
          `${p}@${JSON.parse(fs.readFileSync(path.join(F.REPO, 'node_modules', p, 'package.json'), 'utf8')).version}`,
      )
      .join(' ');
    const sarif = {
      version: '2.1.0',
      runs: [
        eslintToSarifRun(results, {
          root: src,
          version: `${versions} (${level})`,
        }),
      ],
    };
    fs.writeFileSync(
      path.join(dir, 'results.sarif'),
      JSON.stringify(sarif, null, 2),
    );

    const fatal = results.filter((r) =>
      r.messages.some((m) => !m.ruleId),
    ).length;
    const byRule = {};
    for (const r of sarif.runs[0].results)
      (byRule[r.ruleId] ??= []).push(
        `${r.locations[0].physicalLocation.artifactLocation.uri}:${r.locations[0].physicalLocation.region.startLine}`,
      );
    const ranked = Object.entries(byRule).sort(
      (a, b) => b[1].length - a[1].length,
    );
    fs.writeFileSync(
      path.join(dir, 'summary.json'),
      JSON.stringify(
        { name, version, files: files.length, parseErrors: fatal, byRule },
        null,
        2,
      ),
    );
    console.log(
      `hunt (${level}): ${name}@${version}, ${files.length} files, ${sarif.runs[0].results.length} hits, ${fatal} unparsable`,
    );
    for (const [rule, locs] of ranked.slice(0, 15))
      console.log(
        `  ${String(locs.length).padStart(4)}  ${rule}  e.g. ${locs[0]}`,
      );
    console.log(`\nSARIF: ${path.join(dir, 'results.sarif')}`);
    console.log(
      'Triage by reading the code at each hit. Confirm a real issue locally before opening a finding.',
    );
  },

  finding() {
    const [sub, ...a] = args;
    if (sub === 'new') {
      const [repo, pkg, title] = a;
      if (!repo || !pkg || !title)
        fail('usage: finding new <owner/repo> <npm-package> "<title>"');
      const f = F.newFinding({
        id: F.nextId(today.slice(0, 4)),
        repo,
        pkg,
        title,
        today,
      });
      // Guard first, so the target is protected before any file mentions it.
      const added = F.addOpenTargets(f);
      F.saveFinding(f);
      console.log(
        `${f.id} opened: ${path.join(F.home(), 'findings', f.id, 'finding.json')}`,
      );
      console.log(
        `open-finding guard now blocks ${added.length} more term(s). Fill in the finding, then: sr report ${f.id}`,
      );
    } else if (sub === 'list') {
      for (const f of F.listFindings()) {
        const since = f.timeline.reported
          ? `${F.daysBetween(f.timeline.reported, today)}d since report`
          : 'not reported';
        console.log(
          `${f.id}  ${f.status.padEnd(9)}  ${since.padEnd(20)}  ${f.title}`,
        );
      }
    } else fail('usage: finding new|list');
  },

  report() {
    const f = F.loadFinding(args[0] ?? fail('usage: report <SR-id> [--send]'));
    if (f.status !== 'triage') fail(`${f.id} is already ${f.status}`);
    const errors = F.validateFinding(f);
    if (errors.length)
      fail(`${f.id} isn't ready to report:\n  ✖ ${errors.join('\n  ✖ ')}`);
    const body = F.privateReport(f);
    const endpoint = `repos/${f.target.repo}/security-advisories/reports`;
    if (!flags.has('--send')) {
      console.log(
        `DRY RUN: would POST to ${endpoint}:\n${JSON.stringify(body, null, 2)}\n\nRe-run with --send to file it.`,
      );
      return;
    }
    const res = JSON.parse(
      run('gh', ['api', '-X', 'POST', endpoint, '--input', '-'], {
        input: JSON.stringify(body),
      }),
    );
    f.status = 'reported';
    f.ghsa = res.ghsa_id ?? null;
    f.report = { url: res.html_url ?? null };
    f.timeline.reported = today;
    F.saveFinding(f);
    console.log(
      `${f.id} reported: ${res.html_url}\nDisclosure deadline: ${F.deadline(today)}`,
    );
  },

  disclosure() {
    const offline = flags.has('--offline');
    for (const f of F.listFindings().filter((x) => x.status !== 'published')) {
      if (!f.timeline.reported) {
        console.log(`${f.id}  triage    not reported yet`);
        continue;
      }
      const checks = offline
        ? { fixedOnNpm: false, ghsaPublished: false }
        : lookups(f);
      const blockers = F.publishBlockers(f, { ...checks, today });
      const due = F.deadline(f.timeline.reported);
      const state =
        blockers.length === 0
          ? 'READY'
          : today >= due
            ? 'DEADLINE PASSED'
            : `${F.daysBetween(today, due)}d left`;
      console.log(
        `${f.id}  ${state.padEnd(16)}  reported ${f.timeline.reported}, deadline ${due}  ${f.title}`,
      );
      if (blockers.length && !offline)
        for (const b of blockers) console.log(`      waiting on: ${b}`);
    }
  },

  publish() {
    const f = F.loadFinding(
      args[0] ?? fail('usage: publish <SR-id> [--deadline-release] [--pr]'),
    );
    const blockers = F.publishBlockers(f, {
      ...lookups(f),
      today,
      deadlineRelease: flags.has('--deadline-release'),
    });
    if (blockers.length)
      fail(`${f.id} can't be published:\n  ✖ ${blockers.join('\n  ✖ ')}`);
    const md = F.advisoryMarkdown(f, today);
    const osv = JSON.stringify(F.toOsv(f, today), null, 2) + '\n';
    const out = (ext) => path.join(F.REPO, 'advisories', `${f.id}.${ext}`);
    if (!flags.has('--pr')) {
      console.log(
        `DRY RUN: would write ${out('md')} and ${out('osv.json')}, then open a PR.\n\n${md}`,
      );
      return;
    }
    const others = F.listFindings().filter((x) => x.status !== 'published');
    F.removeOpenTargets(f, others);
    fs.mkdirSync(path.join(F.REPO, 'advisories'), { recursive: true });
    fs.writeFileSync(out('md'), md);
    fs.writeFileSync(out('osv.json'), osv);
    const git = (...a) => run('git', a, { cwd: F.REPO });
    git('fetch', '-q', 'origin');
    git('switch', '-c', `advisory/${f.id.toLowerCase()}`, 'origin/main');
    git('add', out('md'), out('osv.json'));
    git(
      'commit',
      '-m',
      `docs(advisory): ${f.id} ${f.title}\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`,
    );
    git('push', '-u', 'origin', 'HEAD');
    const url = run('gh', ['pr', 'create', '--fill', '--base', 'main'], {
      cwd: F.REPO,
    }).trim();
    f.status = 'published';
    f.timeline.published = today;
    F.saveFinding(f);
    console.log(`${f.id} published: ${url}`);
  },
};

/**
 * JS files worth parsing: bundles are kept (that's where npm packages ship their code), minified
 * builds are skipped.
 * ponytail: "minified" means an average line over 300 chars; files over 5 MB are skipped outright.
 */
function sourceFiles(dir) {
  return fs
    .readdirSync(dir, { recursive: true })
    .map((p) => path.join(dir, p))
    .filter(
      (p) =>
        /\.(c|m)?js$/.test(p) &&
        !p.includes(`${path.sep}node_modules${path.sep}`),
    )
    .filter((p) => {
      const { size } = fs.statSync(p);
      if (size > 5 * 1024 * 1024) return false;
      const text = fs.readFileSync(p, 'utf8');
      return text.length / (text.split('\n').length || 1) < 300;
    });
}

function lookups(f) {
  let fixedOnNpm = false;
  let ghsaPublished = false;
  if (f.affected?.fixed) {
    try {
      fixedOnNpm =
        run('npm', [
          'view',
          `${f.target.package}@${f.affected.fixed}`,
          'version',
        ]).trim() === f.affected.fixed;
    } catch {}
  }
  if (f.ghsa) {
    try {
      ghsaPublished =
        run('gh', [
          'api',
          `repos/${f.target.repo}/security-advisories/${f.ghsa}`,
          '--jq',
          '.state',
        ]).trim() === 'published';
    } catch {}
  }
  return { fixedOnNpm, ghsaPublished };
}

if (!Object.hasOwn(commands, cmd))
  fail(
    'usage: sr hunt|finding|report|disclosure|publish (see the header of scripts/sr.mjs)',
  );
await commands[cmd]();
