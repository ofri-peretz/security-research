#!/usr/bin/env node
// Scoreboard CLI. Progress lives in .ctf/progress.json (gitignored, local only).
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { STATE_DIR, checkFlag, flagFor } from './lib/flags.mjs';
import { TRACKS, loadCatalog, findChallenge } from './lib/catalog.mjs';
import { startServer, runScript, solutionDir } from './lib/runner.mjs';

const PROGRESS = path.join(STATE_DIR, 'progress.json');
const HINT_PENALTY = 0.15; // per hint, off the challenge's base XP
const FIX_BONUS = 0.5;     // of base XP, for a fix that blocks the exploit and keeps the feature

const RANKS = [
  [0, 'Recruit'],
  [200, 'Packet Sniffer'],
  [600, 'Frame Smuggler'],
  [1100, 'Protocol Breaker'],
  [1700, 'Exploit Developer'],
  [2300, 'Protocol Wizard'],
];

const c = (code) => (s) => (process.stdout.isTTY ? `\x1b[${code}m${s}\x1b[0m` : s);
const green = c(32), yellow = c(33), dim = c(2), bold = c(1), cyan = c(36);

function load() {
  try { return JSON.parse(fs.readFileSync(PROGRESS, 'utf8')); } catch { return { solves: {}, hints: {}, fixes: {}, log: [] }; }
}
function save(p) {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.writeFileSync(PROGRESS, JSON.stringify(p, null, 2));
}
const base = (ch) => ch.level * 100;
function xpFor(p, ch) {
  let xp = 0;
  if (p.solves[ch.id]) xp += Math.round(base(ch) * (1 - HINT_PENALTY * (p.hints[ch.id] ?? 0)));
  if (p.fixes[ch.id]) xp += Math.round(base(ch) * FIX_BONUS);
  return xp;
}
const totalXp = (p, cat) => cat.reduce((s, ch) => s + xpFor(p, ch), 0);
function rank(xp) {
  let r = RANKS[0], next = null;
  for (const [min, name] of RANKS) { if (xp >= min) r = [min, name]; else { next = [min, name]; break; } }
  return { name: r[1], next };
}
function badges(p, cat) {
  const out = [];
  for (const [track, label] of Object.entries(TRACKS)) {
    const t = cat.filter((x) => x.track === track);
    if (!t.length) continue;
    if (t.every((x) => p.solves[x.id])) out.push(`${label}: cleared`);
    if (t.every((x) => p.solves[x.id] && !(p.hints[x.id] > 0))) out.push(`${label}: no hints`);
    if (t.every((x) => p.fixes[x.id])) out.push(`${label}: patched every bug`);
  }
  if (Object.keys(p.solves).length >= 1) out.unshift('First blood');
  return out;
}

function status() {
  const p = load(), cat = loadCatalog();
  const xp = totalXp(p, cat), r = rank(xp);
  console.log(bold(`\nProtocol CTF  ·  ${xp} XP  ·  ${r.name}`) + (r.next ? dim(`  (${r.next[0] - xp} XP to ${r.next[1]})`) : ''));
  for (const [track, label] of Object.entries(TRACKS)) {
    const t = cat.filter((x) => x.track === track);
    if (!t.length) continue;
    console.log('\n' + cyan(label));
    for (const ch of t) {
      const mark = p.solves[ch.id] ? green('■') : '□';
      const fix = p.fixes[ch.id] ? green(' +fixed') : '';
      const hints = p.hints[ch.id] ? yellow(` ${p.hints[ch.id]} hint(s)`) : '';
      console.log(`  ${mark} ${ch.id.padEnd(7)} L${ch.level} ${ch.title.padEnd(26)} ${dim(ch.tags.join(', '))}${hints}${fix}`);
    }
  }
  const b = badges(p, cat);
  if (b.length) console.log('\n' + bold('Badges: ') + b.join(' · '));
  console.log(dim('\nnode ctf.mjs start <id> · submit <id> <flag> · hint <id> · fix <id> · log\n'));
}

function list() { status(); }

function start(id) {
  const ch = findChallenge(id);
  console.log(bold(`\n${ch.id}: ${ch.title}`) + dim(`  (L${ch.level}, ${base(ch)} XP)`));
  console.log(`Brief: ${path.relative(process.cwd(), path.join(ch.dir, 'README.md'))}\n`);
  const child = spawn(process.execPath, [path.join(ch.dir, 'server.mjs')], { stdio: 'inherit' });
  child.on('error', (err) => { console.error(err.message); process.exit(1); });
  child.on('exit', (code) => process.exit(code ?? 0));
}

function submit(id, flag) {
  const ch = findChallenge(id);
  const p = load();
  if (p.solves[id]) return console.log(dim(`Already solved ${id}.`));
  if (!checkFlag(id, flag)) {
    p.log.push({ at: new Date().toISOString(), id, event: 'wrong-flag' });
    save(p);
    console.log(yellow('Not the flag. Keep going.'));
    process.exitCode = 1;
    return;
  }
  // eslint-disable-next-line secure-coding/detect-object-injection -- id passed findChallenge(), which throws unless it is an exact catalog id (plugin FP: guard is in another function)
  p.solves[id] = new Date().toISOString();
  p.log.push({ at: p.solves[id], id, event: 'solved', hints: p.hints[id] ?? 0 });
  save(p);
  console.log(green(`Correct! +${xpFor(p, ch)} XP.`) + ` Writeup: solutions/${id}/WRITEUP.md`);
  console.log(dim(`Bonus: patch ${path.relative(process.cwd(), path.join(ch.dir, 'server.mjs'))} so the bug is gone, then run: node ctf.mjs fix ${id}`));
  status();
}

function hint(id) {
  const ch = findChallenge(id);
  const hints = JSON.parse(fs.readFileSync(path.join(ch.dir, 'hints.json'), 'utf8'));
  const p = load();
  const used = p.hints[id] ?? 0;
  if (used >= hints.length) {
    hints.forEach((h, i) => console.log(`${i + 1}. ${h}`));
    return console.log(dim('No more hints. The writeup is in solutions/.'));
  }
  // eslint-disable-next-line secure-coding/detect-object-injection -- id passed findChallenge(), which throws unless it is an exact catalog id (plugin FP: guard is in another function)
  if (!p.solves[id]) p.hints[id] = used + 1; // hints after solving are free
  p.log.push({ at: new Date().toISOString(), id, event: 'hint', n: used + 1 });
  save(p);
  for (let i = 0; i <= used; i++) console.log(`${i + 1}. ${hints[i]}`);
  if (!p.solves[id]) console.log(yellow(`(-${Math.round(HINT_PENALTY * 100)}% XP on ${id})`));
}

async function fix(id) {
  const ch = findChallenge(id);
  const server = path.join(ch.dir, 'server.mjs');
  console.log(`Checking your patched ${path.relative(process.cwd(), server)} ...`);
  let srv;
  try { srv = await startServer(server); } catch (e) { console.log(yellow(e.message)); process.exitCode = 1; return; }
  try {
    const fn = await runScript(path.join(ch.dir, 'functional.mjs'));
    if (fn.code !== 0) {
      console.log(yellow('Functional check failed: your fix broke the legitimate feature.\n') + dim(fn.out));
      process.exitCode = 1; return;
    }
    const ex = await runScript(path.join(solutionDir(id), 'exploit.mjs'));
    if (ex.out.includes(flagFor(id))) {
      console.log(yellow('The reference exploit still gets the flag. Not fixed yet.'));
      process.exitCode = 1; return;
    }
    const p = load();
    const first = !p.fixes[id];
    // eslint-disable-next-line secure-coding/detect-object-injection -- id passed findChallenge(), which throws unless it is an exact catalog id (plugin FP: guard is in another function)
    p.fixes[id] = new Date().toISOString();
    p.log.push({ at: p.fixes[id], id, event: 'fixed' });
    save(p);
    console.log(green(`Fixed: feature works and the exploit is blocked.${first ? ` +${Math.round(base(ch) * FIX_BONUS)} XP.` : ''}`));
    console.log(dim(`Compare with solutions/${id}/fixed-server.mjs. Variants of the exploit may still work: try them.`));
  } finally { srv.stop(); }
}

function log() {
  for (const e of load().log) console.log(`${e.at}  ${e.id.padEnd(7)} ${e.event}${e.n ? ' #' + e.n : ''}`);
}

const [cmd, ...args] = process.argv.slice(2);
const need = (n) => { if (args.length < n) { console.log('Missing arguments. Try: node ctf.mjs help'); process.exit(1); } };
switch (cmd) {
  case undefined: case 'status': status(); break;
  case 'list': list(); break;
  case 'start': need(1); start(args[0]); break;
  case 'submit': need(2); submit(args[0], args[1]); break;
  case 'hint': need(1); hint(args[0]); break;
  case 'fix': need(1); await fix(args[0]); break;
  case 'log': log(); break;
  default:
    console.log('Usage: node ctf.mjs [status|list|start <id>|submit <id> <flag>|hint <id>|fix <id>|log]');
}
