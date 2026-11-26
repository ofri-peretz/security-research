import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const GUARD = path.join(import.meta.dirname, 'open-finding-guard.mjs');

function repo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-'));
  const git = (...a) => execFileSync('git', a, { cwd: dir });
  git('init', '-q');
  git('config', 'user.email', 't@example.com');
  git('config', 'user.name', 't');
  git('config', 'commit.gpgsign', 'false');
  const run = (...args) =>
    spawnSync(process.execPath, [GUARD, ...args], {
      cwd: dir,
      encoding: 'utf8',
    });
  const stage = (name, body) => {
    fs.writeFileSync(path.join(dir, name), body);
    git('add', name);
  };
  return {
    dir,
    git,
    run,
    stage,
    cleanup: () => fs.rmSync(dir, { recursive: true, force: true }),
  };
}

test('missing list fails: a guard with nothing to check must not pass', () => {
  const r = repo();
  try {
    r.stage('a.md', 'hello');
    assert.equal(r.run('--staged').status, 1);
  } finally {
    r.cleanup();
  }
});

test('staged content naming an open target is refused, without echoing the term', () => {
  const r = repo();
  try {
    fs.writeFileSync(
      path.join(r.dir, '.open-findings'),
      '# comment\nAcme-Widget\n',
    );
    r.stage('a.md', 'the acme-widget OAuth bug');
    const out = r.run('--staged');
    assert.equal(out.status, 1);
    assert.ok(!out.stderr.toLowerCase().includes('acme-widget'));
  } finally {
    r.cleanup();
  }
});

test('a staged path naming the target is refused', () => {
  const r = repo();
  try {
    fs.writeFileSync(path.join(r.dir, '.open-findings'), 'acme-widget\n');
    r.stage('acme-widget-notes.md', 'nothing here');
    assert.equal(r.run('--staged').status, 1);
  } finally {
    r.cleanup();
  }
});

test('clean content and an empty list both pass', () => {
  const r = repo();
  try {
    fs.writeFileSync(path.join(r.dir, '.open-findings'), 'acme-widget\n');
    r.stage('a.md', 'unrelated');
    assert.equal(r.run('--staged').status, 0);
    fs.writeFileSync(path.join(r.dir, '.open-findings'), '');
    r.stage('b.md', 'acme-widget');
    assert.equal(r.run('--staged').status, 0);
  } finally {
    r.cleanup();
  }
});

test('range mode catches a mention in any pushed commit, including the message', () => {
  const r = repo();
  try {
    fs.writeFileSync(path.join(r.dir, '.open-findings'), 'acme-widget\n');
    r.stage('a.md', 'base');
    r.git('commit', '-qm', 'base');
    r.stage('b.md', 'clean');
    r.git('commit', '-qm', 'fix acme-widget thing');
    assert.equal(r.run('--range', 'HEAD~1..HEAD').status, 1);
  } finally {
    r.cleanup();
  }
});

test('removing a mention is allowed', () => {
  const r = repo();
  try {
    fs.writeFileSync(path.join(r.dir, '.open-findings'), 'acme-widget\n');
    r.stage('a.md', 'acme-widget');
    r.git('commit', '-qm', 'base');
    r.stage('a.md', 'gone');
    assert.equal(r.run('--staged').status, 0);
  } finally {
    r.cleanup();
  }
});
