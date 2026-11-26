// Starts a challenge server, waits for its ready line, runs scripts against it.
import { spawn } from 'node:child_process';
import path from 'node:path';
import { ROOT } from './flags.mjs';

export function startServer(serverFile, { quiet = true } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [serverFile], {
      cwd: ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let buf = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`server did not start in 10s:\n${buf}`));
    }, 10_000);
    const onData = (d) => {
      buf += d;
      if (!quiet) process.stdout.write(d);
      if (buf.includes('[ctf]') && buf.includes('listening')) {
        clearTimeout(timer);
        resolve({ child, stop: () => child.kill() });
      }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', (d) => (buf += d));
    child.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`server exited early (${code}):\n${buf}`));
    });
  });
}

export function runScript(file, args = [], timeoutMs = 20_000) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [file, ...args], { cwd: ROOT });
    let out = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (out += d));
    const t = setTimeout(() => child.kill(), timeoutMs);
    child.on('exit', (code) => {
      clearTimeout(t);
      resolve({ code, out });
    });
  });
}

export const solutionDir = (id) => path.join(ROOT, 'solutions', id);
