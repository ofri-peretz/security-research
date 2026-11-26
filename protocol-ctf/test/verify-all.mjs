// Maintainer check: for every challenge, prove the lab is real and the reference fix is real.
//  vulnerable server: functional passes, negative control is denied, exploit returns the exact flag
//  fixed server:      functional passes, exploit no longer returns the flag
import path from 'node:path';
import { loadCatalog } from '../lib/catalog.mjs';
import { flagFor } from '../lib/flags.mjs';
import { startServer, runScript, solutionDir } from '../lib/runner.mjs';

const only = process.argv[2];
let failures = 0;
const check = (ok, label, out = '') => {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}`);
  if (!ok) { failures++; if (out) console.log(out.split('\n').map((l) => '        ' + l).join('\n')); }
};

for (const ch of loadCatalog().filter((c) => !only || c.id === only)) {
  console.log(`\n${ch.id} ${ch.title}`);
  const flag = flagFor(ch.id);
  const sol = solutionDir(ch.id);
  for (const [variant, server] of [['vulnerable', path.join(ch.dir, 'server.mjs')], ['fixed', path.join(sol, 'fixed-server.mjs')]]) {
    let srv;
    try { srv = await startServer(server); } catch (e) { check(false, `${variant}: server starts`, e.message); continue; }
    try {
      const fn = await runScript(path.join(ch.dir, 'functional.mjs'));
      check(fn.code === 0, `${variant}: functional check passes`, fn.out);
      if (variant === 'vulnerable') {
        const ctl = await runScript(path.join(sol, 'control.mjs'));
        check(ctl.code === 0, 'vulnerable: negative control is denied', ctl.out);
      }
      const ex = await runScript(path.join(sol, 'exploit.mjs'));
      const got = ex.out.includes(flag);
      check(variant === 'vulnerable' ? got : !got, `${variant}: exploit ${variant === 'vulnerable' ? 'returns the flag' : 'is blocked'}`, ex.out);
    } finally { srv.stop(); await new Promise((r) => setTimeout(r, 300)); }
  }
}
console.log(failures ? `\n${failures} check(s) failed` : '\nAll checks passed');
process.exit(failures ? 1 : 0);
