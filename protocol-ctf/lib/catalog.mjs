import fs from 'node:fs';
import path from 'node:path';
import { ROOT } from './flags.mjs';

export const TRACKS = {
  websockets: 'WebSockets',
  grpc: 'gRPC',
  'ai-agents': 'AI agents & MCP (OWASP LLM Top 10)',
};

export function loadCatalog() {
  const out = [];
  for (const track of Object.keys(TRACKS)) {
    const dir = path.join(ROOT, 'challenges', track);
    if (!fs.existsSync(dir)) continue;
    for (const name of fs.readdirSync(dir).sort()) {
      const file = path.join(dir, name, 'challenge.json');
      if (!fs.existsSync(file)) continue;
      const meta = JSON.parse(fs.readFileSync(file, 'utf8'));
      out.push({ ...meta, track, dir: path.join(dir, name) });
    }
  }
  return out;
}

export function findChallenge(id) {
  const c = loadCatalog().find((x) => x.id === id);
  if (!c) throw new Error(`Unknown challenge "${id}". Run: node ctf.mjs list`);
  return c;
}
