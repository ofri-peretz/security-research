// Flags are derived per install: HMAC(local secret, challenge id).
// Honor rule: don't read .ctf/secret or compute flags yourself. Exploit the service.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const STATE_DIR = path.join(ROOT, '.ctf');
const SECRET_FILE = path.join(STATE_DIR, 'secret');

function secret() {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  if (!fs.existsSync(SECRET_FILE)) {
    fs.writeFileSync(SECRET_FILE, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
  }
  return fs.readFileSync(SECRET_FILE, 'utf8').trim();
}

export function flagFor(id) {
  const mac = crypto.createHmac('sha256', secret()).update(id).digest('hex').slice(0, 20);
  return `CTF{${id}_${mac}}`;
}

export function checkFlag(id, candidate) {
  const want = Buffer.from(flagFor(id));
  const got = Buffer.from(String(candidate ?? '').trim());
  return want.length === got.length && crypto.timingSafeEqual(want, got);
}

export const FLAG_RE = /CTF\{[a-z0-9-]+_[0-9a-f]{20}\}/;
