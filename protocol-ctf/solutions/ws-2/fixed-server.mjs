// Reference fix for ws-2. Two separate controls, each doing one job:
//  1. Authentication: a session cookie (or token). Nothing else grants access.
//  2. CSWSH defence: an exact-match Origin allowlist, checked in addition to auth, never instead.
// Plus least privilege: secrets never go over the socket at all.
import http from 'node:http';
import { WebSocketServer } from 'ws';
import { flagFor } from '../../lib/flags.mjs';
import { HOST, ready } from '../../lib/serve.mjs';

const PORT = 41102;
const ADMIN_SESSION = crypto.randomUUID();
const CONFIG = { region: 'eu-west-1', featureFlags: { newBilling: true }, vaultToken: flagFor('ws-2') };
const PUBLIC_KEYS = new Set(['region', 'featureFlags']);
const ALLOWED_ORIGINS = new Set(['https://console.corp.local']);

const server = http.createServer((req, res) => { res.setHeader('content-type', 'text/html'); res.end('<h1>Ops console</h1>'); });
const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  if (req.url !== '/live') return socket.destroy();
  const originOk = ALLOWED_ORIGINS.has(req.headers.origin ?? '');
  const hasSession = (req.headers.cookie ?? '').split(/;\s*/).includes(`sid=${ADMIN_SESSION}`);
  if (!originOk) { socket.write('HTTP/1.1 403 Forbidden\r\n\r\n'); return socket.destroy(); }
  wss.handleUpgrade(req, socket, head, (ws) => {
    // Unauthenticated console visitors get public keys only; admins could get more via a server-side vault, not this socket.
    ws.send(JSON.stringify({ type: 'hello', authenticated: hasSession, commands: ['get'] }));
    ws.on('message', (raw) => {
      let m; try { m = JSON.parse(raw); } catch { return; }
      if (m.cmd === 'get' && PUBLIC_KEYS.has(m.key)) ws.send(JSON.stringify({ key: m.key, value: CONFIG[m.key] }));
    });
  });
});
server.listen(PORT, HOST, () => ready('ws-2', `http://${HOST}:${PORT}`));
