// ws-2 Origin Story: an internal ops console that streams live config over WebSockets.
import http from 'node:http';
import { WebSocketServer } from 'ws';
import { flagFor } from '../../../lib/flags.mjs';
import { HOST, ready } from '../../../lib/serve.mjs';

const PORT = 41102;
const ADMIN_SESSION = crypto.randomUUID(); // only the admin's browser has this cookie
const CONFIG = { region: 'eu-west-1', featureFlags: { newBilling: true }, vaultToken: flagFor('ws-2') };

// "Only our own console page may open the socket." Browsers always send Origin, so this is safe... right?
const TRUSTED_ORIGIN = /^https:\/\/console\.corp\.local/;

const server = http.createServer((req, res) => {
  res.setHeader('content-type', 'text/html');
  res.end(`<h1>Ops console</h1><p>Live config socket: <code>/live</code>.
  Auth: <code>sid</code> session cookie, or requests coming from the console origin.</p>`);
});

const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  if (req.url !== '/live') return socket.destroy();
  const origin = req.headers.origin ?? '';
  const cookie = req.headers.cookie ?? '';
  const hasSession = cookie.split(/;\s*/).includes(`sid=${ADMIN_SESSION}`);
  const fromConsole = TRUSTED_ORIGIN.test(origin);
  if (!hasSession && !fromConsole) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    return socket.destroy();
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    ws.send(JSON.stringify({ type: 'hello', via: hasSession ? 'session' : 'trusted-origin', commands: ['get', 'dump'] }));
    ws.on('message', (raw) => {
      let m; try { m = JSON.parse(raw); } catch { return; }
      if (m.cmd === 'get') ws.send(JSON.stringify({ key: m.key, value: m.key === 'vaultToken' ? '<redacted>' : CONFIG[m.key] }));
      if (m.cmd === 'dump') ws.send(JSON.stringify({ type: 'config', config: CONFIG }));
    });
  });
});

server.listen(PORT, HOST, () => ready('ws-2', `http://${HOST}:${PORT}  (socket: ws://${HOST}:${PORT}/live)`));
