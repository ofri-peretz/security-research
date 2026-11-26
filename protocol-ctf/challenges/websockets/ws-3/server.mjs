// ws-3 Merge Conflict: a realtime game lobby. Players patch their own settings over the socket.
import { WebSocketServer } from 'ws';
import { flagFor } from '../../../lib/flags.mjs';
import { HOST, ready } from '../../../lib/serve.mjs';

const PORT = 41103;
const DEFAULTS = { theme: 'dark', sound: { volume: 5, muted: false }, nickname: 'anon' };

// Deep merge so clients can send partial patches like {"sound":{"volume":7}}
function merge(target, source) {
  for (const key of Object.keys(source)) {
    const value = source[key];
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      if (!target[key] || typeof target[key] !== 'object') target[key] = {};
      merge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

const wss = new WebSocketServer({ host: HOST, port: PORT });
wss.on('connection', (ws) => {
  const session = { user: 'guest', settings: merge({}, DEFAULTS) };
  const send = (m) => ws.send(JSON.stringify(m));
  send({ type: 'hello', you: session.user, commands: ['settings.get', 'settings.patch', 'admin.secrets'] });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return send({ type: 'error', error: 'bad json' }); }
    switch (msg.type) {
      case 'settings.get':
        return send({ type: 'settings', settings: session.settings });
      case 'settings.patch':
        if (typeof msg.patch !== 'object' || msg.patch === null) return send({ type: 'error', error: 'patch must be an object' });
        merge(session.settings, msg.patch);
        return send({ type: 'settings', settings: session.settings });
      case 'admin.secrets':
        if (session.isAdmin !== true) return send({ type: 'error', error: 'admins only' });
        return send({ type: 'secrets', flag: flagFor('ws-3') });
      default:
        return send({ type: 'error', error: 'unknown command' });
    }
  });
});
wss.on('listening', () => ready('ws-3', `ws://${HOST}:${PORT}`));
