// ws-1 Eavesdrop: a team chat over WebSockets.
import { WebSocketServer } from 'ws';
import crypto from 'node:crypto';
import { flagFor } from '../../lib/flags.mjs';
import { HOST, ready } from '../../lib/serve.mjs';

const PORT = 41101;
const USERS = { guest: { password: 'guest', rooms: ['lobby'] }, alice: { password: crypto.randomUUID(), rooms: ['lobby', 'staff'] } };
const HISTORY = {
  lobby: [{ from: 'alice', text: 'Welcome! Be nice.' }],
  staff: [{ from: 'alice', text: `Rotated the deploy key: ${flagFor('ws-1')}` }],
};
const sessions = new Map(); // token -> username
const wss = new WebSocketServer({ host: HOST, port: PORT });

function broadcast(room, msg) {
  for (const client of wss.clients) if (client.rooms?.has(room)) client.send(JSON.stringify(msg));
}

wss.on('connection', (ws) => {
  ws.rooms = new Set();
  const send = (m) => ws.send(JSON.stringify(m));
  send({ type: 'hello', protocol: 'chat/1', commands: ['login', 'rooms', 'join', 'say'] });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return send({ type: 'error', error: 'bad json' }); }

    if (msg.type === 'login') {
      const u = USERS[msg.user];
      if (!u || u.password !== msg.password) return send({ type: 'error', error: 'bad credentials' });
      const token = crypto.randomBytes(16).toString('hex');
      sessions.set(token, msg.user);
      ws.user = msg.user;
      send({ type: 'welcome', user: msg.user, token });
      // Presence: tell everyone where alice hangs out (she's always online)
      send({ type: 'presence', user: 'alice', status: 'online' }); // don't leak other users' rooms
      return;
    }
    if (!ws.user) return send({ type: 'error', error: 'login first' });

    if (msg.type === 'rooms') return send({ type: 'rooms', rooms: USERS[ws.user].rooms });

    if (msg.type === 'join') {
      if (!HISTORY[msg.room]) return send({ type: 'error', error: 'no such room' });
      if (!USERS[ws.user].rooms.includes(msg.room)) return send({ type: 'error', error: 'not a member' });
      ws.rooms.add(msg.room);
      send({ type: 'joined', room: msg.room, history: HISTORY[msg.room] });
      return;
    }

    if (msg.type === 'say') {
      if (!USERS[ws.user].rooms.includes(msg.room)) return send({ type: 'error', error: 'not a member' });
      const m = { from: ws.user, text: String(msg.text).slice(0, 500) };
      HISTORY[msg.room].push(m);
      broadcast(msg.room, { type: 'message', room: msg.room, ...m });
      return;
    }
    send({ type: 'error', error: 'unknown command' });
  });
});

wss.on('listening', () => ready('ws-1', `ws://${HOST}:${PORT}`));
