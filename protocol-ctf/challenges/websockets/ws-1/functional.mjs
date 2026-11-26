// Legit use must keep working after your fix: guest logs in, joins lobby, sees history, can talk.
import WebSocket from 'ws';
const ws = new WebSocket('ws://127.0.0.1:41101');
const fail = (m) => { console.error('FUNCTIONAL FAIL:', m); process.exit(1); };
setTimeout(() => fail('timeout'), 5000);
const steps = [];
ws.on('message', (raw) => {
  const m = JSON.parse(raw);
  steps.push(m.type);
  if (m.type === 'hello') ws.send(JSON.stringify({ type: 'login', user: 'guest', password: 'guest' }));
  if (m.type === 'welcome') ws.send(JSON.stringify({ type: 'join', room: 'lobby' }));
  if (m.type === 'joined') {
    if (!m.history?.length) fail('lobby history missing');
    ws.send(JSON.stringify({ type: 'say', room: 'lobby', text: 'hi' }));
  }
  if (m.type === 'message' && m.text === 'hi') { console.log('ok'); process.exit(0); }
  if (m.type === 'error') fail(m.error);
});
