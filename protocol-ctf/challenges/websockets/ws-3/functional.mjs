// Legit use: nested partial patches must still merge, and non-admins still can't read secrets.
import WebSocket from 'ws';
const ws = new WebSocket('ws://127.0.0.1:41103');
const fail = (m) => { console.error('FUNCTIONAL FAIL:', m); process.exit(1); };
setTimeout(() => fail('timeout'), 5000);
let step = 0;
ws.on('message', (raw) => {
  const m = JSON.parse(raw);
  if (m.type === 'hello') ws.send(JSON.stringify({ type: 'settings.patch', patch: { sound: { volume: 7 }, nickname: 'neo' } }));
  if (m.type === 'settings' && step++ === 0) {
    const s = m.settings;
    if (s.sound.volume !== 7 || s.sound.muted !== false || s.nickname !== 'neo' || s.theme !== 'dark') fail('merge broken: ' + JSON.stringify(s));
    ws.send(JSON.stringify({ type: 'admin.secrets' }));
  }
  if (m.type === 'secrets') fail('guest read secrets');
  if (m.type === 'error' && m.error === 'admins only') { console.log('ok'); process.exit(0); }
});
