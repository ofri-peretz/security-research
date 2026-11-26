// Legit use: the real console page (exact origin) must still be able to read non-secret config.
import WebSocket from 'ws';
const fail = (m) => { console.error('FUNCTIONAL FAIL:', m); process.exit(1); };
setTimeout(() => fail('timeout'), 5000);
const ws = new WebSocket('ws://127.0.0.1:41102/live', { origin: 'https://console.corp.local' });
ws.on('unexpected-response', (_req, res) => fail(`console origin rejected (${res.statusCode})`));
ws.on('message', (raw) => {
  const m = JSON.parse(raw);
  if (m.type === 'hello') ws.send(JSON.stringify({ cmd: 'get', key: 'region' }));
  if (m.key === 'region') { m.value === 'eu-west-1' ? (console.log('ok'), process.exit(0)) : fail('wrong value'); }
});
