// Negative control: setting isAdmin directly in your own settings must NOT work (it lands on settings, not session).
import WebSocket from 'ws';
const ws = new WebSocket('ws://127.0.0.1:41103');
setTimeout(() => process.exit(1), 5000);
ws.on('message', (raw) => {
  const m = JSON.parse(raw);
  if (m.type === 'hello') { ws.send('{"type":"settings.patch","patch":{"isAdmin":true}}'); ws.send('{"type":"admin.secrets"}'); }
  if (m.type === 'secrets') { console.log('CONTROL FAIL'); process.exit(1); }
  if (m.type === 'error') { console.log('denied as expected:', m.error); process.exit(0); }
});
