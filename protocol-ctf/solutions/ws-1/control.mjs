// Negative control: without logging in, join must be refused (proves the bug is authz, not "no auth").
import WebSocket from 'ws';
const ws = new WebSocket('ws://127.0.0.1:41101');
setTimeout(() => process.exit(1), 5000);
ws.on('message', (raw) => {
  const m = JSON.parse(raw);
  if (m.type === 'hello') ws.send(JSON.stringify({ type: 'join', room: 'staff' }));
  if (m.type === 'joined') { console.log('CONTROL FAIL: unauthenticated join worked'); process.exit(1); }
  if (m.type === 'error') { console.log('denied as expected:', m.error); process.exit(0); }
});
