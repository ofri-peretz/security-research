// Negative control: no cookie and a foreign origin must be refused with 403.
import WebSocket from 'ws';
setTimeout(() => process.exit(1), 5000);
const ws = new WebSocket('ws://127.0.0.1:41102/live', { origin: 'https://evil.example' });
ws.on('unexpected-response', (_q, res) => { console.log('denied as expected:', res.statusCode); process.exit(res.statusCode === 403 ? 0 : 1); });
ws.on('open', () => { console.log('CONTROL FAIL: foreign origin accepted'); process.exit(1); });
