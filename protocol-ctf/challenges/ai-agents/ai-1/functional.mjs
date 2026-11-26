// Legit use: tools/list works and dns_check resolves localhost.
import { postJson } from '../../../lib/http.mjs';
const U = 'http://127.0.0.1:41301/mcp';
const fail = (m) => { console.error('FUNCTIONAL FAIL:', m); process.exit(1); };
const list = await postJson(U, { jsonrpc: '2.0', id: 1, method: 'tools/list' });
if (list.body?.result?.tools?.[0]?.name !== 'dns_check') fail('tools/list');
const call = await postJson(U, { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'dns_check', arguments: { hostname: 'localhost' } } });
const text = call.body?.result?.content?.[0]?.text ?? '';
if (!/^localhost -> /.test(text)) fail('dns_check localhost: ' + text);
console.log('ok');
