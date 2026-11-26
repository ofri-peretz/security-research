// Negative control: the denylist really does block ; chaining (so the bypass is the finding, not a missing filter).
import { postJson } from '../../lib/http.mjs';
const r = await postJson('http://127.0.0.1:41301/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'dns_check', arguments: { hostname: 'x; printenv OPS_API_TOKEN' } } });
const t = r.body?.result?.content?.[0]?.text ?? '';
console.log(t);
process.exit(t.startsWith('rejected') ? 0 : 1);
