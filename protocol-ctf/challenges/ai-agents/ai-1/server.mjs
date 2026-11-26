// ai-1 Tool Time: an MCP server (JSON-RPC over HTTP) that gives an AI assistant network tools.
import http from 'node:http';
import path from 'node:path';
import { exec } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { flagFor } from '../../../lib/flags.mjs';
import { HOST, ready } from '../../../lib/serve.mjs';
import { readJson, sendJson } from '../../../lib/http.mjs';

const PORT = 41301;
const LOOKUP = path.join(path.dirname(fileURLToPath(import.meta.url)), 'lookup.mjs');
process.env.OPS_API_TOKEN = flagFor('ai-1'); // the server's own credential, as in any real deployment

const TOOLS = [{
  name: 'dns_check',
  description: 'Resolve a hostname to check that a service is reachable.',
  inputSchema: { type: 'object', properties: { hostname: { type: 'string' } }, required: ['hostname'] },
}];

// "Sanitize" the hostname so the model can't chain commands.
const BLOCKED = /[;&|<>]/;

function dnsCheck(hostname) {
  return new Promise((resolve) => {
    if (BLOCKED.test(hostname)) return resolve('rejected: hostname contains forbidden characters');
    exec(`node "${LOOKUP}" ${hostname}`, { timeout: 5000 }, (err, stdout, stderr) => resolve((stdout || stderr || String(err)).trim()));
  });
}

async function rpc(msg) {
  switch (msg.method) {
    case 'initialize':
      return { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'netops-mcp', version: '1.4.2' } };
    case 'tools/list':
      return { tools: TOOLS };
    case 'tools/call': {
      const { name, arguments: args = {} } = msg.params ?? {};
      if (name !== 'dns_check') throw Object.assign(new Error('unknown tool'), { code: -32602 });
      return { content: [{ type: 'text', text: await dnsCheck(String(args.hostname ?? '')) }] };
    }
    default:
      throw Object.assign(new Error('method not found'), { code: -32601 });
  }
}

http.createServer(async (req, res) => {
  if (req.method !== 'POST' || req.url !== '/mcp') return sendJson(res, 404, { error: 'POST JSON-RPC to /mcp' });
  let msg;
  try { msg = await readJson(req); } catch { return sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }); }
  try { sendJson(res, 200, { jsonrpc: '2.0', id: msg.id ?? null, result: await rpc(msg) }); }
  catch (e) { sendJson(res, 200, { jsonrpc: '2.0', id: msg.id ?? null, error: { code: e.code ?? -32603, message: e.message } }); }
}).listen(PORT, HOST, () => ready('ai-1', `http://${HOST}:${PORT}/mcp  (MCP, JSON-RPC over HTTP)`));
