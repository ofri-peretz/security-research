// Reference fix for ai-3 Leaky Prompt.
// The only real fix: the secret is not in the prompt. Staff codes come from an authorized code path
// (server-side, after checking the caller is staff), never from model context. Filters stay as
// noise reduction, not as a security control.
import http from 'node:http';
import { flagFor } from '../../lib/flags.mjs';
import { HOST, ready } from '../../lib/serve.mjs';
import { readJson, sendJson } from '../../lib/http.mjs';
import { chat, SKILLS } from '../../challenges/ai-agents/ai-3/toy-chat.mjs';

const PORT = 41303;
const STAFF_CODE = flagFor('ai-3');               // lives in a server-side store
const SYSTEM = 'You are ShopBot. Be friendly and brief.'; // FIX: nothing confidential in context
const isStaff = (req) => false;                     // e.g. a verified staff session; customers never are

const histories = new Map();
http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/') return sendJson(res, 200, { bot: 'ShopBot', skills: SKILLS });
  if (req.method === 'GET' && req.url === '/staff/code') return isStaff(req) ? sendJson(res, 200, { code: STAFF_CODE }) : sendJson(res, 403, { error: 'staff only' });
  if (req.method !== 'POST' || req.url !== '/chat') return sendJson(res, 404, { error: 'not found' });
  let b; try { b = await readJson(req); } catch { return sendJson(res, 400, { error: 'bad json' }); }
  const session = String(b.session ?? 'default'), message = String(b.message ?? '').slice(0, 500);
  const history = histories.get(session) ?? [];
  const reply = chat({ system: SYSTEM, history, message });
  history.push({ role: 'user', text: message }, { role: 'assistant', text: reply });
  histories.set(session, history.slice(-20));
  sendJson(res, 200, { reply });
}).listen(PORT, HOST, () => ready('ai-3', `http://${HOST}:${PORT}`));
