// Tiny JSON-over-HTTP helpers shared by the AI-track servers.
export async function readJson(req, limit = 64 * 1024) {
  let body = '';
  for await (const chunk of req) { body += chunk; if (body.length > limit) throw new Error('too large'); }
  return body ? JSON.parse(body) : {};
}
export function sendJson(res, status, obj) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(obj, null, 2));
}
export async function postJson(url, obj) {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify(obj) });
  return { status: r.status, body: await r.json().catch(() => null) };
}
