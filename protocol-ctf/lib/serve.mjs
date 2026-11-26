// Every challenge binds to loopback only. Never expose these services.
export const HOST = '127.0.0.1';
export function ready(id, url) {
  console.log(`[ctf] ${id} listening on ${url}  (Ctrl+C to stop)`);
}
