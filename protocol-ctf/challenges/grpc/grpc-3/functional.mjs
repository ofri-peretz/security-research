// Legit use: comparisons with && must still filter correctly, and an empty filter returns everything.
import path from 'node:path';
import { grpc, loadProto } from '../../../lib/grpc.mjs';
const { pkg } = loadProto(path.resolve('challenges/grpc/grpc-3/orders.proto'));
const c = new pkg.orders.Orders('127.0.0.1:41203', grpc.credentials.createInsecure());
const collect = (filter) => new Promise((resolve, reject) => {
  const ids = []; const s = c.Stream({ filter });
  s.on('data', (o) => ids.push(o.id)); s.on('end', () => resolve(ids.join(','))); s.on('error', reject);
});
try {
  const a = await collect('o.total > 50 && o.status == "shipped"');
  const b = await collect('');
  const d = await collect("o.status != 'pending'");
  if (a !== 'o-1,o-3' || b !== 'o-1,o-2,o-3' || d !== 'o-1,o-3') throw new Error(`got ${a} / ${b} / ${d}`);
  console.log('ok'); process.exit(0);
} catch (e) { console.error('FUNCTIONAL FAIL', e.message); process.exit(1); }
