// Negative control: the character allowlist must reject a semicolon statement.
import path from 'node:path';
import { grpc, loadProto } from '../../lib/grpc.mjs';
const { pkg } = loadProto(path.resolve('challenges/grpc/grpc-3/orders.proto'));
const c = new pkg.orders.Orders('127.0.0.1:41203', grpc.credentials.createInsecure());
setTimeout(() => { console.log('CONTROL FAIL: timeout'); process.exit(1); }, 5000);
const s = c.Stream({ filter: 'true; process.exit()' });
s.on('data', () => {});
s.on('error', (e) => { console.log('denied as expected:', e.details); process.exit(e.code === grpc.status.INVALID_ARGUMENT ? 0 : 1); });
s.on('end', () => { console.log('CONTROL FAIL'); process.exit(1); });
