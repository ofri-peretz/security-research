// Negative control: no credentials at all must be UNAUTHENTICATED.
import path from 'node:path';
import { grpc, loadProto } from '../../lib/grpc.mjs';
const { pkg } = loadProto(path.resolve('challenges/grpc/grpc-1/bank.proto'));
const c = new pkg.bank.Accounts('127.0.0.1:41201', grpc.credentials.createInsecure());
c.GetAccount({ account_id: 'acc-0001' }, new grpc.Metadata(), (err) => {
  if (err?.code === grpc.status.UNAUTHENTICATED) { console.log('denied as expected'); process.exit(0); }
  console.log('CONTROL FAIL', err?.code); process.exit(1);
});
