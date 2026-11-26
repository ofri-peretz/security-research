// Legit use: guest reads own account with a bearer token; guest is denied the treasury account.
import path from 'node:path';
import { grpc, loadProto } from '../../../lib/grpc.mjs';
const { pkg } = loadProto(path.resolve('challenges/grpc/grpc-1/bank.proto'));
const c = new pkg.bank.Accounts('127.0.0.1:41201', grpc.credentials.createInsecure());
const md = new grpc.Metadata(); md.set('authorization', 'Bearer guest-token');
const fail = (m) => { console.error('FUNCTIONAL FAIL:', m); process.exit(1); };
c.GetAccount({ account_id: 'acc-1001' }, md, (err, acc) => {
  if (err || acc.memo !== 'Coffee fund') return fail(err?.message ?? 'wrong account');
  c.GetAccount({ account_id: 'acc-0001' }, md, (err2) => {
    if (!err2) return fail('guest read treasury');
    console.log('ok'); process.exit(0);
  });
});
