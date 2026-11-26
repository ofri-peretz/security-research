// Legit use: product search must keep working.
import path from 'node:path';
import { grpc, loadProto } from '../../../lib/grpc.mjs';
const { pkg } = loadProto(path.resolve('challenges/grpc/grpc-2/catalog.proto'));
const c = new pkg.shop.Catalog('127.0.0.1:41202', grpc.credentials.createInsecure());
c.Search({ query: 'mouse' }, (err, res) => {
  if (err || res.products.length !== 1 || res.products[0].sku !== 'MS-02') { console.error('FUNCTIONAL FAIL', err?.message); process.exit(1); }
  console.log('ok'); process.exit(0);
});
