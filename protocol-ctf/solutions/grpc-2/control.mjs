// Negative control: a made-up method path must be UNIMPLEMENTED (the server isn't just echoing).
import { grpc } from '../../lib/grpc.mjs';
const client = new grpc.Client('127.0.0.1:41202', grpc.credentials.createInsecure());
client.makeUnaryRequest('/ops.Maintenance/DropEverything', (b) => b, (b) => b, Buffer.alloc(0), (err) => {
  if (err?.code === grpc.status.UNIMPLEMENTED) { console.log('denied as expected'); process.exit(0); }
  console.log('CONTROL FAIL', err?.code); process.exit(1);
});
