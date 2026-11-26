// Reference fix for grpc-3 Stream Filter: never compile user input into code.
// Parse a tiny filter grammar into data, then evaluate that data against an allowlist of fields.
import path from 'node:path';
import { grpc, loadProto, bind } from '../../lib/grpc.mjs';
import { flagFor } from '../../lib/flags.mjs';

const { pkg } = loadProto(path.resolve('challenges/grpc/grpc-3/orders.proto'));
const PORT = 41203;
process.env.PAYMENTS_SIGNING_KEY = flagFor('grpc-3');

const ORDERS = [
  { id: 'o-1', status: 'shipped', total: 79.5, note: '' },
  { id: 'o-2', status: 'pending', total: 12.0, note: '' },
  { id: 'o-3', status: 'shipped', total: 240.0, note: 'gift wrap' },
];
const FIELDS = new Set(['id', 'status', 'total']);
const OPS = { '==': (a, b) => a === b, '!=': (a, b) => a !== b, '>': (a, b) => a > b, '<': (a, b) => a < b, '>=': (a, b) => a >= b, '<=': (a, b) => a <= b };
// clause := o.<field> <op> <number | "string" | 'string'> ; filter := clause (&& clause)*
const CLAUSE = /^\s*o\.(\w+)\s*(==|!=|>=|<=|>|<)\s*(-?\d+(?:\.\d+)?|"[^"]*"|'[^']*')\s*$/;

function parse(filter) {
  if (!filter.trim()) return [];
  return filter.split('&&').map((part) => {
    const m = CLAUSE.exec(part);
    if (!m || !FIELDS.has(m[1])) throw new Error('invalid filter');
    const value = /^["']/.test(m[3]) ? m[3].slice(1, -1) : Number(m[3]);
    return { field: m[1], op: OPS[m[2]], value };
  });
}

const server = new grpc.Server();
server.addService(pkg.orders.Orders.service, {
  Stream(call) {
    let clauses;
    try { clauses = parse(String(call.request.filter ?? '')); }
    catch { call.emit('error', { code: grpc.status.INVALID_ARGUMENT, details: 'invalid filter' }); return; }
    for (const order of ORDERS) if (clauses.every((c) => c.op(order[c.field], c.value))) call.write(order);
    call.end();
  },
});
bind(server, 'grpc-3', PORT);
