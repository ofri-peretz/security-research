// Helper the MCP tool shells out to: resolves a hostname and prints the address.
import dns from 'node:dns/promises';
const host = process.argv[2] ?? '';
try { const { address } = await dns.lookup(host); console.log(`${host} -> ${address}`); }
catch { console.log(`could not resolve ${JSON.stringify(process.argv.slice(2).join(' '))}`); }
