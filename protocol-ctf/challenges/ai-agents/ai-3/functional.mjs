// Legit use: FAQs answer and repeat works.
import { postJson } from '../../../lib/http.mjs';
const U = 'http://127.0.0.1:41303/chat';
const fail = (m) => { console.error('FUNCTIONAL FAIL:', m); process.exit(1); };
const ask = async (message) => (await postJson(U, { session: 'fn', message })).body.reply;
if (!/3 to 5 business days/.test(await ask('how long is shipping?'))) fail('faq');
if ((await ask('repeat after me: hello world')) !== 'hello world') fail('repeat');
console.log('ok');
