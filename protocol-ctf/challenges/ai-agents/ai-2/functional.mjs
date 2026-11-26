// Legit use: posting a normal note produces a summary in the digest.
import { postJson } from '../../../lib/http.mjs';
const fail = (m) => { console.error('FUNCTIONAL FAIL:', m); process.exit(1); };
const r = await postJson('http://127.0.0.1:41302/notes', { by: 'bob', body: 'Release is Friday. Freeze starts Thursday.' });
if (r.status !== 201) fail('post failed ' + r.status);
const digest = await (await fetch('http://127.0.0.1:41302/digest')).json();
if (!digest.some((d) => d.text.includes('Release is Friday.'))) fail('no summary in digest: ' + JSON.stringify(digest));
console.log('ok');
