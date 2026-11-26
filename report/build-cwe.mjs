#!/usr/bin/env node
// Builds data/cwe.json from MITRE's catalog (https://cwe.mitre.org/data/xml/cwec_latest.xml.zip,
// unzipped). Keeps only what validation needs: name, abstraction and mapping usage.
//   node report/build-cwe.mjs path/to/cwec_vX.Y.xml
// ponytail: regex over MITRE's regular XML; switch to a real parser if their format changes.
import fs from 'node:fs';
import path from 'node:path';

// eslint-disable-next-line node-security/no-arbitrary-file-access -- dev script; the path is the operator's own CLI argument (plugin FP: CLI args are the intended input)
const xml = fs.readFileSync(process.argv[2], 'utf8');
const version = xml.match(
  /<Weakness_Catalog[^>]*Version="([^"]+)"[^>]*Date="([^"]+)"/,
);
const unescape = (s) =>
  s
    .replace(/&apos;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
const entries = {};
for (const [kind, tag] of [
  ['weakness', 'Weakness'],
  ['category', 'Category'],
  ['view', 'View'],
]) {
  const re = new RegExp(
    `<${tag} ID="(\\d+)" Name="([^"]*)"([^>]*)>([\\s\\S]*?)</${tag}>`,
    'g',
  );
  for (const [, id, name, attrs, body] of xml.matchAll(re)) {
    const usage =
      body.match(/<Mapping_Notes>[\s\S]*?<Usage>([^<]+)<\/Usage>/)?.[1] ??
      (kind === 'weakness' ? 'Allowed' : 'Prohibited');
    // eslint-disable-next-line secure-coding/detect-object-injection -- id is a \d+ regex capture (plugin FP: numeric keys from a regex aren't recognized)
    entries[id] = {
      name: unescape(name),
      kind,
      abstraction: attrs.match(/Abstraction="([^"]+)"/)?.[1] ?? null,
      status: attrs.match(/Status="([^"]+)"/)?.[1] ?? null,
      usage,
    };
  }
}
const out = {
  source: 'MITRE CWE',
  version: version[1],
  date: version[2],
  entries,
};
fs.writeFileSync(
  path.join(import.meta.dirname, 'data', 'cwe.json'),
  JSON.stringify(out) + '\n',
);
console.log(
  `cwe.json: CWE ${version[1]} (${version[2]}), ${Object.keys(entries).length} entries`,
);
