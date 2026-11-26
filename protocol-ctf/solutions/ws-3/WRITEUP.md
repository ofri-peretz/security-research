# ws-3 · Merge Conflict: writeup

**Class:** Prototype pollution (CWE-1321) leading to authorization bypass.

## Exploit
Send as raw text (if you build the object in JS with `{__proto__: ...}` you set the prototype
instead of creating a key):
```json
{"type":"settings.patch","patch":{"__proto__":{"isAdmin":true}}}
{"type":"admin.secrets"}
```

## Why it works
1. `JSON.parse` creates an own property literally named `__proto__`. `Object.keys` returns it.
2. `merge(session.settings, patch)` reaches `target['__proto__']`, which on a plain object is
   `Object.prototype`. It's an object, so `merge` recurses into it and writes `isAdmin = true`
   onto **every object in the process**.
3. `session` has no own `isAdmin`, so `session.isAdmin` walks the prototype chain and finds `true`.

## Disproving the variants (worth knowing)
- `{"constructor":{"prototype":{"isAdmin":true}}}` does **not** work here: `target.constructor` is
  a function, so this `merge` replaces it with `{}` instead of recursing. Other merge
  implementations (lodash < 4.17.12, CVE-2019-10744) do recurse, so always try both.
- `{"isAdmin":true}` lands on `settings`, not `session` (that's `control.mjs`).

## Impact in the real world
Pollution is a *gadget* bug: impact depends on what later reads a missing property. Here it's an
auth flag. Elsewhere it's template options leading to RCE, `child_process` `shell`/`env` options,
or a DoS. In a report, show the full chain, not just "I polluted the prototype".

## Fix
`fixed-server.mjs`: skip `__proto__`, `constructor`, `prototype`, and give `session` an explicit
`isAdmin: false` so authorization state never comes from the prototype chain. Alternatives:
`Object.create(null)` targets, `structuredClone`, schema validation of the patch, or a `Map`.

## Scanner check
**Caught.** `secure-coding/detect-object-injection` (CWE-915) fires on the merge write at line 14.
Good answer-key case for that rule.
