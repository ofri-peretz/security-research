# grpc-3 · Stream Filter: writeup

**Class:** Code injection via dynamic evaluation (CWE-95), OWASP A03:2021 Injection.

## Exploit
```json
{"filter": "(o.note = process.env.PAYMENTS_SIGNING_KEY, true)"}
```
Every streamed order comes back with the key in `note`.

## Why it works
`new Function('o', 'return (' + filter + ');')` is `eval` with extra steps. The character "allowlist"
allows everything an expression needs, and expressions can do anything: the comma operator chains
side effects, assignment writes into the row object, and `process` is in scope. The trick that turns
"code runs" into "data comes back" is choosing an output channel you already have: a response field.

## Disproving the variants
- `true; process.exit()` is rejected: `;` isn't in the allowlist (`control.mjs`). So you can't
  write statements, only expressions. Expressions are enough.
- `'${...}'` in single quotes is just a string, so nothing leaks. Backticks are allowed, so a real
  template literal does run code, but it still needs an output channel, like the `note` field.
- `o.status == "x" || 1 == 1` shows filter-logic injection (returns all rows) even without code
  execution. In a real target with per-user rows, that alone is a BOLA.

## Real-world shape
Report builders, rule engines, "advanced search", feature-flag targeting, Mongo `$where`,
`vm.runInNewContext` used as a "sandbox" (it isn't one), and template engines. In a pen-test report,
prove impact with a harmless read (an env var name, `process.version`), never a destructive payload.

## Fix
Parse a small grammar into data and evaluate it against an allowlist of fields (see
`fixed-server.mjs`). Or use a vetted expression library with no access to the host environment, run
out of process.

## Scanner check
**Caught.** `node-security/detect-eval-with-expression` fires on `new Function(...)` at line 31.
