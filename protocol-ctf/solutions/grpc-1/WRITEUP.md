# grpc-1 · Trust the Gateway: writeup

**Class:** Authentication bypass by trusting a spoofable identity header (CWE-290), a.k.a.
"gateway trust" / "header-based auth behind a proxy". OWASP A07:2021.

## Recon
- `GetAccount acc-1001` with the guest token works.
- `GetAccount acc-0001` returns `PERMISSION_DENIED: account belongs to treasury`. The error leaks
  the owner's username, which is exactly the value you need next.

## Exploit
```bash
grpcurl -plaintext -import-path challenges/grpc/grpc-1 -proto bank.proto \
  -H 'x-authenticated-user: treasury' -d '{"account_id":"acc-0001"}' \
  127.0.0.1:41201 bank.Accounts/GetAccount
```

## Why it works
gRPC metadata are HTTP/2 headers. The backend assumes only the gateway can set
`x-authenticated-user`, and the header wins over the bearer token. That holds only if (a) the
backend is unreachable except through the gateway and (b) the gateway strips the header from client
requests. In real targets, (a) fails through SSRF, debug ports, Kubernetes services exposed by
mistake, or another internal service that forwards client headers; (b) fails when a new route is
added to the gateway without the stripping rule.

## Hunting habit
On any gRPC or HTTP API: try `x-user`, `x-user-id`, `x-authenticated-user`, `x-forwarded-user`,
`x-remote-user`, `x-original-user`, `x-envoy-*`, `x-forwarded-for: 127.0.0.1`. Error messages that
name owners or roles are your wordlist.

## Fix
The backend authenticates every call itself. If it needs the gateway's word, the gateway must prove
it: mTLS between gateway and backend, or a short-lived JWT signed by the gateway and verified by the
backend. Also: don't put owner names in `PERMISSION_DENIED` messages.

## Scanner check
**Not caught.** Related rule: `express-security/no-permissive-trust-proxy` (Express `trust proxy`).
**Rule gap:** identity read from `call.metadata.get('x-…user…')` (gRPC) or `req.headers['x-…user…']`
used for authorization without verification.
