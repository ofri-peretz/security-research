# grpc-1 · Trust the Gateway  (Level 1, 100 XP)

An internal gRPC accounts service (`bank.proto` is next to this file). In production it sits
behind an API gateway. The backend port was left reachable directly (here: `127.0.0.1:41201`).
Your credentials: metadata `authorization: Bearer guest-token`. Your account is `acc-1001`.

**Goal:** read the memo on the treasury account `acc-0001`. Flag: `CTF{grpc-1_...}`.

```bash
node ctf.mjs start grpc-1
```

Clients: [grpcurl](https://github.com/fullstorydev/grpcurl) is the standard tool
(`grpcurl -plaintext -import-path challenges/grpc/grpc-1 -proto bank.proto -H 'authorization: Bearer guest-token' -d '{"account_id":"acc-1001"}' 127.0.0.1:41201 bank.Accounts/GetAccount`),
or `@grpc/grpc-js` in Node (installed here; see `lib/grpc.mjs` for a proto loader).

**What you are learning:** gRPC metadata is just HTTP/2 headers. Services behind a gateway or
service mesh often trust identity headers that only the gateway is supposed to set. Hunters find
this whenever the backend is reachable another way: SSRF, a misrouted path, a debug port, a
sidecar that forwards client headers.
