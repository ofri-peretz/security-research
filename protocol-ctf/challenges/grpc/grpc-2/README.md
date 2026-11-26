# grpc-2 · Hidden Methods  (Level 2, 200 XP)

**Black-box challenge: don't read `server.mjs`.** You only get what the vendor gives customers:
`catalog.proto`, a product search API at `127.0.0.1:41202`.

**Goal:** find what else this server can do, and pull a production API key out of it.
Flag: `CTF{grpc-2_...}`.

```bash
node ctf.mjs start grpc-2
```

Tools: `grpcurl` is ideal here. If you don't have it, Node can do everything too: reflection is
just another gRPC service (`grpc.reflection.v1.ServerReflection`), and its proto ships inside
`node_modules/@grpc/reflection/build/proto/`. You can also call any method path with
`client.makeUnaryRequest(path, serialize, deserialize, ...)` using raw bytes.

**What you are learning:** "undocumented" is not "unauthenticated". gRPC server reflection,
GraphQL introspection and OpenAPI files left on prod servers all hand an attacker the full API
map. In recon, this is the first thing to try against any gRPC port.
