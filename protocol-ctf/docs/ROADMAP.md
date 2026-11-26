# Roadmap

Shipped (v0.1): WebSockets, gRPC, AI agents & MCP. 9 challenges.

## Proposed next track: GraphQL

Clearest bug classes of the remaining protocols, very common in paid programs, and it reuses
skills from this release (introspection is grpc-2's reflection; resolvers are ws-1's per-message
authorization).

- gql-1 Introspection recon and a hidden admin mutation
- gql-2 BOLA through a nested resolver (`user { orders { ... } }` skips the owner check)
- gql-3 Batching / alias abuse to bypass a login rate limit (safe local brute force of a 3-digit PIN)
- gql-4 (stretch) CSRF on a GraphQL endpoint that accepts GET or `text/plain`

## Later tracks

- **Message queues (AMQP / Kafka / Redis pub-sub):** unauthenticated consumers, poisoned messages that
  reach unsafe deserialization, tenant isolation via topic names. Needs a broker: Docker or an
  in-process fake.
- **Streaming (HLS / RTMP / WebRTC):** HLS playlist SSRF and path traversal in segment URLs, signed URL
  bypass, WebRTC TURN abuse and ICE candidate IP leaks, RTMP stream-key guessing.
- **AI agents, round 2:** MCP tool poisoning (malicious tool descriptions), rug-pull tool updates,
  confused-deputy OAuth in MCP, and an optional real-model mode (bring your own API key) to feel how
  probabilistic injection behaves.
- **Networking basics:** HTTP request smuggling (CL.TE) against a toy proxy pair, DNS rebinding
  against a localhost dev server, SSRF to a fake cloud metadata service.
