# How httpsig compares

An honest comparison against the other RFC 9421 implementations. **Methodology:**
competitor capabilities are taken from their published READMEs/docs — *documented*
claims, not an independent audit. httpsig's behavior is covered by the test suite
in `test/` (sign/verify round-trips, tampered components, wrong keys, expiry).

| | **httpsig** (`httpsig-js` on npm) | **node-http-message-signatures** | **dadrus/httpsig** | **yaronf/httpsign** | **pyauth/http-message-signatures** |
|---|---|---|---|---|---|
| Language | TypeScript | TypeScript | Go | Go | Python |
| Runtime | Any WebCrypto: Node, Workers, browsers, Deno, Bun | Node | Go | Go | Python 3 |
| Crypto | WebCrypto only (`crypto.subtle`) | Node crypto | Go crypto | Go crypto | Python crypto |
| Algorithms | `ecdsa-p256-sha256`, `ed25519` | broader (RSA-PSS, HMAC, etc.) | broad, incl. RFC 9651 types | full RFC coverage | broad |
| Input model | `fetch` `Request`/`Response` | Node `http` messages | framework-agnostic `Message` iface | Go `net/http` + raw | `httpx`-style messages |
| Dependencies | zero | some | Go stdlib | Go stdlib | several |
| Structured Fields | built-in minimal impl | own impl | own impl (RFC 8941+9651) | own impl | own impl |
| Policies / negotiation | manual | manual | ✅ policy engine, `Accept-Signature` | manual | manual |
| Test vectors | round-trip + tamper tests | — | — | ✅ official RFC vectors | — |

## Where httpsig is genuinely different

1. **It runs wherever `fetch` runs.** WebCrypto-only means the same code signs
   requests in a Cloudflare Worker, a browser, Deno, Bun, or Node — no Node
   `http` module, no Go runtime, no Python. For agent-to-agent auth where the
   signer might be an edge worker, that's the difference between usable and
   not.

2. **Zero dependencies, dual ESM+CJS.** No structured-fields package, no crypto
   shim — the whole thing is a few hundred lines you can audit in an afternoon.

3. **`fetch`-native API.** Sign a `Request`, verify a `Request`/`Response` — the
   same objects your HTTP client already produces. No adapter layer between your
   code and the wire format.

## Where it is NOT the right tool

- **You need RSA-PSS, HMAC, or the full RFC 9421 algorithm registry** → use
  `node-http-message-signatures` or `dadrus/httpsig`.
- **You need policy-driven verification** (covered-component sets, tag
  requirements, `Accept-Signature` negotiation) → `dadrus/httpsig`'s policy
  engine is more complete.
- **You need conformance proven against the official RFC test vectors** →
  `yaronf/httpsign` (Go) is the reference-grade implementation.
- **You're in Python or Rust** → `pyauth/http-message-signatures` or
  `httpsig-rs`.

httpsig deliberately covers the two algorithms agent auth actually uses
(ECDSA P-256 and Ed25519) and nothing else — a smaller surface to audit, at the
cost of breadth.
