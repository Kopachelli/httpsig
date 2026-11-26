# httpsig

HTTP Message Signatures ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)) — sign and verify `fetch` Requests with WebCrypto. Zero dependencies.

This is the authentication primitive the **MCP authorization spec** and the emerging agent-to-agent HTTP auth drafts are standardizing on. If your agents call each other's APIs, this is how they prove who's asking.

```ts
import { sign, verify } from 'httpsig';

// Signer
const { privateKey, publicKey } = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
);

const req = new Request('https://api.example.com/v1/agents/run', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: '{"task":"summarize"}',
});
const { signatureInput, signature } = await sign(req, privateKey, {
  components: ['@method', '@authority', '@path', 'content-digest'],
  keyid: 'agent-7',
});
req.headers.set('Signature-Input', signatureInput);
req.headers.set('Signature', signature);
await fetch(req);

// Verifier
const result = await verify(req, { publicKey });
// { ok: true, label: 'sig1', keyid: 'agent-7', params: {...} }
```

## What's covered

- **Derived components**: `@method`, `@authority`, `@scheme`, `@request-target`, `@path`, `@query`, `@query-param;name="x"`, `@target-uri`
- **Header components**: any header, lowercased, repeated fields combined per RFC
- **`content-digest`**: auto-computed on sign when covered; **re-verified against the actual body on verify** — a tampered body with a stale digest fails
- **Signature params**: `created`, `expires`, `nonce`, `alg`, `keyid`, `tag` with clock-skew checks
- **Algorithms**: `ecdsa-p256-sha256` (ES256) and `ed25519` via WebCrypto — Node ≥ 20, browsers, Workers

## Honest limits

- Single-message signatures only — no replay caches. If you accept signatures across requests, add your own nonce/replay store (the `nonce` param is there for it).
- `@status` (response signing) is parsed but response-side signing isn't implemented yet.
- Multiple signature labels are all verified; `ok:true` requires every label to pass.

## API

```ts
sign(request, privateKey, { components?, label?, keyid?, alg?, created?, expires?, nonce?, tag? })
  → { signatureInput, signature, signingString }

verify(request, { publicKey, skewSec?, now? })
  → { ok:true, label, keyid, params } | { ok:false, label?, reason }
```

`publicKey` accepts a `CryptoKey`, `JsonWebKey`, raw bytes, or `{ key, alg }`.

## Install

```sh
npm install httpsig
```
