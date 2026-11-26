import { signingString as buildBase } from './sign.js';
import { b64decode, b64encode, parseDictionaryHeader, parseSignatureParams } from './components.js';
import type { VerifyOptions, VerifyResult, SigAlg } from './types.js';

async function importKey(
  material: VerifyOptions['publicKey'],
  alg: SigAlg | undefined,
): Promise<CryptoKey> {
  type KeyMaterial = { key: CryptoKey | JsonWebKey | Uint8Array; alg?: SigAlg };
  const m: KeyMaterial =
    material && typeof material === 'object' && 'key' in material
      ? (material as KeyMaterial)
      : { key: material as CryptoKey | JsonWebKey | Uint8Array };
  const effectiveAlg = m.alg ?? alg ?? 'ecdsa-p256-sha256';
  if (m.key instanceof CryptoKey) return m.key;
  if (m.key instanceof Uint8Array) {
    // Raw public key bytes: assume EC P-256 uncompressed point or Ed25519 raw.
    return crypto.subtle.importKey(
      'raw',
      m.key as BufferSource,
      effectiveAlg === 'ed25519' ? 'Ed25519' : { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
  }
  // JsonWebKey
  const jwk = m.key as JsonWebKey;
  const subtleAlg = effectiveAlg === 'ed25519'
    ? { name: 'Ed25519' }
    : { name: 'ECDSA', namedCurve: 'P-256' };
  return crypto.subtle.importKey('jwk', jwk, subtleAlg, false, ['verify']);
}

/**
 * Verify all signature labels present on a Request per RFC 9421.
 *
 * Checks, per label:
 *  - Signature-Input and Signature members exist and pair up
 *  - every covered component is present and canonicalizes identically
 *  - created/expires are within skew (when present)
 *  - the cryptographic signature verifies
 *
 * Returns ok:true only when EVERY label verifies. Use the per-call result
 * `reason` for diagnostics.
 */
export async function verify(request: Request, options: VerifyOptions): Promise<VerifyResult> {
  const sigInputHeader = request.headers.get('signature-input');
  const sigHeader = request.headers.get('signature');
  if (!sigInputHeader || !sigHeader) {
    return { ok: false, reason: 'missing Signature-Input or Signature header' };
  }
  const inputs = parseDictionaryHeader(sigInputHeader);
  const sigs = parseDictionaryHeader(sigHeader);
  if (!inputs.size) return { ok: false, reason: 'no signature labels in Signature-Input' };

  const skew = options.skewSec ?? 300;
  const nowMs = options.now ?? Date.now;
  const nowSec = Math.floor(nowMs() / 1000);

  // Body is needed if any covered component is content-digest.
  let body: Uint8Array | undefined;
  const needsBody = [...inputs.values()].some(({ params }) =>
    parseSignatureParams(params).components.some((c) => c.toLowerCase().startsWith('content-digest'))
  );
  if (needsBody) body = new Uint8Array(await request.clone().arrayBuffer());

  let firstOk: VerifyResult | null = null;
  for (const [label, member] of inputs) {
    const sigMember = sigs.get(label);
    if (!sigMember) return { ok: false, label, reason: `no Signature member for label ${label}` };
    const sigBytes = sigMember.params;
    const m = sigBytes.match(/^:([A-Za-z0-9+/=]+):$/);
    if (!m) return { ok: false, label, reason: 'Signature value is not :base64:' };

    const { components, params } = parseSignatureParams(member.params);
    if (!components.length) return { ok: false, label, reason: 'empty covered components' };

    // Freshness checks.
    if (params.created !== undefined) {
      const created = Number(params.created);
      if (!Number.isFinite(created)) return { ok: false, label, reason: 'bad created param' };
      if (created > nowSec + skew) return { ok: false, label, reason: 'signature from the future' };
    }
    if (params.expires !== undefined) {
      const expires = Number(params.expires);
      if (!Number.isFinite(expires)) return { ok: false, label, reason: 'bad expires param' };
      if (expires < nowSec - skew) return { ok: false, label, reason: 'signature expired' };
    }

    // Rebuild the signing string using the params EXACTLY as received.
    const base = await buildBase(request, components, member.params, body);

    // When content-digest is covered, the signed header must also match the
    // actual body — otherwise a tampered body with a stale digest header
    // would still verify.
    if (components.some((c) => c.toLowerCase().startsWith('content-digest'))) {
      if (body === undefined) return { ok: false, label, reason: 'content-digest covered but no body' };
      const digest = await crypto.subtle.digest('SHA-256', body as BufferSource);
      const expected = `sha-256=:${b64encode(new Uint8Array(digest))}:`;
      const actual = request.headers.get('content-digest') ?? '';
      if (actual.toLowerCase() !== expected.toLowerCase()) {
        return { ok: false, label, reason: 'content-digest does not match body' };
      }
    }
    const alg = (params.alg as SigAlg | undefined) ?? 'ecdsa-p256-sha256';
    const key = await importKey(options.publicKey, params.alg as SigAlg | undefined);
    const ok = await crypto.subtle.verify(
      alg === 'ed25519' ? 'Ed25519' : { name: 'ECDSA', hash: 'SHA-256' },
      key,
      b64decode(m[1]) as BufferSource,
      new TextEncoder().encode(base),
    );
    if (!ok) return { ok: false, label, reason: 'signature verification failed' };
    if (!firstOk) firstOk = { ok: true, label, keyid: params.keyid, params };
  }
  return firstOk ?? { ok: false, reason: 'no labels verified' };
}
