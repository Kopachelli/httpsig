import { componentValue, serializeParams, b64encode, te, parseComponent } from './components.js';
import type { SignOptions, SignResult, SigAlg } from './types.js';

const DEFAULT_COMPONENTS = ['@method', '@authority', '@path'];

function algForKey(key: CryptoKey, override?: SigAlg): SigAlg {
  if (override) return override;
  if (key.algorithm.name === 'ECDSA') return 'ecdsa-p256-sha256';
  if (key.algorithm.name === 'Ed25519' || key.algorithm.name === 'NODE-ED25519') return 'ed25519';
  throw new Error(`unsupported key algorithm: ${key.algorithm.name}`);
}

export async function signingString(
  request: Request,
  components: string[],
  paramsString: string,
  body?: Uint8Array,
): Promise<string> {
  const lines: string[] = [];
  for (const raw of components) {
    const { name, params } = parseComponent(raw);
    let value: string | null;
    if (name === '@signature-params') {
      value = paramsString;
    } else if (name === '@query-param') {
      const pname = params.name;
      if (!pname) throw new Error('@query-param requires ;name=');
      const url = new URL(request.url);
      const vals = url.searchParams.getAll(pname);
      if (!vals.length) throw new Error(`@query-param ${pname} absent`);
      value = vals.length === 1 ? vals[0] : vals.join(', ');
    } else {
      value = await componentValue(request, name, body);
    }
    if (value === null) throw new Error(`component not present: ${raw}`);
    lines.push(`"${raw}": ${value}`);
  }
  lines.push(`"@signature-params": ${paramsString}`);
  return lines.join('\n');
}

/**
 * Sign a fetch Request per RFC 9421. Returns header values to set:
 *
 *   const { signatureInput, signature } = await sign(request, key, opts);
 *   request.headers.set('Signature-Input', signatureInput);
 *   request.headers.set('Signature', signature);
 *
 * `key` must be a private CryptoKey (ECDSA P-256 or Ed25519).
 * The request body is read via request.clone() when 'content-digest' is
 * covered or when computing it explicitly is not needed otherwise.
 */
export async function sign(
  request: Request,
  key: CryptoKey,
  options: SignOptions = {},
): Promise<SignResult> {
  if (key.type !== 'private') throw new Error('signing requires a private CryptoKey');
  const components = options.components ?? DEFAULT_COMPONENTS;
  const label = options.label ?? 'sig1';
  const alg = algForKey(key, options.alg);
  const nowSec = Math.floor(Date.now() / 1000);

  const params: Record<string, string> = {};
  params.created = String(options.created ?? nowSec);
  if (options.expires !== undefined) params.expires = String(options.expires);
  if (options.nonce !== undefined) params.nonce = options.nonce;
  params.alg = alg;
  if (options.keyid !== undefined) params.keyid = options.keyid;
  if (options.tag !== undefined) params.tag = options.tag;

  const paramsString = serializeParams(components, params);

  // Body bytes only when a covered component needs them.
  const coversDigest = components.some((c) => c.toLowerCase().startsWith('content-digest'));
  let body: Uint8Array | undefined;
  if (coversDigest) {
    body = new Uint8Array(await request.clone().arrayBuffer());
    // RFC 9530 content-digest: set it if the signer didn't, so the covered
    // component always has a correct value to sign.
    if (!request.headers.has('content-digest')) {
      const digest = await crypto.subtle.digest('SHA-256', body as BufferSource);
      request.headers.set('content-digest', `sha-256=:${b64encode(new Uint8Array(digest))}:`);
    }
  }

  const base = await signingString(request, components, paramsString, body);
  const sigBytes = new Uint8Array(await crypto.subtle.sign(
    alg === 'ed25519' ? 'Ed25519' : { name: 'ECDSA', hash: 'SHA-256' },
    key,
    te.encode(base),
  ));

  return {
    signatureInput: `${label}=${paramsString}`,
    signature: `${label}=:${b64encode(sigBytes)}:`,
    signingString: base,
  };
}
