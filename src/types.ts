/** RFC 9421 §2.1.2 signature algorithm identifiers we support. */
export type SigAlg = 'ecdsa-p256-sha256' | 'ed25519';

export interface SignOptions {
  /** Covered component identifiers, e.g. ['@method','@authority','@path']. */
  components?: string[];
  /** Signature label. Default 'sig1'. */
  label?: string;
  /** keyid parameter value. */
  keyid?: string;
  /** Algorithm. Inferred from the CryptoKey when omitted. */
  alg?: SigAlg;
  /** created param, epoch seconds. Default now. */
  created?: number;
  /** expires param, epoch seconds. */
  expires?: number;
  /** nonce param. */
  nonce?: string;
  /** tag param. */
  tag?: string;
}

export interface SignResult {
  /** Value for the Signature-Input header. */
  signatureInput: string;
  /** Value for the Signature header. */
  signature: string;
  /** The exact signing string that was signed (for debugging/tests). */
  signingString: string;
}

export interface VerifyOptions {
  /** Public key(s) to try, keyed by keyid or a single key. */
  publicKey: CryptoKey | JsonWebKey | Uint8Array | { key: CryptoKey | JsonWebKey | Uint8Array; alg?: SigAlg };
  /** Allowed clock skew for created/expires, seconds. Default 300. */
  skewSec?: number;
  /** Injectable clock, epoch ms. Default Date.now. */
  now?: () => number;
}

export type VerifyResult =
  | { ok: true; label: string; keyid?: string; params: Record<string, string> }
  | { ok: false; label?: string; reason: string };
