/** RFC 9421 §2.1 derived component identifiers. */
const DERIVED = new Set([
  '@method', '@authority', '@scheme', '@request-target', '@path',
  '@query', '@query-param', '@status', '@signature-params',
]);

/** RFC 9421 §2.2.9 well-known signature parameters, serialized in this order. */
const PARAM_ORDER = ['created', 'expires', 'nonce', 'alg', 'keyid', 'tag'];

const te = new TextEncoder();

export function isDerived(name: string): boolean {
  return DERIVED.has(name);
}

/** Serialize signature parameters: `("c1" "c2");created=..;keyid=".."`. */
export function serializeParams(components: string[], params: Record<string, string>): string {
  const inner = `(${components.map((c) => `"${c}"`).join(' ')})`;
  const parts: string[] = [inner];
  for (const name of PARAM_ORDER) {
    const v = params[name];
    if (v === undefined) continue;
    if (name === 'created' || name === 'expires') {
      parts.push(`${name}=${v}`);
    } else {
      parts.push(`${name}="${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`);
    }
  }
  return parts.join(';');
}

/**
 * Value of a covered component for a request. Returns null when the
 * component cannot be derived (e.g. @query-param without a name, or a
 * missing header is an error — callers handle that).
 */
export async function componentValue(
  request: Request,
  name: string,
  body?: Uint8Array,
): Promise<string | null> {
  const url = new URL(request.url);
  switch (name) {
    case '@method':
      return request.method.toUpperCase();
    case '@authority':
      return url.host.toLowerCase();
    case '@scheme':
      return url.protocol.replace(/:$/, '').toLowerCase();
    case '@request-target':
      return url.pathname + url.search;
    case '@path':
      return url.pathname || '/';
    case '@query':
      return url.search ? url.search.slice(1) : '';
    case '@target-uri':
      return request.url;
    case '@signature-params':
      return null; // set by caller during base construction
    default:
      break;
  }
  if (name.startsWith('@query-param')) {
    // @query-param;name="foo" — parameters live in the component identifier,
    // handled by the parser; not supported in v1 covered set.
    return null;
  }
  if (name.startsWith('@')) return null;
  // Header field: lowercase name; Headers.get joins repeated fields with
  // ", " which is exactly the RFC 9421 combined form.
  const value = request.headers.get(name.toLowerCase());
  if (value === null) return null;
  return value.trim().replace(/\s+/g, ' ');
}

/** Parse a component identifier like `@query-param`;name="x" or `foo`;p="v". */
export function parseComponent(raw: string): { name: string; params: Record<string, string> } {
  const semi = raw.indexOf(';');
  if (semi === -1) return { name: raw.trim(), params: {} };
  const name = raw.slice(0, semi).trim();
  const params: Record<string, string> = {};
  const rest = raw.slice(semi + 1);
  for (const m of rest.matchAll(/(;?)\s*([A-Za-z0-9_-]+)\s*=\s*"((?:[^"\\]|\\.)*)"/g)) {
    params[m[2]] = m[3].replace(/\\(.)/g, '$1');
  }
  return { name, params };
}

/** Extract `("a" "b");k=v;k2="v2"` inner list from Signature/Signature-Input headers. */
export function parseDictionaryHeader(value: string | null): Map<string, { params: string; raw: string }> {
  const out = new Map<string, { params: string; raw: string }>();
  if (!value) return out;
  // Split top-level on commas not inside parens/quotes.
  const members: string[] = [];
  let depth = 0, inStr = false, cur = '';
  for (const ch of value) {
    if (ch === '"') inStr = !inStr;
    if (!inStr) {
      if (ch === '(') depth++;
      if (ch === ')') depth--;
      if (ch === ',' && depth === 0) { members.push(cur); cur = ''; continue; }
    }
    cur += ch;
  }
  if (cur.trim()) members.push(cur);
  for (const m of members) {
    const eq = m.indexOf('=');
    if (eq === -1) continue;
    const label = m.slice(0, eq).trim();
    out.set(label, { params: m.slice(eq + 1).trim(), raw: m.trim() });
  }
  return out;
}

/** Parse `("c1" "c2");created=1;keyid="k"` into components + params. */
export function parseSignatureParams(params: string): { components: string[]; params: Record<string, string> } {
  const close = params.indexOf(')');
  const inner = params.slice(params.indexOf('(') + 1, close);
  const components = [...inner.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1].replace(/\\(.)/g, '$1'));
  const rest = params.slice(close + 1);
  const kv: Record<string, string> = {};
  for (const part of rest.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const k = part.slice(0, eq).trim();
    let v = part.slice(eq + 1).trim();
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1).replace(/\\(.)/g, '$1');
    kv[k] = v;
  }
  return { components, params: kv };
}

export function b64encode(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export { te, DERIVED, PARAM_ORDER };
