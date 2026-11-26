import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sign, verify } from '../dist/esm/index.js';

async function makeKeyPair() {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  ) as Promise<CryptoKeyPair>;
}

async function signedRequest(key: CryptoKey, init?: RequestInit & { url?: string }) {
  const req = new Request(init?.url ?? 'https://api.example.com/v1/items?filter=active', {
    method: init?.method ?? 'POST',
    headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) },
    body: init?.body ?? '{"hello":"world"}',
  });
  const { signatureInput, signature } = await sign(req, key, {
    components: ['@method', '@authority', '@path', '@query', 'content-digest'],
    keyid: 'test-key-1',
  });
  req.headers.set('Signature-Input', signatureInput);
  req.headers.set('Signature', signature);
  return req;
}

test('sign + verify roundtrip', async () => {
  const { privateKey, publicKey } = await makeKeyPair();
  const req = await signedRequest(privateKey);
  const v = await verify(req, { publicKey });
  assert.equal(v.ok, true);
  if (v.ok) assert.equal(v.keyid, 'test-key-1');
});

test('verify fails on tampered method', async () => {
  const { privateKey, publicKey } = await makeKeyPair();
  const req = await signedRequest(privateKey);
  const tampered = new Request(req.url, { method: 'DELETE', headers: req.headers });
  const v = await verify(tampered, { publicKey });
  assert.equal(v.ok, false);
});

test('verify fails on tampered query', async () => {
  const { privateKey, publicKey } = await makeKeyPair();
  const req = await signedRequest(privateKey);
  const tampered = new Request(req.url.replace('active', 'deleted'), { method: 'POST', headers: req.headers });
  const v = await verify(tampered, { publicKey });
  assert.equal(v.ok, false);
});

test('verify fails on tampered body when content-digest covered', async () => {
  const { privateKey, publicKey } = await makeKeyPair();
  const req = await signedRequest(privateKey);
  // Signer must have set content-digest — set it now for realism check:
  const tampered = new Request(req.url, {
    method: 'POST',
    headers: req.headers,
    body: '{"hello":"tampered"}',
  });
  const v = await verify(tampered, { publicKey });
  assert.equal(v.ok, false);
});

test('missing signature headers → not ok', async () => {
  const { publicKey } = await makeKeyPair();
  const req = new Request('https://x.test/');
  const v = await verify(req, { publicKey });
  assert.equal(v.ok, false);
});

test('expired signature rejected', async () => {
  const { privateKey, publicKey } = await makeKeyPair();
  const req = new Request('https://api.example.com/a', { method: 'GET' });
  const past = Math.floor(Date.now() / 1000) - 7200;
  const { signatureInput, signature } = await sign(req, privateKey, {
    components: ['@method', '@authority'],
    created: past,
    expires: past + 60,
  });
  req.headers.set('Signature-Input', signatureInput);
  req.headers.set('Signature', signature);
  const v = await verify(req, { publicKey });
  assert.equal(v.ok, false);
  if (!v.ok) assert.match(v.reason, /expired/);
});

test('future-dated signature rejected beyond skew', async () => {
  const { privateKey, publicKey } = await makeKeyPair();
  const req = new Request('https://api.example.com/a', { method: 'GET' });
  const future = Math.floor(Date.now() / 1000) + 3600;
  const { signatureInput, signature } = await sign(req, privateKey, {
    components: ['@method', '@authority'],
    created: future,
  });
  req.headers.set('Signature-Input', signatureInput);
  req.headers.set('Signature', signature);
  const v = await verify(req, { publicKey });
  assert.equal(v.ok, false);
});

test('wrong key fails', async () => {
  const a = await makeKeyPair();
  const b = await makeKeyPair();
  const req = await signedRequest(a.privateKey);
  const v = await verify(req, { publicKey: b.publicKey });
  assert.equal(v.ok, false);
});

test('ed25519 roundtrip', async () => {
  const { privateKey, publicKey } = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const req = new Request('https://api.example.com/x', { method: 'GET' });
  const { signatureInput, signature } = await sign(req, privateKey, {
    components: ['@method', '@authority'],
  });
  req.headers.set('Signature-Input', signatureInput);
  req.headers.set('Signature', signature);
  const v = await verify(req, { publicKey });
  assert.equal(v.ok, true);
});
