// Two agents authenticate each other with HTTP Message Signatures.
import { sign, verify } from '../dist/esm/index.js';

// Agent A's keypair (in reality: loaded from KMS/HSM/env)
const a = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
// Agent B's public key (distributed via did:web / agent card)
const bPub = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);

// A → B: signed task request
const req = new Request('https://agent-b.internal/tasks/run', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ task: 'summarize https://example.com' }),
});
const s = await sign(req, a.privateKey, {
  components: ['@method', '@authority', '@path', 'content-digest'],
  keyid: 'agent-a',
});
req.headers.set('Signature-Input', s.signatureInput);
req.headers.set('Signature', s.signature);
console.log('Signature-Input:', s.signatureInput);

// B verifies
const v = await verify(req, { publicKey: bPub.publicKey });
console.log('verify with wrong key:', v.ok); // false
const v2 = await verify(req, { publicKey: a.publicKey });
console.log('verify with right key:', v2.ok, v2.ok ? v2.keyid : '');
