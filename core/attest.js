/**
 * PARAMANT CORE — attestation
 *
 * The verification problem: any website can SAY "I use Paramant Wall" by
 * setting a header or a window flag. A browser extension must be able to prove
 * it INDEPENDENTLY and cryptographically — otherwise the green checkmark is
 * worthless.
 *
 * Solution: Wall holds an Ed25519 PRIVATE key. The matching PUBLIC key is baked
 * into the extension. Wall signs a short attestation (domain + timestamp +
 * version + nonce). The extension fetches it from /.well-known/paramant-wall on
 * the SAME origin it is inspecting, and verifies the signature against the
 * embedded public key. A malicious site cannot produce a valid signature
 * without the private key, which never leaves the server.
 *
 * Key handling:
 *   - If WALL_ATTEST_PRIVKEY (PKCS8 PEM, base64) is set in env, use it.
 *   - Else load /opt/wall/.attest_key.pem if present.
 *   - Else generate a fresh keypair, persist it, and LOG the public key once so
 *     the operator can paste it into the extension.
 */
'use strict';
const crypto = require('crypto');
const fs = require('fs');

const KEY_PATH = process.env.WALL_ATTEST_KEY_PATH || '/opt/wall/.attest_key.pem';

function loadOrCreateKeys() {
  // 1. from env (base64 PKCS8 PEM)
  if (process.env.WALL_ATTEST_PRIVKEY) {
    try {
      const pem = Buffer.from(process.env.WALL_ATTEST_PRIVKEY, 'base64').toString('utf8');
      const priv = crypto.createPrivateKey(pem);
      const pub = crypto.createPublicKey(priv);
      return { priv: priv, pub: pub, source: 'env' };
    } catch (e) { console.error('[attest] bad WALL_ATTEST_PRIVKEY:', e.message); }
  }
  // 2. from disk
  try {
    if (fs.existsSync(KEY_PATH)) {
      const pem = fs.readFileSync(KEY_PATH, 'utf8');
      const priv = crypto.createPrivateKey(pem);
      const pub = crypto.createPublicKey(priv);
      return { priv: priv, pub: pub, source: 'disk' };
    }
  } catch (e) { console.error('[attest] cannot read key file:', e.message); }
  // 3. generate + persist
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  try {
    fs.writeFileSync(KEY_PATH, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  } catch (e) { console.error('[attest] cannot persist key (using ephemeral):', e.message); }
  return { priv: privateKey, pub: publicKey, source: 'generated' };
}

class Attestor {
  constructor() {
    const k = loadOrCreateKeys();
    this.priv = k.priv;
    this.pub = k.pub;
    this.source = k.source;
    // public key as raw 32-byte base64url — what goes into the extension
    this.publicKeyB64 = this.pub.export({ type: 'spki', format: 'der' })
      .slice(-32).toString('base64');
    this.publicKeyPem = this.pub.export({ type: 'spki', format: 'pem' });
    if (k.source === 'generated') {
      console.log('\n  [attest] NEW Ed25519 attestation key generated.');
      console.log('  [attest] PUT THIS PUBLIC KEY IN THE EXTENSION (raw32 b64):');
      console.log('  [attest]   ' + this.publicKeyB64 + '\n');
    }
  }

  // Sign an attestation for a given domain. Short TTL so a captured
  // attestation can't be replayed on another site for long.
  attest(domain, opts) {
    opts = opts || {};
    const payload = {
      v: 1,
      product: 'paramant-wall',
      domain: String(domain || '').toLowerCase(),
      version: opts.version || 'unknown',
      ts: Date.now(),
      ttl: opts.ttlMs || 5 * 60 * 1000,
      // features the extension can display
      features: opts.features || ['cookieless', 'ip-anonymised', 'k-anonymity', 'pii-stripped'],
      nonce: crypto.randomBytes(8).toString('hex'),
    };
    const msg = Buffer.from(JSON.stringify(payload));
    const sig = crypto.sign(null, msg, this.priv).toString('base64');
    return { payload: payload, signature: sig, publicKey: this.publicKeyB64 };
  }

  // (For tests / self-check) verify with our own public key.
  verify(payload, signatureB64) {
    try {
      const msg = Buffer.from(JSON.stringify(payload));
      return crypto.verify(null, msg, this.pub, Buffer.from(signatureB64, 'base64'));
    } catch (e) { return false; }
  }
}

module.exports = { Attestor };
