// Walkthrough of how a Wallet Unit Attestation (WUA) is built + what it contains.
// Run against a live backend: BASE=http://localhost:3200/wp node test/wua-demo.mjs
import * as jose from 'jose';

const BASE = process.env.BASE ?? 'http://localhost:3200/wp';
const ISS = process.env.WP_ISSUER ?? BASE;
const hr = (t) => console.log(`\n\x1b[1m── ${t} ──\x1b[0m`);
const post = (p, b) => fetch(`${BASE}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) });
const b64urlJson = (seg) => JSON.parse(Buffer.from(seg, 'base64url').toString());

// 1) The wallet creates its INSTANCE KEY (would live in the device secure area; attested by key attestation).
hr('1) wallet instance key (created by the wallet, bound into the WUA)');
const { publicKey, privateKey } = await jose.generateKeyPair('ES256', { extractable: true });
const instanceJwk = await jose.exportJWK(publicKey);
console.log('instance public JWK:', JSON.stringify(instanceJwk));

// 2) Register the instance: nonce -> integrity token -> instanceId.
hr('2) register: POST /wallet-instances  (device integrity is checked here, once)');
const { nonce } = await (await fetch(`${BASE}/nonce`)).json();
const reg = await (await post('/wallet-instances', {
  instanceKey: instanceJwk, integrityToken: `dev-integrity:${nonce}`, nonce, platform: 'android',
})).json();
console.log('challenge nonce:', nonce);
console.log('-> instanceId:', reg.instanceId);

// 3) Prove possession of the instance key (fresh PoP over a WP nonce) and ask for the WUA.
hr('3) obtain the WUA: PoP (signed by the instance key) -> POST /wallet-attestation');
const { nonce: popNonce } = await (await fetch(`${BASE}/nonce`)).json();
const pop = await new jose.SignJWT({ aud: ISS, nonce: popNonce })
  .setProtectedHeader({ typ: 'wallet-provider-pop+jwt', alg: 'ES256' })
  .setIssuedAt()
  .sign(privateKey);
console.log('instance PoP JWT (wallet -> WP, proves it holds the instance key):');
console.log('  header :', JSON.stringify(b64urlJson(pop.split('.')[0])));
console.log('  payload:', JSON.stringify(b64urlJson(pop.split('.')[1])));
const wua = (await (await post('/wallet-attestation', { instanceId: reg.instanceId, pop })).json()).wallet_attestation;

// 4) Anatomy of the WUA.
hr('4) the WUA (compact JWS: header.payload.signature)');
const [h, p] = wua.split('.');
console.log(wua.slice(0, 68) + '…  (' + wua.length + ' chars)');

const header = b64urlJson(h);
console.log('\nProtected header:');
console.log('  typ =', header.typ, ' → OAuth 2.0 client attestation (draft-ietf-oauth-attestation-based-client-auth)');
console.log('  alg =', header.alg, ' → signed with the WP signer key');
console.log('  x5c =', header.x5c.length, 'cert(s) → [signer]; the CA is the trust anchor (served at /.well-known/wallet-provider-ca.pem)');

const payload = b64urlJson(p);
console.log('\nPayload claims:');
for (const [k, v] of Object.entries(payload)) {
  const note = {
    iss: 'the Wallet Provider (WP_ISSUER)',
    sub: 'the subject = wallet client id (defaults to instanceId)',
    iat: 'issued-at (epoch s)', exp: 'expiry (epoch s) — short-lived, refreshed by re-calling /wallet-attestation',
    cnf: 'KEY BINDING: cnf.jwk = the instance public key → this WUA is bound to that key',
    aal: 'authenticator assurance level',
    wallet_name: 'human-readable wallet name', wallet_link: 'wallet info URL',
    status: 'Token Status List reference {idx,uri} → revocation is published there',
  }[k];
  const shown = typeof v === 'object' ? JSON.stringify(v) : v;
  console.log(`  ${k} = ${String(shown).slice(0, 90)}${note ? `   ← ${note}` : ''}`);
}

// 5) Verify it the way a relying issuer would.
hr('5) verification (as a relying issuer does)');
const signerPem = `-----BEGIN CERTIFICATE-----\n${header.x5c[0]}\n-----END CERTIFICATE-----`;
const signerPub = await jose.importX509(signerPem, 'ES256');
const { payload: verified } = await jose.jwtVerify(wua, signerPub, { issuer: ISS });
console.log('signature valid against x5c[0]:', !!verified);
// show the signer cert identity + chain to the CA
const x509 = await import('node:crypto');
const sc = new x509.X509Certificate(signerPem);
console.log('x5c[0] signer cert subject:', sc.subject.replaceAll('\n', ', '));
console.log('x5c[0] signer cert issuer :', sc.issuer.replaceAll('\n', ', '));
const caPem = await (await fetch(`${BASE}/.well-known/wallet-provider-ca.pem`)).text();
const ca = new x509.X509Certificate(caPem);
console.log('WP CA (trust anchor) subject:', ca.subject.replaceAll('\n', ', '));
console.log('signer chains to the CA:', sc.verify(ca.publicKey), '(signer cert signed by the CA key)');
console.log('cnf.jwk == the instance key we generated:', JSON.stringify(payload.cnf.jwk) === JSON.stringify(instanceJwk) ||
  (payload.cnf.jwk.x === instanceJwk.x && payload.cnf.jwk.y === instanceJwk.y));
