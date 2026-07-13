import { generateKeyPair, exportJWK, calculateJwkThumbprint, importJWK, compactDecrypt, type JWK } from 'jose';

export interface EncKeyPair {
  publicJwk: JWK;
  privateJwk: JWK;
  /** Key id echoed in the JWE header (`kid`) — the RFC 7638 thumbprint, so it is stable + unique. */
  kid: string;
}

/**
 * OpenID4VP response encryption (HAIP): a **per-transaction** ephemeral ECDH-ES P-256 key. The public JWK is
 * advertised in the request's `client_metadata.jwks`; the wallet encrypts its Authorization Response
 * (`{ vp_token, state }`) to it as a JWE (`alg=ECDH-ES`, `enc=A256GCM`, `apv=base64url(nonce)`), and the
 * verifier decrypts with the private JWK. The same key doubles as the mdoc `EReaderKey` for `deviceMac`.
 */
export async function generateEncKey(): Promise<EncKeyPair> {
  const { publicKey, privateKey } = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
  const publicJwk = await exportJWK(publicKey);
  const privateJwk = await exportJWK(privateKey);
  const kid = await calculateJwkThumbprint(publicJwk, 'sha256');
  return { publicJwk, privateJwk, kid };
}

/** The public JWK to embed in `client_metadata.jwks.keys[]` (adds `use`/`alg`/`kid`, per the wallet contract). */
export function encClientMetadataJwk(publicJwk: JWK, kid: string): Record<string, unknown> {
  return { ...publicJwk, use: 'enc', alg: 'ECDH-ES', kid };
}

/** RFC 7638 SHA-256 thumbprint bytes of the enc public key, for the mdoc OpenID4VP handover (SessionTranscript). */
export async function encJwkThumbprintBytes(publicJwk: JWK): Promise<Uint8Array> {
  const b64 = await calculateJwkThumbprint(publicJwk, 'sha256');
  return new Uint8Array(Buffer.from(b64, 'base64url'));
}

/** Decrypts a compact ECDH-ES JWE response with the session's private JWK → the Authorization Response JSON. */
export async function decryptResponse(jwe: string, privateJwk: JWK): Promise<{ vp_token?: unknown; state?: unknown }> {
  const key = await importJWK(privateJwk, 'ECDH-ES');
  const { plaintext } = await compactDecrypt(jwe, key);
  return JSON.parse(Buffer.from(plaintext).toString('utf8')) as { vp_token?: unknown; state?: unknown };
}
