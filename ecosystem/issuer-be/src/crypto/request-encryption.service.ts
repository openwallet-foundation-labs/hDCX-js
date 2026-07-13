import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { compactDecrypt, exportJWK, generateKeyPair, calculateJwkThumbprint, type JWK } from 'jose';

/**
 * Credential Request Encryption (OpenID4VCI 1.0 §8.2 / §12.2 `credential_request_encryption`). The issuer
 * advertises an EC public key; the wallet encrypts the entire Credential Request to it as a compact JWE
 * (ECDH-ES) — mandatory whenever the wallet also asks for an encrypted response (§8.2: request encryption
 * MUST be used if `credential_response_encryption` is included, so the wallet's response key can't be
 * substituted by an attacker). We hold an ephemeral P-256 keypair generated at boot; the wallet fetches the
 * current metadata before each issuance, so key rotation across restarts is transparent.
 */
@Injectable()
export class RequestEncryptionService implements OnModuleInit {
  private readonly logger = new Logger(RequestEncryptionService.name);
  private privateKey!: CryptoKey;
  private pubJwk!: JWK;

  async onModuleInit(): Promise<void> {
    const { publicKey, privateKey } = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
    this.privateKey = privateKey as CryptoKey;
    const jwk = await exportJWK(publicKey);
    // §12.2: each JWK MUST carry a `kid`; the wallet echoes it into the JWE header (§10). alg = ECDH-ES.
    this.pubJwk = { ...jwk, kid: await calculateJwkThumbprint(jwk, 'sha256'), alg: 'ECDH-ES', use: 'enc' };
    this.logger.log(`credential-request encryption key ready (kid=${this.pubJwk.kid})`);
  }

  /** The public JWK to advertise in `credential_request_encryption.jwks`. */
  publicJwk(): JWK {
    return this.pubJwk;
  }

  /** Decrypts a compact-JWE Credential Request (ECDH-ES) to its JSON object. */
  async decrypt(jwe: string): Promise<Record<string, unknown>> {
    const { plaintext } = await compactDecrypt(jwe.trim(), this.privateKey);
    return JSON.parse(new TextDecoder().decode(plaintext)) as Record<string, unknown>;
  }
}
