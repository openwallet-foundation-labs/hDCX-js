import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify, type JWK } from 'jose';
import { TrustedListService } from '../trust/trusted-list.service';
import { OAuthError } from '../vci/oauth-error';
import { verifyX5cToAnchors } from './x5c-chain.util';

/**
 * Verifies a Key Attestation (the WUA — OID4VCI Appendix D / HAIP §4.5.1), whether carried standalone (the
 * `attestation` proof type) or inside a jwt proof's `key_attestation` header. Confirms it chains to a trusted
 * Wallet Provider CA, is fresh, and — when an `expectedNonce` is given — echoes it; returns the `attested_keys`
 * (the WSCD-bound holder keys) and the attestation `nonce`. Trust + freshness checks are skipped by
 * `DEV_ATTESTATION_BYPASS=true` (attested_keys are still decoded so batch issuance keeps working).
 */
@Injectable()
export class KeyAttestationService {
  private readonly logger = new Logger(KeyAttestationService.name);

  constructor(
    private readonly trust: TrustedListService,
    private readonly config: ConfigService,
  ) {}

  async verifyAttestation(keyAttJwt: string, expectedNonce?: string): Promise<{ attestedKeys: JWK[]; nonce?: string }> {
    if (this.config.get<string>('DEV_ATTESTATION_BYPASS') === 'true') {
      // Dev bypass: skip trust + freshness checks, but still decode attested_keys so batch expansion works.
      const payload = decodeJwt(keyAttJwt);
      const attestedKeys = payload.attested_keys as JWK[] | undefined;
      if (!attestedKeys?.length) throw new OAuthError('invalid_proof', 'key attestation has no attested_keys');
      return { attestedKeys, nonce: payload.nonce as string | undefined };
    }

    try {
      const kah = decodeProtectedHeader(keyAttJwt);
      if (kah.typ !== 'key-attestation+jwt') throw new Error('bad key-attestation typ');
      if (!kah.x5c?.length) throw new Error('key attestation missing x5c');
      const leafJwk = await verifyX5cToAnchors(kah.x5c, await this.trust.getWalletProviderCAs());
      const { payload } = await jwtVerify(keyAttJwt, await importJWK(leafJwk, kah.alg ?? 'ES256'));

      const now = Math.floor(Date.now() / 1000);
      if (typeof payload.iat !== 'number' || payload.iat > now + 60 || payload.iat < now - 300) {
        throw new Error('key attestation iat out of window');
      }
      if (typeof payload.exp === 'number' && payload.exp < now) throw new Error('key attestation expired');
      if (expectedNonce && payload.nonce !== expectedNonce) throw new Error('key attestation nonce mismatch');

      const attestedKeys = payload.attested_keys as JWK[] | undefined;
      if (!attestedKeys?.length) throw new Error('no attested_keys');
      return { attestedKeys, nonce: payload.nonce as string | undefined };
    } catch (e) {
      this.logger.warn(`key attestation rejected: ${(e as Error).message}`);
      throw new OAuthError('invalid_proof', 'key attestation verification failed');
    }
  }
}
