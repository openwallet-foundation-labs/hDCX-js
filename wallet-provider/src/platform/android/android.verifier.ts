import { Injectable, Logger } from '@nestjs/common';
import {
  devIntegrity,
  type IntegrityResult,
  type KeyAttestationVerdict,
  type PlatformVerifier,
} from '../platform-verifier';
import { verifyPlayIntegrity } from './play-integrity';
import { verifyAndroidKeyAttestation } from './android-key-attestation';
import { AndroidAttestationRevocation } from './android-attestation-revocation';

/** Android verification: Play Integrity (registration) + Android Key Attestation (credential keys). */
@Injectable()
export class AndroidVerifier implements PlatformVerifier {
  readonly platform = 'android' as const;
  private readonly logger = new Logger(AndroidVerifier.name);

  constructor(private readonly revocation: AndroidAttestationRevocation) {}

  async verifyIntegrity(integrityToken: string | undefined, challenge: string): Promise<IntegrityResult> {
    const dev = devIntegrity(integrityToken, challenge, 'android');
    if (dev) return dev;
    if (!integrityToken) return { trusted: false, platform: 'android', reason: 'missing integrity token' };

    const packageName = process.env.PLAY_INTEGRITY_PACKAGE_NAME;
    if (packageName) return verifyPlayIntegrity(packageName, integrityToken, challenge);

    this.logger.warn('integrity token not recognized (no PLAY_INTEGRITY_PACKAGE_NAME; dev stub expects `dev-integrity:<nonce>`)');
    return { trusted: false, platform: 'android', reason: 'unrecognized integrity token' };
  }

  /**
   * Derives the `key_storage` level from evidence: only when every provided Android Key Attestation chain
   * verifies (in validity, unrevoked, roots in a pinned Google root, in TEE/StrongBox, challenge = the
   * issuer nonce) is `iso_18045_high` asserted. A tampered/invalid/revoked chain is rejected; no chain
   * yields `iso_18045_moderate`.
   */
  async verifyKeyAttestation(keyAttestations: string[] | undefined, challenge?: string): Promise<KeyAttestationVerdict> {
    if (!keyAttestations || keyAttestations.length === 0) {
      this.logger.warn('key attestation issued without a hardware chain — asserting iso_18045_moderate');
      return { level: 'iso_18045_moderate' };
    }
    const revokedSerials = await this.revocation.getRevokedSerials();
    const trustedRoots = rootsFromEnv();
    const challengeBytes = new TextEncoder().encode(challenge ?? '');
    let allHardware = true;
    for (const b64 of keyAttestations) {
      const verdict = await verifyAndroidKeyAttestation(new Uint8Array(Buffer.from(b64, 'base64')), challengeBytes, {
        revokedSerials,
        ...(trustedRoots ? { trustedRoots } : {}),
      });
      if (!verdict.verified) throw new Error(`key attestation chain rejected: ${verdict.reason}`);
      if (challenge && !verdict.challengeMatches) throw new Error('key attestation challenge does not match the issuer nonce');
      if (verdict.securityLevel === 'software') allHardware = false;
    }
    return { level: allHardware ? 'iso_18045_high' : 'iso_18045_moderate' };
  }
}

/** Optional operator override of the trust anchors: a PEM bundle in ANDROID_ATTESTATION_ROOTS. */
function rootsFromEnv(): readonly string[] | undefined {
  const bundle = process.env.ANDROID_ATTESTATION_ROOTS;
  if (!bundle) return undefined;
  const pems = bundle.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  return pems && pems.length > 0 ? pems : undefined;
}
