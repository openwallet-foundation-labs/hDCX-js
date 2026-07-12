import 'reflect-metadata'; // @peculiar/x509 (via tsyringe) needs the reflect polyfill loaded first
import { Crypto } from '@peculiar/webcrypto';
import { AsnConvert } from '@peculiar/asn1-schema';
import { KeyDescription, SecurityLevel } from '@peculiar/asn1-android';
import * as x509 from '@peculiar/x509';
import { GOOGLE_ATTESTATION_ROOTS } from './google-attestation-roots';

x509.cryptoProvider.set(new Crypto());

const ANDROID_KEY_ATTESTATION_OID = '1.3.6.1.4.1.11129.2.1.17';

export type KeyStorageLevel = 'software' | 'trustedEnvironment' | 'strongBox';

export interface AndroidKeyAttestationVerdict {
  /** The chain is signature-valid, within validity, unrevoked, and roots in a trusted Google root. */
  verified: boolean;
  /** Where the attested key lives, per the attestation extension. */
  securityLevel: KeyStorageLevel;
  /** The attestation challenge equals the expected nonce (anti-replay). */
  challengeMatches: boolean;
  reason?: string;
}

export interface VerifyKeyAttestationOptions {
  /** Trust anchors (PEM). Defaults to the pinned Google hardware-attestation roots. */
  trustedRoots?: readonly string[];
  /** Certificate serial numbers (normalised lowercase hex) revoked/suspended per Google's status list. */
  revokedSerials?: ReadonlySet<string>;
  /** Clock for certificate validity-period checks (default: current time). */
  now?: Date;
}

/** Serial numbers vary in case/leading zeros across sources — normalise before comparing. */
export function normalizeSerial(serial: string): string {
  return serial.toLowerCase().replace(/[^0-9a-f]/g, '').replace(/^0+/, '') || '0';
}

const rootThumbprintCache = new Map<readonly string[], Promise<Set<string>>>();
function trustedThumbprints(pems: readonly string[]): Promise<Set<string>> {
  let cached = rootThumbprintCache.get(pems);
  if (!cached) {
    cached = (async () => {
      const set = new Set<string>();
      for (const pem of pems) {
        const cert = new x509.X509Certificate(pem);
        set.add(toHex(new Uint8Array(await cert.getThumbprint('SHA-256'))));
      }
      return set;
    })();
    rootThumbprintCache.set(pems, cached);
  }
  return cached;
}

/**
 * Verifies an Android Key Attestation certificate chain (concatenated DER, leaf → Google root) and extracts
 * the attested key's storage security level + challenge. Production-grade checks: every certificate must be
 * within its validity period, each signed by the next, none revoked/suspended per Google's status list, and
 * the chain must root in a pinned Google hardware-attestation root. This is what lets the Wallet Provider
 * assert a storage level (e.g. `iso_18045_high`) truthfully instead of on faith.
 */
export async function verifyAndroidKeyAttestation(
  chainDer: Uint8Array,
  expectedChallenge: Uint8Array,
  options: VerifyKeyAttestationOptions = {},
): Promise<AndroidKeyAttestationVerdict> {
  const { trustedRoots = GOOGLE_ATTESTATION_ROOTS, revokedSerials, now = new Date() } = options;
  const fail = (reason: string): AndroidKeyAttestationVerdict =>
    ({ verified: false, securityLevel: 'software', challengeMatches: false, reason });

  let certs: x509.X509Certificate[];
  try {
    certs = splitDerCerts(chainDer).map((der) => new x509.X509Certificate(Buffer.from(der)));
  } catch (e) {
    return fail(`malformed certificate chain: ${(e as Error).message}`);
  }
  if (certs.length < 2) return fail('attestation chain too short');

  // 1. Every certificate must be within its validity period (Android rotates short-lived intermediates).
  for (let i = 0; i < certs.length; i++) {
    if (now < certs[i].notBefore || now > certs[i].notAfter) {
      return fail(`certificate ${i} is outside its validity period`);
    }
  }

  // 2. Each certificate must be signed by the next; the root must be a pinned Google attestation root.
  for (let i = 0; i < certs.length - 1; i++) {
    const ok = await certs[i].verify({ publicKey: certs[i + 1].publicKey, signatureOnly: true });
    if (!ok) return fail(`certificate ${i} is not signed by its issuer`);
  }
  const root = certs[certs.length - 1];
  const rootThumbprint = toHex(new Uint8Array(await root.getThumbprint('SHA-256')));
  if (!(await trustedThumbprints(trustedRoots)).has(rootThumbprint)) {
    return fail('chain does not root in a trusted Google attestation root');
  }

  // 3. No certificate in the chain may be revoked/suspended per Google's attestation status list.
  if (revokedSerials && revokedSerials.size > 0) {
    for (const cert of certs) {
      const serial = normalizeSerial(cert.serialNumber);
      if (revokedSerials.has(serial)) return fail(`certificate ${serial} is revoked or suspended by Google`);
    }
  }

  // 4. The leaf carries the Android Key Attestation extension → parse the KeyDescription.
  const ext = certs[0].getExtension(ANDROID_KEY_ATTESTATION_OID);
  if (!ext) return fail('leaf has no Android Key Attestation extension');
  let keyDescription: KeyDescription;
  try {
    keyDescription = AsnConvert.parse(ext.value, KeyDescription);
  } catch (e) {
    return fail(`unparsable KeyDescription: ${(e as Error).message}`);
  }

  const securityLevel: KeyStorageLevel =
    keyDescription.attestationSecurityLevel === SecurityLevel.strongBox ? 'strongBox'
    : keyDescription.attestationSecurityLevel === SecurityLevel.trustedEnvironment ? 'trustedEnvironment'
    : 'software';
  const challenge = new Uint8Array(keyDescription.attestationChallenge.buffer);
  const challengeMatches = equalBytes(challenge, expectedChallenge);

  return {
    verified: true,
    securityLevel,
    challengeMatches,
    reason: challengeMatches ? undefined : 'attestation challenge does not match the expected nonce',
  };
}

/** Splits concatenated DER certificates (each a self-delimiting `SEQUENCE`) into individual DER blobs. */
function splitDerCerts(der: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  let i = 0;
  while (i < der.length) {
    if (der[i] !== 0x30) throw new Error(`expected a DER SEQUENCE at offset ${i}`);
    const lenByte = der[i + 1];
    let header: number;
    let length: number;
    if (lenByte < 0x80) {
      header = 2;
      length = lenByte;
    } else {
      const numBytes = lenByte & 0x7f;
      length = 0;
      for (let k = 0; k < numBytes; k++) length = (length << 8) | der[i + 2 + k];
      header = 2 + numBytes;
    }
    out.push(der.subarray(i, i + header + length));
    i += header + length;
  }
  return out;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
