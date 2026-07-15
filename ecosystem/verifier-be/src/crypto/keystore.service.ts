import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Crypto } from '@peculiar/webcrypto';
import * as x509 from '@peculiar/x509';
import { createHash } from 'node:crypto';
import { importPKCS8, SignJWT, type CryptoKey } from 'jose';

const webcrypto = new Crypto();
x509.cryptoProvider.set(webcrypto);

/** Which registrar-issued identity signs a request: a direct RP, or one operating through an intermediary. */
export type RpProfile = 'plain' | 'intermediary';

interface RawKeystore {
  privateKeyPem: string;
  certPem: string;
  caCertPem?: string;
}

interface LoadedProfile {
  privateKey: CryptoKey;
  /** The same WRPAC key as a WebCrypto ECDSA signing key — for raw COSE_Sign1 (mdoc reader authentication). */
  signingKey: CryptoKey;
  cert: x509.X509Certificate;
  /** base64 (not url) DER of the leaf WRPAC — the JOSE `x5c` entry. */
  x5c: string[];
  /** DER of the WRPAC chain (leaf first, + CA when configured) — the COSE `x5chain` for mdoc reader auth. */
  chainDer: Uint8Array[];
  /** `x509_hash` value: base64url(SHA-256(certDer)). */
  thumbprint: string;
  clientId: string;
  wrprc?: string;
}

/** PEM (PKCS#8 or certificate) → DER bytes (a standalone ArrayBuffer for WebCrypto). */
function pemToDer(pem: string): ArrayBuffer {
  const b64 = pem.replace(/-----BEGIN [^-]+-----/, '').replace(/-----END [^-]+-----/, '').replace(/\s+/g, '');
  const buf = Buffer.from(b64, 'base64');
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

/**
 * The verifier's Wallet-Relying Party Access Certificates (WRPAC) + signing keys, one per profile:
 *   - `plain`        — a directly registered RP (VERIFIER_WRPAC / VERIFIER_WRPRC).
 *   - `intermediary` — an RP operating through an intermediary; its WRPRC carries `intermediary`/`act.sub`
 *                      (VERIFIER_WRPAC_INTERMEDIARY / VERIFIER_WRPRC_INTERMEDIARY). Optional.
 *
 * Each WRPAC (reader access cert, chains to the Registrar CA) signs the OpenID4VP request object; the client
 * identifier is `x509_hash:base64url(SHA-256(certDer))` (HAIP). The matching WRPRC is carried by value in the
 * request's `verifier_info`. When VERIFIER_WRPAC is unset the `plain` profile falls back to an ephemeral
 * self-signed dev cert (won't chain to the Registrar CA, so real wallets reject it).
 */
@Injectable()
export class KeystoreService implements OnModuleInit {
  private readonly logger = new Logger(KeystoreService.name);
  private readonly profiles = new Map<RpProfile, LoadedProfile>();

  constructor(private readonly config: ConfigService) {}

  async onModuleInit() {
    const raw = this.config.get<string>('VERIFIER_WRPAC');
    // HAIP forbids a self-signed request-signing certificate (the WRPAC must chain to the RP Registrar CA).
    // Fail-closed: without VERIFIER_WRPAC we would fall back to a self-signed ephemeral cert, so refuse to boot
    // unless `DEV_ALLOW_EPHEMERAL_WRPAC=true` explicitly opts in (local dev only — never set in a deployed env).
    if (!raw && this.config.get<string>('DEV_ALLOW_EPHEMERAL_WRPAC') !== 'true') {
      throw new Error(
        'VERIFIER_WRPAC is required: a self-signed request-signing cert is forbidden by HAIP. ' +
          'Set VERIFIER_WRPAC to a registrar-issued WRPAC keystore, or DEV_ALLOW_EPHEMERAL_WRPAC=true for local dev only.',
      );
    }
    const plain = raw ? await this.loadFromPem(JSON.parse(raw) as RawKeystore) : await this.ephemeral();
    plain.wrprc = this.config.get<string>('VERIFIER_WRPRC')?.trim() || undefined;
    this.profiles.set('plain', plain);
    this.logger.log(
      `WRPAC(plain) ${raw ? 'loaded' : 'EPHEMERAL'}: ${plain.cert.subject} client_id=${plain.clientId} wrprc=${!!plain.wrprc}`,
    );

    const iRaw = this.config.get<string>('VERIFIER_WRPAC_INTERMEDIARY');
    if (iRaw) {
      const inter = await this.loadFromPem(JSON.parse(iRaw) as RawKeystore);
      inter.wrprc = this.config.get<string>('VERIFIER_WRPRC_INTERMEDIARY')?.trim() || undefined;
      this.profiles.set('intermediary', inter);
      this.logger.log(`WRPAC(intermediary) loaded: ${inter.cert.subject} client_id=${inter.clientId} wrprc=${!!inter.wrprc}`);
    } else {
      this.logger.warn('VERIFIER_WRPAC_INTERMEDIARY unset — the intermediary RP profile is unavailable');
    }
  }

  /** True when the given profile is configured (else callers should fall back to `plain`). */
  has(rp: RpProfile): boolean {
    return this.profiles.has(rp);
  }

  /** Resolves to the requested profile if configured, else `plain`. */
  resolve(rp: RpProfile): RpProfile {
    return this.profiles.has(rp) ? rp : 'plain';
  }

  clientId(rp: RpProfile): string {
    return this.profile(rp).clientId;
  }

  x5c(rp: RpProfile): string[] {
    return this.profile(rp).x5c;
  }

  wrprc(rp: RpProfile): string | undefined {
    return this.profile(rp).wrprc;
  }

  /** The profile's WRPAC certificate chain (DER, leaf first) — the COSE `x5chain` for mdoc reader authentication. */
  readerChainDer(rp: RpProfile): Uint8Array[] {
    return this.profile(rp).chainDer;
  }

  /** Raw ES256 (P-256 r||s) signature over `data` with the profile's WRPAC key — for a COSE_Sign1 mdoc readerAuth. */
  async signCoseRaw(data: Uint8Array, rp: RpProfile): Promise<Uint8Array> {
    const ab = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
    const sig = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.profile(rp).signingKey, ab);
    return new Uint8Array(sig);
  }

  /** Signs an OpenID4VP request object (JAR) with the profile's WRPAC key: ES256, typ `oauth-authz-req+jwt`, x5c leaf. */
  async signRequestObject(payload: Record<string, unknown>, rp: RpProfile): Promise<string> {
    const p = this.profile(rp);
    return new SignJWT(payload)
      .setProtectedHeader({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: p.x5c })
      .sign(p.privateKey);
  }

  private profile(rp: RpProfile): LoadedProfile {
    return this.profiles.get(rp) ?? this.profiles.get('plain')!;
  }

  private async loadFromPem(ks: RawKeystore): Promise<LoadedProfile> {
    const privateKey = (await importPKCS8(ks.privateKeyPem, 'ES256', { extractable: false })) as CryptoKey;
    // The same key as a WebCrypto ECDSA signer for raw COSE_Sign1 (mdoc reader auth) — jose signs JOSE only.
    const signingKey = await webcrypto.subtle.importKey(
      'pkcs8',
      pemToDer(ks.privateKeyPem),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign'],
    );
    const cert = new x509.X509Certificate(ks.certPem);
    const chainDer = [new Uint8Array(cert.rawData)];
    if (ks.caCertPem) chainDer.push(new Uint8Array(new x509.X509Certificate(ks.caCertPem).rawData));
    return this.fromCert(privateKey, signingKey, cert, chainDer);
  }

  private fromCert(
    privateKey: CryptoKey,
    signingKey: CryptoKey,
    cert: x509.X509Certificate,
    chainDer: Uint8Array[],
  ): LoadedProfile {
    const der = new Uint8Array(cert.rawData);
    const thumbprint = createHash('sha256').update(der).digest('base64url');
    return {
      privateKey,
      signingKey,
      cert,
      x5c: [Buffer.from(der).toString('base64')],
      chainDer,
      thumbprint,
      clientId: `x509_hash:${thumbprint}`,
    };
  }

  private async ephemeral(): Promise<LoadedProfile> {
    const keys = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: '01',
      name: 'CN=DEV Verifier, O=Hopae S.A. (dev), C=LU',
      keys,
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
      notBefore: new Date(Date.now() - 86400_000),
      notAfter: new Date(Date.now() + 365 * 86400_000),
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
        await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
      ],
    });
    const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey)).toString('base64');
    const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${pkcs8.match(/.{1,64}/g)!.join('\n')}\n-----END PRIVATE KEY-----\n`;
    const privateKey = (await importPKCS8(privateKeyPem, 'ES256')) as CryptoKey;
    // The generated key already has 'sign' usage — reuse it as the WebCrypto COSE signer (self-signed, dev only).
    return this.fromCert(privateKey, keys.privateKey, cert, [new Uint8Array(cert.rawData)]);
  }
}
