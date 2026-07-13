import { Injectable, Logger } from '@nestjs/common';
import * as x509 from '@peculiar/x509';
import { inflateSync } from 'node:zlib';
import { importX509, exportJWK, importJWK, jwtVerify } from 'jose';
import { SDJwtInstance } from '@sd-jwt/core';
import { generateSalt, digest, ES256 } from '@sd-jwt/crypto-nodejs';
import type { KbVerifier, Verifier } from '@sd-jwt/types';
import { DeviceResponse, SessionTranscript } from '@lukas.j.han/mdoc';
import { TrustedListService } from '../trust/trusted-list.service';
import { REQUESTABLE, type RequestableCredential } from './dcql';
import { mdocVerifyContext } from './mdoc.context';
import { toPlainObject } from './mdoc.util';

/** The vp_token is a DCQL-keyed map of query id → presentation (string, or array of strings). */
export type VpToken = Record<string, string | string[]>;

export interface VerifiedCredential {
  queryId: string;
  format: string;
  type: string;
  claims: Record<string, unknown>;
}

/** How the wallet built its response (channel-specific), for binding checks + the mdoc SessionTranscript. */
export interface ResponseBinding {
  nonce: string;
  mode: 'qr' | 'dc_api';
  /** The client_id of the RP profile that signed the request (SD-JWT key-binding aud + mdoc SessionTranscript). */
  clientId: string;
  /** direct_post: the response_uri the wallet posted to. */
  responseUri?: string;
  /** dc_api: the calling web origin. */
  origin?: string;
  /** RFC 7638 thumbprint of the response-encryption key — bound into the mdoc handover for `*.jwt` responses. */
  encThumbprint?: Uint8Array;
}

/** Reads the `bits`-wide status entry at `idx` from a base64url zlib-DEFLATE status list (LSB-first, IETF TSL §4). */
function statusAt(lstB64url: string, bits: number, idx: number): number {
  const bytes = inflateSync(Buffer.from(lstB64url, 'base64url'));
  const entriesPerByte = 8 / bits;
  const byteIndex = Math.floor(idx / entriesPerByte);
  if (byteIndex >= bytes.length) return 0; // beyond the list → unlisted → valid
  const shift = (idx % entriesPerByte) * bits;
  const mask = (1 << bits) - 1;
  return (bytes[byteIndex] >> shift) & mask;
}

/**
 * Verifies an OpenID4VP `vp_token` against the requested DCQL and the presentation binding, for both credential
 * formats: `dc+sd-jwt` (SD-JWT VC — issuer x5c → PID/Attestation CA, key-binding JWT nonce + aud) and
 * `mso_mdoc` (ISO 18013-5 — DeviceResponse against the reconstructed OpenID4VP SessionTranscript, issuer MSO +
 * device signature, x5chain → PID/Attestation CA). Trust anchors come from the JAdES Trusted Lists; the
 * verification approach mirrors the EUDI research module (`@lukas.j.han/mdoc` + `@sd-jwt`).
 */
@Injectable()
export class VpTokenVerifierService {
  private readonly logger = new Logger(VpTokenVerifierService.name);

  constructor(private readonly trust: TrustedListService) {}

  async verify(vpToken: VpToken, requestedKeys: string[], binding: ResponseBinding): Promise<VerifiedCredential[]> {
    const anchors = await this.trust.getIssuerAnchors();
    const allAnchors = [...anchors.pid, ...anchors.attestation];
    const anchorsDer = allAnchors.map((c) => new Uint8Array(c.rawData));
    const out: VerifiedCredential[] = [];

    for (const key of requestedKeys) {
      const cred = REQUESTABLE[key as keyof typeof REQUESTABLE];
      if (!cred) continue;
      const raw = vpToken[cred.queryId];
      if (raw == null) throw new Error(`vp_token missing a presentation for query '${cred.queryId}'`);
      const presentation = Array.isArray(raw) ? raw[0] : raw;

      const claims =
        cred.format === 'dc+sd-jwt'
          ? await this.verifySdJwtVc(presentation, cred, allAnchors, binding)
          : await this.verifyMdoc(presentation, cred, anchorsDer, binding);

      out.push({ queryId: cred.queryId, format: cred.format, type: cred.type, claims });
    }
    return out;
  }

  // --- SD-JWT VC ------------------------------------------------------------

  private async verifySdJwtVc(
    presentation: string,
    cred: RequestableCredential,
    anchors: x509.X509Certificate[],
    binding: ResponseBinding,
  ): Promise<Record<string, unknown>> {
    const issuerJwt = presentation.split('~')[0];
    const header = JSON.parse(Buffer.from(issuerJwt.split('.')[0], 'base64url').toString()) as { x5c?: string[] };
    if (!header.x5c?.length) throw new Error('SD-JWT VC issuer JWT has no x5c');

    const leafJwk = await this.verifyX5cChain(header.x5c, anchors);
    const verifier: Verifier = await ES256.getVerifier(leafJwk);
    const kbVerifier: KbVerifier = async (data, sig, payload) => {
      const jwk = (payload as { cnf?: { jwk?: JsonWebKey } }).cnf?.jwk;
      if (!jwk) return false;
      return (await ES256.getVerifier(jwk))(data, sig);
    };

    const sdjwt = new SDJwtInstance({ saltGenerator: generateSalt, hashAlg: 'sha-256', hasher: digest, verifier, kbVerifier });
    const result = await sdjwt.verify(presentation, { keyBindingNonce: binding.nonce, requiredClaimKeys: cred.claimNames });

    // Audience binding: the key-binding JWT MUST be addressed to this verifier (client_id).
    const aud = (result.kb?.payload as { aud?: unknown } | undefined)?.aud;
    if (aud !== binding.clientId) {
      throw new Error(`SD-JWT VC key-binding aud '${String(aud)}' != client_id '${binding.clientId}'`);
    }

    // Revocation: refuse a credential whose Token Status List entry is not valid (IETF TSL).
    await this.checkStatus(result.payload as { status?: unknown }, anchors);

    return this.pickClaims(result.payload as Record<string, unknown>, cred.claimNames);
  }

  /**
   * Presented-credential revocation check (IETF Token Status List). Reads `status.status_list = { idx, uri }`
   * from the credential, fetches the `statuslist+jwt` (verified: x5c → a trusted issuer anchor, ES256, and
   * `sub == uri`), decodes the packed bit array (zlib DEFLATE, LSB-first), and rejects a non-valid (≠0) entry.
   * A credential without a status reference (e.g. current mdoc) is accepted — there is nothing to check.
   */
  private async checkStatus(payload: { status?: unknown }, anchors: x509.X509Certificate[]): Promise<void> {
    const ref = (payload.status as { status_list?: { idx?: number; uri?: string } } | undefined)?.status_list;
    if (!ref?.uri || typeof ref.idx !== 'number') return;

    const res = await fetch(ref.uri, { headers: { Accept: 'application/statuslist+jwt' }, signal: AbortSignal.timeout(8000) });
    if (!res.ok) throw new Error(`status list fetch failed: HTTP ${res.status}`);
    const token = (await res.text()).trim();
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString()) as { x5c?: string[] };
    if (!header.x5c?.length) throw new Error('status list token has no x5c');

    const leafJwk = await this.verifyX5cChain(header.x5c, anchors);
    const { payload: st } = await jwtVerify(token, await importJWK(leafJwk, 'ES256'));
    if (typeof st.sub === 'string' && st.sub !== ref.uri) {
      throw new Error(`status list token sub '${st.sub}' != referenced uri`);
    }
    const sl = st.status_list as { bits?: number; lst?: string } | undefined;
    if (!sl?.lst || !sl.bits) throw new Error('status list token missing status_list.{bits,lst}');

    const status = statusAt(sl.lst, sl.bits, ref.idx);
    if (status !== 0) throw new Error(`credential is revoked/suspended (status list entry ${ref.idx} = ${status})`);
  }

  // --- mdoc (ISO 18013-5) ---------------------------------------------------

  private async verifyMdoc(
    presentation: string,
    cred: RequestableCredential,
    trustedCertificates: Uint8Array[],
    binding: ResponseBinding,
  ): Promise<Record<string, unknown>> {
    const deviceResponse = DeviceResponse.decode(new Uint8Array(Buffer.from(presentation, 'base64url')));

    const sessionTranscript =
      binding.mode === 'dc_api'
        ? await SessionTranscript.forOid4VpDcApi(
            { origin: binding.origin ?? '', nonce: binding.nonce, jwkThumbprint: binding.encThumbprint },
            mdocVerifyContext,
          )
        : await SessionTranscript.forOid4Vp(
            {
              clientId: binding.clientId,
              nonce: binding.nonce,
              responseUri: binding.responseUri ?? '',
              jwkThumbprint: binding.encThumbprint,
            },
            mdocVerifyContext,
          );

    await deviceResponse.verify(
      { sessionTranscript, trustedCertificates, disableCertificateChainValidation: false },
      mdocVerifyContext,
    );

    const doc = deviceResponse.documents?.find((d) => d.docType === cred.type) ?? deviceResponse.documents?.[0];
    if (!doc) throw new Error(`mdoc DeviceResponse has no document for docType '${cred.type}'`);
    const claims = toPlainObject(doc.issuerSigned.getPrettyClaims(cred.namespace!)) as Record<string, unknown>;
    return this.pickClaims(claims, cred.claimNames);
  }

  // --- helpers --------------------------------------------------------------

  /**
   * Verifies an x5c chain to a trusted issuer anchor and returns the leaf public key (JWK). Builds the chain
   * with `X509ChainBuilder` (including the trusted anchors), checks each link's signature + validity, and
   * requires the root to be, or be signed by, a trusted certificate.
   */
  private async verifyX5cChain(x5c: string[], anchors: x509.X509Certificate[]): Promise<JsonWebKey> {
    const parsed = x5c.map((b64) => new x509.X509Certificate(new Uint8Array(Buffer.from(b64, 'base64'))));
    const date = new Date();
    const builder = new x509.X509ChainBuilder({ certificates: [...parsed, ...anchors] });
    const chain = Array.from(await builder.build(parsed[0]));
    if (chain.length === 0) throw new Error('SD-JWT VC x5c chain building failed');

    const root = chain[chain.length - 1];
    // `equal()` has an `is this` type predicate that narrows the anchor to `never` in the false branch; cast back.
    const trusted = await Promise.all(
      anchors.map(async (a) => root.equal(a) || (await root.verify({ publicKey: (a as x509.X509Certificate).publicKey, date }))),
    );
    if (!trusted.some(Boolean)) throw new Error('SD-JWT VC x5c does not chain to a trusted issuer certificate');

    for (let i = 0; i < chain.length - 1; i++) {
      if (!(await chain[i].verify({ publicKey: chain[i + 1].publicKey, date }))) {
        throw new Error(`SD-JWT VC x5c: "${chain[i].subject}" is not signed by "${chain[i + 1].subject}"`);
      }
    }
    const leafKey = await importX509(chain[0].toString('pem'), 'ES256', { extractable: true });
    return exportJWK(leafKey);
  }

  private pickClaims(all: Record<string, unknown>, wanted: string[]): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const name of wanted) if (all[name] !== undefined) out[name] = all[name];
    return out;
  }
}
