import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomBytes, randomUUID } from 'node:crypto';
import { type JWK } from 'jose';
import { KeystoreService, type RpProfile } from '../crypto/keystore.service';
import { SessionStore, type PresentationSession } from '../session/session.store';
import { RequestBuilderService } from './request-builder.service';
import { VpTokenVerifierService, type VpToken } from './vp-token-verifier.service';
import { REQUESTABLE, parseRequestedKeys, type RequestableKey } from './dcql';
import { generateEncKey, decryptResponse, encJwkThumbprintBytes } from './enc-key';
import { IsoMdocService, buildIsoMdocSessionTranscript } from './iso-mdoc.service';

export interface CreatePresentationInput {
  credentials?: unknown;
  mode?: 'qr' | 'dc_api';
  /** DC-API protocol (dc_api mode only): `openid4vp` (default) or `org-iso-mdoc` (ISO 18013-7, mdoc only). */
  dc_api_protocol?: 'openid4vp' | 'org-iso-mdoc';
  /** Which registrar-issued RP identity signs the request: `plain` (default) or `intermediary`. */
  rp?: string;
  /** Same-device flow: the verifier returns a `redirect_uri` + one-time response_code the wallet returns to. */
  same_device?: boolean;
  /** dc_api: the web origins the response may come from. */
  origins?: string[];
}

@Injectable()
export class VpService {
  private readonly logger = new Logger(VpService.name);
  private readonly baseUrl: string;
  private readonly feUrl?: string;

  constructor(
    private readonly keystore: KeystoreService,
    private readonly requestBuilder: RequestBuilderService,
    private readonly verifier: VpTokenVerifierService,
    private readonly isoMdoc: IsoMdocService,
    private readonly sessions: SessionStore,
    config: ConfigService,
  ) {
    this.baseUrl = config.getOrThrow<string>('VERIFIER_BASE_URL').replace(/\/$/, '');
    this.feUrl = config.get<string>('VERIFIER_FE_URL')?.replace(/\/$/, '') || undefined;
  }

  /** Creates a presentation request. `qr` returns an openid4vp:// URL; `dc_api` returns the request object. */
  async createPresentation(input: CreatePresentationInput) {
    const keys = parseRequestedKeys(input.credentials);
    const mode = input.mode === 'dc_api' ? 'dc_api' : 'qr';
    const rp = this.keystore.resolve(input.rp === 'intermediary' ? 'intermediary' : 'plain');
    const sameDevice = input.same_device === true;
    const id = randomUUID();

    // The ISO 18013-7 org-iso-mdoc DC-API protocol is a distinct, self-contained path (raw CBOR DeviceRequest +
    // HPKE, no JAR / OpenID4VP metadata / per-tx ECDH-ES enc key), handled separately.
    if (mode === 'dc_api' && input.dc_api_protocol === 'org-iso-mdoc') {
      return this.createIsoMdocPresentation(id, keys, rp, input.origins);
    }

    const nonce = randomBytes(16).toString('base64url');
    // Per-transaction ephemeral response-encryption key (HAIP: responses are always encrypted).
    const enc = await generateEncKey();
    const encInput = { publicJwk: enc.publicJwk, kid: enc.kid };
    const encFields = {
      encPrivateJwk: enc.privateJwk as Record<string, unknown>,
      encPublicJwk: enc.publicJwk as Record<string, unknown>,
      encKid: enc.kid,
    };

    let session: PresentationSession;
    if (mode === 'dc_api') {
      const origins = input.origins?.length ? input.origins : [this.baseUrl];
      const { jwt } = await this.requestBuilder.buildForDcApi(keys, nonce, origins, rp, encInput);
      session = { id, nonce, requested: keys, mode, dcApiProtocol: 'openid4vp', sameDevice, rp, requestJwt: jwt, expectedOrigins: origins, ...encFields, createdAt: Date.now() };
    } else {
      const { jwt } = await this.requestBuilder.buildForQr(id, keys, nonce, rp, encInput);
      session = { id, nonce, requested: keys, mode, sameDevice, rp, requestJwt: jwt, ...encFields, createdAt: Date.now() };
    }
    await this.sessions.put(session);
    this.logger.log(`presentation ${id} created (mode=${mode}, rp=${rp}, same_device=${sameDevice}, credentials=${keys.join(',')})`);

    return {
      transaction_id: id,
      mode,
      rp,
      requested: keys.map((k) => ({ key: k, label: REQUESTABLE[k].label })),
      ...(mode === 'qr'
        ? {
            client_id: this.keystore.clientId(rp),
            request_uri: `${this.baseUrl}/request/${id}`,
            // The QR / deep-link the wallet scans (OpenID4VP §5, request_uri flow).
            qr: `openid4vp://?client_id=${encodeURIComponent(this.keystore.clientId(rp))}&request_uri=${encodeURIComponent(
              `${this.baseUrl}/request/${id}`,
            )}`,
          }
        : {
            // For the Digital Credentials API: the frontend passes this to navigator.credentials.get.
            // OID4VP 1.0: a signed (JWS) request uses the `openid4vp-v1-signed` protocol identifier.
            dc_api_request: { protocol: 'openid4vp-v1-signed', request: { request: session.requestJwt } },
          }),
    };
  }

  /**
   * The ISO/IEC 18013-7 **org-iso-mdoc** DC-API protocol: hands the browser a raw CBOR `DeviceRequest` +
   * `EncryptionInfo` (recipient HPKE key + nonce) instead of an OpenID4VP JAR. Only mso_mdoc credentials
   * (pid_mdoc, mdl) are presentable this way — SD-JWT VC has no ISO DeviceResponse.
   */
  private async createIsoMdocPresentation(id: string, keys: RequestableKey[], rp: RpProfile, origins?: string[]) {
    const mdocKeys = keys.filter((k) => IsoMdocService.isSupportedKey(k));
    if (mdocKeys.length === 0) {
      throw new Error('org-iso-mdoc requires at least one mso_mdoc credential (pid_mdoc, mdl); SD-JWT VC is not supported');
    }
    const expectedOrigins = origins?.length ? origins : [this.baseUrl];
    // Reader auth binds to one origin's SessionTranscript; sign for the primary expected origin (the wallet
    // rebuilds the transcript from its actual calling origin — a match yields a "trusted reader" verdict).
    const { deviceRequest, encryptionInfo, nonce, encPrivateJwk } = await this.isoMdoc.createSession(mdocKeys, rp, expectedOrigins[0]);

    const session: PresentationSession = {
      id,
      nonce,
      requested: mdocKeys,
      mode: 'dc_api',
      dcApiProtocol: 'org-iso-mdoc',
      sameDevice: false,
      rp,
      expectedOrigins,
      isoMdoc: { encryptionInfo, nonce, encPrivateJwk: encPrivateJwk as Record<string, unknown> },
      createdAt: Date.now(),
    };
    await this.sessions.put(session);
    this.logger.log(`presentation ${id} created (mode=dc_api, protocol=org-iso-mdoc, rp=${rp}, credentials=${mdocKeys.join(',')})`);

    return {
      transaction_id: id,
      mode: 'dc_api' as const,
      rp,
      requested: mdocKeys.map((k) => ({ key: k, label: REQUESTABLE[k].label })),
      // ISO 18013-7 Annex C: navigator.credentials.get({ digital: { requests: [{ protocol, data }] } }).
      dc_api_request: { protocol: 'org-iso-mdoc', request: { deviceRequest, encryptionInfo } },
    };
  }

  async getRequestJwt(id: string): Promise<string> {
    const session = await this.sessions.get(id);
    if (!session || !session.requestJwt) throw new Error('unknown or expired transaction');
    return session.requestJwt;
  }

  /** direct_post (QR channel): the wallet POSTs { vp_token, state } to the response_uri. */
  async submitDirectPost(id: string, body: Record<string, unknown>) {
    const session = await this.sessions.get(id);
    if (!session) throw new Error('unknown or expired transaction');
    const vpToken = await this.decryptVpToken(session, body);
    await this.finish(session, vpToken, {
      nonce: session.nonce,
      mode: 'qr',
      clientId: this.keystore.clientId(session.rp),
      responseUri: `${this.baseUrl}/response/${id}`,
      encThumbprint: await this.encThumbprint(session),
    });
    // HAIP same-device: return a redirect_uri carrying a fresh one-time response_code (cross-device polls instead).
    if (session.sameDevice && this.feUrl) {
      const responseCode = randomBytes(16).toString('base64url');
      await this.sessions.bindResponseCode(responseCode, id);
      const sep = this.feUrl.includes('?') ? '&' : '?';
      return { redirect_uri: `${this.feUrl}${sep}response_code=${responseCode}` };
    }
    return { status: 'ok' };
  }

  /** Digital Credentials API channel: the frontend posts back the wallet's response + calling origin. */
  async submitDcApi(id: string, body: { vp_token?: unknown; response?: string; origin?: string }) {
    const session = await this.sessions.get(id);
    if (!session) throw new Error('unknown or expired transaction');
    const origin = body.origin ?? '';
    if (session.expectedOrigins && !session.expectedOrigins.includes(origin)) {
      throw new Error(`origin '${origin}' is not in expected_origins`);
    }
    if (session.dcApiProtocol === 'org-iso-mdoc') {
      await this.finishIsoMdoc(session, body, origin);
      return { status: 'ok' };
    }
    const vpToken = await this.decryptVpToken(session, body as Record<string, unknown>);
    await this.finish(session, vpToken, {
      nonce: session.nonce,
      mode: 'dc_api',
      clientId: this.keystore.clientId(session.rp),
      origin,
      encThumbprint: await this.encThumbprint(session),
    });
    return { status: 'ok' };
  }

  /**
   * Finishes an ISO 18013-7 org-iso-mdoc DC-API transaction: HPKE-decrypt the wallet's sealed DeviceResponse,
   * rebuild the origin-/EncryptionInfo-bound DC-API SessionTranscript, and verify each requested mdoc credential.
   */
  private async finishIsoMdoc(
    session: PresentationSession,
    body: { response?: string },
    origin: string,
  ): Promise<void> {
    try {
      if (!session.isoMdoc) throw new Error('session is not an org-iso-mdoc transaction');
      if (typeof body.response !== 'string') throw new Error('org-iso-mdoc DC-API response requires `response`');
      const { encryptionInfo, encPrivateJwk } = session.isoMdoc;
      const deviceResponse = await this.isoMdoc.decryptResponse(body.response, origin, encryptionInfo, encPrivateJwk as JWK);
      session.submittedVpToken = { device_response: deviceResponse };
      const sessionTranscript = buildIsoMdocSessionTranscript(origin, encryptionInfo);
      const credentials = await this.verifier.verifyIsoMdoc(deviceResponse, session.requested, sessionTranscript);
      session.result = { status: 'verified', credentials, verifiedAt: Date.now() };
      this.logger.log(`presentation ${session.id} VERIFIED via org-iso-mdoc (${credentials.map((c) => c.type).join(', ')})`);
    } catch (e) {
      session.result = { status: 'failed', error: (e as Error).message, verifiedAt: Date.now() };
      this.logger.warn(`presentation ${session.id} FAILED (org-iso-mdoc): ${(e as Error).message}`);
    } finally {
      await this.sessions.put(session);
    }
  }

  async getResult(id: string) {
    const session = await this.sessions.get(id);
    if (!session) throw new Error('unknown or expired transaction');
    return {
      transaction_id: id,
      status: session.result ? session.result.status : 'pending',
      credentials: session.result?.credentials,
      error: session.result?.error,
      // Raw debug info for the inspector. OpenID4VP: the decoded JAR + compact request JWS + the submitted
      // vp_token. org-iso-mdoc: the CBOR DeviceRequest + EncryptionInfo + the decrypted DeviceResponse.
      debug:
        session.dcApiProtocol === 'org-iso-mdoc'
          ? {
              request: session.isoMdoc ? { protocol: 'org-iso-mdoc', encryptionInfo: session.isoMdoc.encryptionInfo } : null,
              vp_token: session.submittedVpToken ?? null,
            }
          : {
              request: session.requestJwt ? this.decodeJwtPayload(session.requestJwt) : null,
              request_jwt: session.requestJwt,
              vp_token: session.submittedVpToken ?? null,
            },
    };
  }

  /** Decodes a compact JWS payload (the request object claims) to JSON for the debug inspector. */
  private decodeJwtPayload(jwt: string): unknown {
    try {
      return JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
    } catch {
      return null;
    }
  }

  private async finish(
    session: PresentationSession,
    vpToken: VpToken,
    binding: {
      nonce: string;
      mode: 'qr' | 'dc_api';
      clientId: string;
      responseUri?: string;
      origin?: string;
      encThumbprint?: Uint8Array;
    },
  ): Promise<void> {
    session.submittedVpToken = vpToken;
    try {
      const credentials = await this.verifier.verify(vpToken, session.requested, binding);
      session.result = { status: 'verified', credentials, verifiedAt: Date.now() };
      this.logger.log(`presentation ${session.id} VERIFIED (${credentials.map((c) => c.type).join(', ')})`);
    } catch (e) {
      // Record the failure for the polling frontend; the wallet's POST still gets a 200 acknowledgement.
      session.result = { status: 'failed', error: (e as Error).message, verifiedAt: Date.now() };
      this.logger.warn(`presentation ${session.id} FAILED: ${(e as Error).message}`);
    } finally {
      await this.sessions.put(session);
    }
  }

  private parseVpToken(raw: unknown): VpToken {
    if (raw == null) throw new Error('response has no vp_token');
    const value = typeof raw === 'string' ? (JSON.parse(raw) as unknown) : raw;
    if (typeof value !== 'object') throw new Error('vp_token must be a DCQL-keyed object');
    return value as VpToken;
  }

  /**
   * Decrypts the wallet's response to the DCQL vp_token. HAIP responses are encrypted (`direct_post.jwt` /
   * `dc_api.jwt`): the body carries `response` = a compact ECDH-ES JWE, decrypted with the session's per-tx
   * private key. A plaintext `vp_token` (unencrypted) is accepted as a fallback.
   */
  private async decryptVpToken(session: PresentationSession, body: Record<string, unknown>): Promise<VpToken> {
    // HAIP mandates encrypted responses — no plaintext `vp_token` fallback.
    if (typeof body.response !== 'string' || !session.encPrivateJwk) {
      throw new Error('an encrypted JWE response is required (HAIP direct_post.jwt / dc_api.jwt)');
    }
    const dec = await decryptResponse(body.response, session.encPrivateJwk as JWK);
    // Bind the JWE `apv` to the request nonce, and the response `state` to the transaction (direct_post.jwt
    // carries state; dc_api.jwt omits it).
    const expectedApv = Buffer.from(session.nonce, 'utf8').toString('base64url');
    if (dec.apv !== undefined && dec.apv !== expectedApv) {
      throw new Error('JWE apv does not match the request nonce');
    }
    if (dec.state !== undefined && dec.state !== session.id) {
      throw new Error(`response state '${String(dec.state)}' does not match the transaction`);
    }
    return this.parseVpToken(dec.vp_token);
  }

  /** The enc key's RFC 7638 thumbprint bytes, for the mdoc OpenID4VP SessionTranscript (encrypted responses). */
  private async encThumbprint(session: PresentationSession): Promise<Uint8Array | undefined> {
    return session.encPublicJwk ? encJwkThumbprintBytes(session.encPublicJwk as JWK) : undefined;
  }

  /** Same-device return: exchange a one-time response_code (carried by the redirect_uri) for the result. */
  async exchangeResponseCode(code: string) {
    const id = await this.sessions.resolveResponseCode(code);
    if (!id) throw new Error('unknown or expired response_code');
    return this.getResult(id);
  }

  /** Exposed for tests / introspection. */
  requestableKeys(): RequestableKey[] {
    return Object.keys(REQUESTABLE) as RequestableKey[];
  }
}
