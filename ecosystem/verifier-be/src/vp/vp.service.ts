import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomBytes, randomUUID } from 'node:crypto';
import { type JWK } from 'jose';
import { KeystoreService } from '../crypto/keystore.service';
import { SessionStore, type PresentationSession } from '../session/session.store';
import { RequestBuilderService } from './request-builder.service';
import { VpTokenVerifierService, type VpToken } from './vp-token-verifier.service';
import { REQUESTABLE, parseRequestedKeys, type RequestableKey } from './dcql';
import { generateEncKey, decryptResponse, encJwkThumbprintBytes } from './enc-key';

export interface CreatePresentationInput {
  credentials?: unknown;
  mode?: 'qr' | 'dc_api';
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
      session = { id, nonce, requested: keys, mode, sameDevice, rp, requestJwt: jwt, expectedOrigins: origins, ...encFields, createdAt: Date.now() };
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
            dc_api_request: { protocol: 'openid4vp', request: { request: session.requestJwt } },
          }),
    };
  }

  async getRequestJwt(id: string): Promise<string> {
    const session = await this.sessions.get(id);
    if (!session) throw new Error('unknown or expired transaction');
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

  async getResult(id: string) {
    const session = await this.sessions.get(id);
    if (!session) throw new Error('unknown or expired transaction');
    return {
      transaction_id: id,
      status: session.result ? session.result.status : 'pending',
      credentials: session.result?.credentials,
      error: session.result?.error,
      // Raw debug info for the inspector: the full request object (decoded JAR), the compact request JWS,
      // and the raw vp_token the wallet submitted (base64url per-credential presentations).
      debug: {
        request: this.decodeJwtPayload(session.requestJwt),
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
    if (typeof body.response === 'string' && session.encPrivateJwk) {
      const dec = await decryptResponse(body.response, session.encPrivateJwk as JWK);
      return this.parseVpToken(dec.vp_token);
    }
    return this.parseVpToken(body.vp_token);
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
