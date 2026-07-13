import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHash, randomBytes } from 'node:crypto';
import { calculateJwkThumbprint, CompactEncrypt, decodeProtectedHeader, importJWK, jwtVerify, type JWK } from 'jose';
import { SessionStore } from '../session/session.store';
import { IssuerJwtService } from '../jwt/issuer-jwt.service';
import { SdJwtService } from '../credentials/sd-jwt.service';
import { MdocService } from '../credentials/mdoc.service';
import { StatusListService } from '../status-list/status-list.service';
import { KeyAttestationService } from '../attestation/key-attestation.service';
import { RequestEncryptionService } from '../crypto/request-encryption.service';
import type { AttestationResult } from '../attestation/wallet-attestation.guard';
import { CREDENTIAL_CONFIGS, getConfig, getConfigByScope, type CredentialConfig, type Flow } from './credential-configs';
import { allCredentialIssuerIds, credentialIssuerId, resolveProfile } from './issuer-profiles';
import { OAuthError } from './oauth-error';

const rand = (n = 32) => randomBytes(n).toString('base64url');
const s256 = (v: string) => createHash('sha256').update(v).digest('base64url');
/** An `n`-digit numeric code (Transaction Code / PIN) from a CSPRNG. */
const numericCode = (n: number) => Array.from(randomBytes(n), (b) => (b % 10).toString()).join('');

interface AuthRequest {
  configIds: string[];
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: string;
  state?: string;
  dpop_jkt?: string;
  /** Demo: issuer defers issuance (returns a transaction_id) when the originating offer requested it. */
  deferred?: boolean;
  /** Profile policy carried from the offer: response-encryption required + max credentials per request. */
  enc?: boolean;
  batch?: 1 | 3;
}

/** A credential/deferred response the controller emits as JSON or, when encrypted, as `application/jwt`. */
interface IssuerResponse {
  contentType: 'application/json' | 'application/jwt';
  payload: unknown;
}

/**
 * OpenID4VCI 1.0 + HAIP issuance logic. Authorization-code flow (PID) with a browser consent step delegated to
 * issuer-fe, and pre-authorized-code flow (mDL). DPoP-bound access tokens; proofs + key attestations verified
 * at the credential endpoint; each credential gets a Token Status List index; claims are hardcoded (sandbox).
 */
@Injectable()
export class VciService {
  private readonly logger = new Logger(VciService.name);

  constructor(
    private readonly store: SessionStore,
    private readonly issuerJwt: IssuerJwtService,
    private readonly sdJwt: SdJwtService,
    private readonly mdoc: MdocService,
    private readonly statusList: StatusListService,
    private readonly keyAttestation: KeyAttestationService,
    private readonly reqEnc: RequestEncryptionService,
    private readonly config: ConfigService,
  ) {}

  private get issuer(): string {
    return this.config.getOrThrow<string>('ISSUER_BASE_URL');
  }
  private get feUrl(): string {
    return this.config.get<string>('ISSUER_FE_URL') ?? 'http://localhost:5175';
  }

  // ---- Pushed Authorization Request (RFC 9126) ---------------------------------------------------------
  async pushAuthorizationRequest(body: Record<string, string>, att: AttestationResult): Promise<{ request_uri: string; expires_in: number }> {
    if (body.request_uri) throw new OAuthError('invalid_request', 'request_uri not allowed in PAR');
    if (body.response_type !== 'code') throw new OAuthError('invalid_request', 'response_type must be code');
    if (!body.code_challenge || body.code_challenge_method !== 'S256') {
      throw new OAuthError('invalid_request', 'PKCE S256 required');
    }
    if (!body.redirect_uri) throw new OAuthError('invalid_request', 'redirect_uri required');
    if (!att.dev && body.client_id !== att.sub) throw new OAuthError('invalid_request', 'client_id must equal attestation sub');

    const configIds = this.resolveAuthCodeConfigs(body.scope, body.authorization_details);
    if (!configIds.length) throw new OAuthError('invalid_scope', 'no authorization_code credential in scope');

    // Demo: the originating offer's profile/policy lives on its offer-state; the wallet echoes `issuer_state`
    // into the authorization request, so we pull it here and carry it through to the access token.
    let policy: { deferred?: boolean; enc?: boolean; batch?: 1 | 3 } = {};
    if (body.issuer_state) {
      policy = (await this.store.get<typeof policy>(`offer-state:${body.issuer_state}`)) ?? {};
    }

    const requestUri = `urn:ietf:params:oauth:request_uri:${rand()}`;
    const session: AuthRequest = {
      configIds,
      client_id: body.client_id ?? att.sub,
      redirect_uri: body.redirect_uri,
      code_challenge: body.code_challenge,
      code_challenge_method: 'S256',
      state: body.state,
      dpop_jkt: body.dpop_jkt,
      deferred: policy.deferred === true,
      enc: policy.enc === true,
      batch: policy.batch === 3 ? 3 : 1,
    };
    await this.store.set(`par:${requestUri}`, session, 300);
    return { request_uri: requestUri, expires_in: 300 };
  }

  private resolveAuthCodeConfigs(scope?: string, authorizationDetails?: string): string[] {
    const ids = new Set<string>();
    for (const s of (scope ?? '').split(' ').filter(Boolean)) {
      const c = getConfigByScope(s);
      if (c?.flow === 'authorization_code') ids.add(c.id);
    }
    if (authorizationDetails) {
      try {
        for (const d of JSON.parse(authorizationDetails) as Array<{ type: string; credential_configuration_id: string }>) {
          const c = d.type === 'openid_credential' ? getConfig(d.credential_configuration_id) : undefined;
          if (c?.flow === 'authorization_code') ids.add(c.id);
        }
      } catch {
        /* ignore malformed authorization_details */
      }
    }
    return [...ids];
  }

  // ---- Authorization endpoint → hand off to issuer-fe consent -----------------------------------------
  async authorize(query: Record<string, string>): Promise<string> {
    const requestUri = query.request_uri;
    if (!requestUri) throw new OAuthError('invalid_request', 'request_uri required (PAR)');
    const session = await this.store.get<AuthRequest>(`par:${requestUri}`);
    if (!session) throw new OAuthError('invalid_request', 'unknown or expired request_uri');
    if (query.client_id && query.client_id !== session.client_id) throw new OAuthError('invalid_request', 'client_id mismatch');

    const interactionId = rand(16);
    await this.store.set(`auth:${interactionId}`, session, 600);
    await this.store.del(`par:${requestUri}`);
    return `${this.feUrl}/authorize?session=${interactionId}`;
  }

  /** issuer-fe fetches this to render the consent screen. */
  async getInteraction(interactionId: string) {
    const session = await this.store.get<AuthRequest>(`auth:${interactionId}`);
    if (!session) throw new OAuthError('invalid_request', 'unknown or expired interaction', 404);
    return {
      demo: true,
      client_id: session.client_id,
      credentials: session.configIds.map((id) => {
        const c = getConfig(id)!;
        return { id, name: c.display.name, format: c.format, fields: c.displayFields };
      }),
    };
  }

  /** issuer-fe posts the user's decision; returns the wallet redirect URL. */
  async decideInteraction(interactionId: string, approve: boolean): Promise<{ redirect: string }> {
    const session = await this.store.getdel<AuthRequest>(`auth:${interactionId}`);
    if (!session) throw new OAuthError('invalid_request', 'unknown or expired interaction', 404);
    const url = new URL(session.redirect_uri);
    if (session.state) url.searchParams.set('state', session.state);
    if (!approve) {
      url.searchParams.set('error', 'access_denied');
      return { redirect: url.toString() };
    }
    const code = rand();
    await this.store.set(
      `authz:${code}`,
      { configIds: session.configIds, client_id: session.client_id, redirect_uri: session.redirect_uri, code_challenge: session.code_challenge, dpop_jkt: session.dpop_jkt, deferred: session.deferred, enc: session.enc, batch: session.batch },
      60,
    );
    url.searchParams.set('code', code);
    url.searchParams.set('iss', this.issuer);
    return { redirect: url.toString() };
  }

  // ---- Credential Offer (issuer-initiated) — pre-authorized_code (mDL) or authorization_code (PID) -----
  async createCredentialOffer(
    configId: string,
    opts: { flow?: Flow; deferred?: boolean; encrypted?: boolean; batchSize?: number; txCode?: boolean } = {},
  ): Promise<{ credential_offer: unknown; credential_offer_uri: string; deep_link: string; tx_code?: string }> {
    const c = getConfig(configId);
    if (!c) throw new OAuthError('invalid_request', 'unknown credential_configuration_id');
    // The operator's options select a standard Credential Issuer profile: `flow`/`deferred` change issuer
    // behavior; `encrypted`/`batch` map to a profile whose METADATA (encryption_required / batch_size) the
    // wallet obeys. The offer points `credential_issuer` at that profile — no non-standard offer members.
    const flow: Flow = opts.flow ?? c.flow;
    const deferred = opts.deferred === true;
    const profile = resolveProfile(opts.encrypted === true, opts.batchSize ?? 1);

    let grants: Record<string, unknown>;
    let txCode: string | undefined;
    if (flow === 'pre-authorized_code') {
      const preAuthCode = rand();
      // Transaction Code (OID4VCI §4.1.1): a PIN the operator shows and the User types into the wallet; the
      // wallet must send it at the token endpoint. Numeric, 5 digits.
      txCode = opts.txCode === true ? numericCode(5) : undefined;
      await this.store.set(`pre-auth:${preAuthCode}`, { configIds: [configId], deferred, enc: profile.enc, batch: profile.batch, txCode }, 600);
      grants = {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': preAuthCode,
          ...(txCode ? { tx_code: { input_mode: 'numeric', length: 5, description: 'PIN shown on the issuer screen' } } : {}),
        },
      };
    } else {
      const issuerState = rand();
      await this.store.set(`offer-state:${issuerState}`, { configIds: [configId], deferred, enc: profile.enc, batch: profile.batch }, 600);
      grants = { authorization_code: { issuer_state: issuerState } };
    }

    const offer = {
      credential_issuer: credentialIssuerId(this.issuer, profile),
      credential_configuration_ids: [configId],
      grants,
    };
    const offerId = rand(16);
    await this.store.set(`offer:${offerId}`, offer, 600);
    const credential_offer_uri = `${this.issuer}/credential-offer/${offerId}`;
    // Standard OpenID4VCI invocation scheme (EUDI wallets register it); credential_offer_uri keeps the QR small.
    // `tx_code` (the PIN value) is returned to the issuer's own frontend to display — it is NOT in the offer.
    return { credential_offer: offer, credential_offer_uri, deep_link: `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(credential_offer_uri)}`, tx_code: txCode };
  }

  async getCredentialOffer(offerId: string) {
    const offer = await this.store.get(`offer:${offerId}`);
    if (!offer) throw new OAuthError('invalid_request', 'unknown or expired offer', 404);
    return offer;
  }

  // ---- Token endpoint ---------------------------------------------------------------------------------
  async token(body: Record<string, string>, att: AttestationResult, dpopJkt: string) {
    const grant = body.grant_type;
    let configIds: string[];
    let deferred = false;
    let requireEncryption = false;
    let maxBatch: 1 | 3 = 1;

    if (grant === 'authorization_code') {
      const session = await this.store.getdel<AuthRequest & { code_challenge: string }>(`authz:${body.code}`);
      if (!session) throw new OAuthError('invalid_grant', 'invalid or used authorization code');
      if (body.redirect_uri !== session.redirect_uri) throw new OAuthError('invalid_grant', 'redirect_uri mismatch');
      if (!att.dev && att.sub !== session.client_id) throw new OAuthError('invalid_grant', 'client_id mismatch');
      if (!body.code_verifier || s256(body.code_verifier) !== session.code_challenge) {
        throw new OAuthError('invalid_grant', 'PKCE verification failed');
      }
      if (session.dpop_jkt && session.dpop_jkt !== dpopJkt) throw new OAuthError('invalid_dpop_proof', 'dpop_jkt mismatch');
      configIds = session.configIds;
      deferred = session.deferred === true;
      requireEncryption = session.enc === true;
      maxBatch = session.batch === 3 ? 3 : 1;
    } else if (grant === 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
      const session = await this.store.getdel<AuthRequest & { txCode?: string }>(`pre-auth:${body['pre-authorized_code']}`);
      if (!session) throw new OAuthError('invalid_grant', 'invalid or used pre-authorized_code');
      // Transaction Code (OID4VCI §6.1): when the offer carried one, the wallet MUST send the matching tx_code.
      if (session.txCode && body.tx_code !== session.txCode) throw new OAuthError('invalid_grant', 'invalid tx_code');
      configIds = session.configIds;
      deferred = session.deferred === true;
      requireEncryption = session.enc === true;
      maxBatch = session.batch === 3 ? 3 : 1;
    } else {
      throw new OAuthError('unsupported_grant_type', `grant_type ${grant}`);
    }

    const access_token = await this.issuerJwt.sign(
      {
        cnf: { jkt: dpopJkt },
        authorized_configs: configIds,
        max_batch: maxBatch,
        ...(deferred ? { deferred: true } : {}),
        ...(requireEncryption ? { require_encryption: true } : {}),
      },
      { typ: 'at+jwt', sub: att.sub, aud: this.issuer, expSec: 3600 },
    );
    return {
      access_token,
      token_type: 'DPoP',
      expires_in: 3600,
      authorization_details: configIds.map((id) => ({
        type: 'openid_credential',
        credential_configuration_id: id,
        credential_identifiers: [id],
      })),
    };
  }

  // ---- Nonce endpoint ---------------------------------------------------------------------------------
  async nonce(): Promise<{ c_nonce: string }> {
    const c_nonce = await this.issuerJwt.sign({ jti: rand(16) }, { typ: 'c_nonce+jwt', sub: 'c_nonce', aud: this.issuer, expSec: 300 });
    return { c_nonce };
  }

  // ---- Credential endpoint ----------------------------------------------------------------------------
  /**
   * Issues one credential per proven holder key (batch, OID4VCI `proofs` / ETSI 472-3 CRED-REQ-PROC-4.6.2.1).
   * Supports: deferred issuance (returns a `transaction_id` when the flow was marked deferred), and Credential
   * Response encryption as a compact JWE when the request carries `credential_response_encryption`.
   * Returns a discriminated `{ contentType, payload }` so the controller can emit JSON or `application/jwt`.
   */
  async credential(body: Record<string, unknown> | string, accessToken: Record<string, unknown>): Promise<IssuerResponse> {
    const { req, wasEncrypted } = await this.decryptRequest(body);
    const authorized = (accessToken.authorized_configs as string[] | undefined) ?? [];
    // OID4VCI: when the token response returned `credential_identifiers`, the wallet sends `credential_identifier`
    // (our identifiers == the config ids). Accept either that or `credential_configuration_id`.
    const configId =
      (req.credential_identifier as string | undefined) ??
      (req.credential_configuration_id as string | undefined) ??
      (authorized.length === 1 ? authorized[0] : undefined);
    if (!configId || !authorized.includes(configId)) throw new OAuthError('invalid_credential_request', 'credential_configuration_id not authorized');
    const c = getConfig(configId)!;

    // Enforce this profile's policy (from the access token): request/response encryption + the batch_size cap.
    this.enforceEncryption(accessToken, req, wasEncrypted);
    const maxBatch = accessToken.max_batch === 3 ? 3 : 1;
    const holderJwks = await this.resolveHolderKeys(req, maxBatch, c.keyAttestationRequired !== false);

    // Deferred issuance: store the verified keys and hand back a transaction_id to redeem later.
    if (accessToken.deferred === true) {
      const transaction_id = rand(16);
      await this.store.set(`deferred:${transaction_id}`, { configId, holderJwks }, 600);
      this.logger.log(`deferring ${holderJwks.length}×${configId} as ${transaction_id}`);
      return this.maybeEncrypt({ transaction_id, interval: 5 }, req);
    }

    return this.maybeEncrypt(await this.issueBatch(c, holderJwks), req);
  }

  // ---- Deferred endpoint ------------------------------------------------------------------------------
  async deferredCredential(body: Record<string, unknown> | string, accessToken: Record<string, unknown>): Promise<IssuerResponse> {
    const { req, wasEncrypted } = await this.decryptRequest(body);
    this.enforceEncryption(accessToken, req, wasEncrypted);
    const txId = req.transaction_id as string | undefined;
    if (!txId) throw new OAuthError('invalid_transaction_id', 'transaction_id required');
    const pending = await this.store.getdel<{ configId: string; holderJwks: JWK[] }>(`deferred:${txId}`);
    if (!pending) throw new OAuthError('invalid_transaction_id', 'unknown or expired transaction_id');
    return this.maybeEncrypt(await this.issueBatch(getConfig(pending.configId)!, pending.holderJwks), req);
  }

  /** A Credential Request arrives as JSON, or as a compact JWE (`application/jwt`) — decrypt it (OID4VCI §8.2). */
  private async decryptRequest(body: Record<string, unknown> | string): Promise<{ req: Record<string, unknown>; wasEncrypted: boolean }> {
    if (typeof body === 'string') return { req: await this.reqEnc.decrypt(body), wasEncrypted: true };
    return { req: body, wasEncrypted: false };
  }

  /**
   * On an `encryption_required` profile (OID4VCI §8.2): the Credential Request MUST be encrypted (JWE) AND
   * carry `credential_response_encryption` (the wallet's response key) — the latter can't travel in the clear.
   */
  private enforceEncryption(accessToken: Record<string, unknown>, req: Record<string, unknown>, wasEncrypted: boolean): void {
    if (accessToken.require_encryption !== true) return;
    if (!wasEncrypted) {
      throw new OAuthError('invalid_encryption_parameters', 'this issuer requires an encrypted Credential Request (compact JWE, application/jwt)');
    }
    if (!req.credential_response_encryption) {
      throw new OAuthError('invalid_encryption_parameters', 'an encrypted request must include credential_response_encryption (the response key)');
    }
  }

  // ---- Notification endpoint --------------------------------------------------------------------------
  async notification(body: Record<string, unknown>): Promise<void> {
    const id = body.notification_id as string | undefined;
    const event = body.event as string | undefined;
    if (!id || !event) throw new OAuthError('invalid_notification_request', 'notification_id and event required');
    if (!(await this.store.get(`notif:${id}`))) throw new OAuthError('invalid_notification_id', 'unknown notification_id');
    this.logger.log(`notification ${id}: ${event}`); // credential_accepted | credential_failure | credential_deleted
  }

  /**
   * Resolves the holder keys to bind, honoring the two batch shapes (ETSI TS 119 472-3 §4.6 / OID4VCI §14.6):
   *
   *  • jwt proofs WITHOUT a key attestation → each `proofs.jwt[]` element binds its own signing key (PoP);
   *    multiple allowed up to `maxBatch`. Rejected when the config mandates a WUA (`requireKeyAttestation`).
   *  • jwt proof WITH a key attestation (WUA) → MUST be the only proof (ETSI CRED-REQ-4.6.1.2-01, blocks the
   *    N×N shape); the bound keys come from the WUA's `attested_keys` (first `maxBatch`), and the proof must be
   *    signed by the first attested key (CRED-REQ-PROC-4.6.2.1-02/-07).
   *  • `attestation` proof (a WUA on its own, no PoP) → exactly one element; keys from `attested_keys`.
   *
   * The Credential Issuer determines the credential count (OID4VCI §14.6): we cap `attested_keys` to `maxBatch`
   * and refuse duplicate keys (CRED-REQ-PROC-4.6.2.1-06).
   */
  private async resolveHolderKeys(req: Record<string, unknown>, maxBatch: number, requireKeyAttestation: boolean): Promise<JWK[]> {
    const proof = req.proof as { proof_type?: string; jwt?: string; attestation?: string } | undefined;
    const proofs = req.proofs as { jwt?: unknown; attestation?: unknown } | undefined;
    const asStrings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);

    const jwtProofs = proof?.proof_type === 'jwt' && proof.jwt ? [proof.jwt] : asStrings(proofs?.jwt);
    const attProofs = proof?.proof_type === 'attestation' && proof.attestation ? [proof.attestation] : asStrings(proofs?.attestation);
    if (jwtProofs.length && attProofs.length) throw new OAuthError('invalid_proof', 'send either jwt or attestation proofs, not both');

    // (A) `attestation` proof type: a WUA on its own (no PoP). Exactly one element; its nonce IS the c_nonce.
    if (attProofs.length) {
      if (attProofs.length !== 1) throw new OAuthError('invalid_proof', 'the attestation proof array must contain exactly one element');
      const { attestedKeys, nonce } = await this.keyAttestation.verifyAttestation(attProofs[0]);
      if (!nonce) throw new OAuthError('invalid_proof', 'attestation nonce required');
      await this.consumeNonce(nonce);
      return this.capBatch(attestedKeys, maxBatch);
    }

    // (B) `jwt` proof type. Verify each PoP signature; all proofs share one c_nonce, consumed once.
    if (!jwtProofs.length) throw new OAuthError('invalid_proof', 'jwt proof required');
    const verified = await Promise.all(jwtProofs.map((jwt) => this.verifyProofSignature(jwt)));
    if (new Set(verified.map((v) => v.nonce)).size !== 1) throw new OAuthError('invalid_proof', 'all proofs must share one c_nonce');
    await this.consumeNonce(verified[0].nonce);

    const withWua = verified.some((v) => typeof v.header['key_attestation'] === 'string');
    if (withWua) {
      // A key attestation carries the batch in its attested_keys → forbid N proofs each with a WUA (N×N).
      if (jwtProofs.length !== 1) throw new OAuthError('invalid_proof', 'a jwt proof carrying a key_attestation must be the only proof (batch keys go in attested_keys)');
      const v = verified[0];
      const { attestedKeys } = await this.keyAttestation.verifyAttestation(v.header['key_attestation'] as string, v.nonce);
      // ETSI CRED-REQ-PROC-4.6.2.1-02/-07: the proof is signed by the FIRST attested key.
      if ((await calculateJwkThumbprint(v.holderJwk, 'sha256')) !== (await calculateJwkThumbprint(attestedKeys[0], 'sha256'))) {
        throw new OAuthError('invalid_proof', 'the jwt proof must be signed by the first attested key');
      }
      return this.capBatch(attestedKeys, maxBatch);
    }

    // Bare jwt(s): each binds its own signing key. A WUA-required config refuses these.
    if (requireKeyAttestation) throw new OAuthError('invalid_proof', 'key attestation required');
    if (jwtProofs.length > maxBatch) throw new OAuthError('invalid_credential_request', `this issuer profile allows at most ${maxBatch} credential(s) per request`);
    return this.assertDistinct(verified.map((v) => v.holderJwk));
  }

  /** Takes the first `maxBatch` attested keys (OID4VCI §14.6 lets the Issuer issue fewer) and refuses duplicates. */
  private async capBatch(keys: JWK[], maxBatch: number): Promise<JWK[]> {
    return this.assertDistinct(keys.slice(0, maxBatch));
  }

  /** Refuses duplicate holder keys — no two Credentials bound to the same key (ETSI CRED-REQ-PROC-4.6.2.1-06). */
  private async assertDistinct(keys: JWK[]): Promise<JWK[]> {
    const tps = await Promise.all(keys.map((k) => calculateJwkThumbprint(k, 'sha256')));
    if (new Set(tps).size !== tps.length) throw new OAuthError('invalid_proof', 'duplicate holder key: each Credential must bind a distinct key');
    return keys;
  }

  /** Verifies a single proof JWT's typ/jwk/signature and extracts the holder key, nonce, and header. */
  private async verifyProofSignature(proofJwt: string): Promise<{ holderJwk: JWK; nonce: string; header: Record<string, unknown> }> {
    const header = decodeProtectedHeader(proofJwt);
    if (header.typ !== 'openid4vci-proof+jwt') throw new OAuthError('invalid_proof', 'bad proof typ');
    const holderJwk = header.jwk as JWK | undefined;
    if (!holderJwk) throw new OAuthError('invalid_proof', 'proof missing jwk');
    let payload;
    try {
      // The proof `aud` is the Credential Issuer Identifier — accept any of our profile identifiers.
      ({ payload } = await jwtVerify(proofJwt, await importJWK(holderJwk, header.alg ?? 'ES256'), { audience: allCredentialIssuerIds(this.issuer) }));
    } catch {
      throw new OAuthError('invalid_proof', 'proof signature invalid');
    }
    const nonce = payload.nonce as string | undefined;
    if (!nonce) throw new OAuthError('invalid_proof', 'proof nonce required');
    return { holderJwk, nonce, header: header as Record<string, unknown> };
  }

  /** Validates the c_nonce we issued and marks it used (single-use). Shared across a batch → call once. */
  private async consumeNonce(nonce: string): Promise<void> {
    try {
      const np = await this.issuerJwt.verify(nonce, { typ: 'c_nonce+jwt', aud: this.issuer });
      if (!np.jti || !(await this.store.setOnce(`c_nonce:${np.jti}`, 300))) throw new Error('nonce replay');
    } catch {
      throw new OAuthError('invalid_nonce', 'invalid or used c_nonce');
    }
  }

  /** Issues one credential per holder key and records a `notification_id` for the batch. */
  private async issueBatch(c: CredentialConfig, holderJwks: JWK[]): Promise<{ credentials: Array<{ credential: string }>; notification_id: string }> {
    const credentials = await Promise.all(holderJwks.map((jwk) => this.issueCredential(c, jwk)));
    const notification_id = rand(16);
    await this.store.set(`notif:${notification_id}`, { configId: c.id, count: credentials.length }, 3600);
    return { credentials: credentials.map((credential) => ({ credential })), notification_id };
  }

  /**
   * Credential Response Encryption (OID4VCI §8.3 / ETSI TS 119 472-3 CRYPTO-5-01). When the request carries
   * `credential_response_encryption` = { jwk, enc } (the key-management `alg` lives in the JWK, not a top-level
   * member), the JSON response is returned as a compact JWE (ECDH-ES to the wallet's key, A128GCM/A256GCM);
   * otherwise it is returned as JSON.
   */
  private async maybeEncrypt(resp: unknown, body: Record<string, unknown>): Promise<IssuerResponse> {
    const enc = body.credential_response_encryption as { jwk?: JWK & { alg?: string }; enc?: string } | undefined;
    if (!enc) return { contentType: 'application/json', payload: resp };
    // OID4VCI 1.0: the request object is { jwk, enc } — the key-management `alg` is a member of the JWK. We
    // only support ECDH-ES.
    const alg = enc.jwk?.alg ?? 'ECDH-ES';
    if (!enc.jwk || alg !== 'ECDH-ES' || !['A128GCM', 'A256GCM'].includes(enc.enc ?? '')) {
      throw new OAuthError('invalid_encryption_parameters', 'credential_response_encryption requires a jwk (ECDH-ES) + enc A128GCM/A256GCM');
    }
    const jwe = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(resp)))
      .setProtectedHeader({ alg: 'ECDH-ES', enc: enc.enc!, ...(enc.jwk.kid ? { kid: enc.jwk.kid as string } : {}) })
      .encrypt(await importJWK(enc.jwk, 'ECDH-ES'));
    return { contentType: 'application/jwt', payload: jwe };
  }

  private async issueCredential(c: CredentialConfig, holderJwk: JWK): Promise<string> {
    const holderJkt = await calculateJwkThumbprint(holderJwk, 'sha256');
    const status = await this.statusList.recordIssuance(c.id, c.format, holderJkt);
    const now = Math.floor(Date.now() / 1000);

    if (c.format === 'dc+sd-jwt') {
      const payload = {
        iss: this.issuer,
        vct: c.vct,
        ...c.sdJwtClaims,
        iat: now,
        exp: now + 63072000, // +2 years
        cnf: { jwk: holderJwk },
        status: { status_list: { idx: status.idx, uri: status.uri } },
      };
      return this.sdJwt.issue(payload, { _sd: c.sdJwtDisclose ?? [] } as never, c.signer);
    }
    // mso_mdoc — embed the Token Status List reference in the MSO `status.status_list = { idx, uri }`
    // (ISO/IEC 18013-5 2nd edition, @lukas.j.han/mdoc >= 0.6.0) so the credential is revocable like SD-JWT VC.
    return this.mdoc.issue(c.doctype!, c.mdocNamespaces!, holderJwk, c.signer, { idx: status.idx, uri: status.uri });
  }

  listConfigs() {
    return CREDENTIAL_CONFIGS;
  }
}
