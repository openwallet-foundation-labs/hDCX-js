import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { type JWK } from 'jose';
import { KeystoreService, type RpProfile } from '../crypto/keystore.service';
import { buildDcqlQuery, type RequestableKey } from './dcql';
import { encClientMetadataJwk } from './enc-key';

export interface BuiltRequest {
  /** The signed request object (compact JWS). */
  jwt: string;
  /** The nonce bound into the request. */
  nonce: string;
}

/** The per-transaction response-encryption key advertised in client_metadata. */
export interface EncKeyInput {
  publicJwk: JWK;
  kid: string;
}

/**
 * Assembles + signs OpenID4VP request objects (JAR, RFC 9101) with the WRPAC key. The RP registration cert
 * (WRPRC) rides in `verifier_info` per ETSI TS 119 472-2 §6.3: a `registrar_dataset` element (the RP dataset)
 * plus a `registration_cert` element (`base64url(WRPRC)`). Two channels:
 *   - `qr`     — `response_mode=direct_post`, a `response_uri` the wallet POSTs the vp_token to.
 *   - `dc_api` — `response_mode=dc_api`, with `expected_origins`, returned inline by the Digital Credentials API.
 */
@Injectable()
export class RequestBuilderService {
  private readonly logger = new Logger(RequestBuilderService.name);
  private readonly baseUrl: string;
  private readonly registrarDataset: Record<string, unknown>;

  constructor(
    private readonly keystore: KeystoreService,
    config: ConfigService,
  ) {
    this.baseUrl = config.getOrThrow<string>('VERIFIER_BASE_URL').replace(/\/$/, '');
    const raw = config.get<string>('VERIFIER_REGISTRAR_DATASET');
    this.registrarDataset = raw
      ? (JSON.parse(raw) as Record<string, unknown>)
      : {
          // Minimal dataset (ETSI TS 119 472-2 REQ-RO-04..12) — override via VERIFIER_REGISTRAR_DATASET.
          identifier: [{ type: 'VAT', value: 'LU' }],
          srvDescription: [{ lang: 'en', content: 'Hopae Demo Verifier' }],
          registryURI: `${this.baseUrl}`,
          purpose: [{ lang: 'en', content: 'Age verification' }],
          policyURI: [{ type: 'privacy', uri: `${this.baseUrl}/privacy` }],
        };
  }

  /** The QR/request_uri channel: encrypted direct_post.jwt to `${base}/response/:id`. Signs with the RP profile. */
  async buildForQr(
    transactionId: string,
    keys: RequestableKey[],
    nonce: string,
    rp: RpProfile,
    enc: EncKeyInput,
  ): Promise<BuiltRequest> {
    const payload = {
      ...this.commonClaims(keys, nonce, rp),
      response_mode: 'direct_post.jwt',
      response_uri: `${this.baseUrl}/response/${transactionId}`,
      state: transactionId,
      client_metadata: this.clientMetadata(enc),
    };
    return { jwt: await this.keystore.signRequestObject(payload, rp), nonce };
  }

  /** The Digital Credentials API channel: encrypted dc_api.jwt, returned inline; bound to the calling origin. */
  async buildForDcApi(
    keys: RequestableKey[],
    nonce: string,
    expectedOrigins: string[],
    rp: RpProfile,
    enc: EncKeyInput,
  ): Promise<BuiltRequest> {
    const payload = {
      ...this.commonClaims(keys, nonce, rp),
      response_mode: 'dc_api.jwt',
      expected_origins: expectedOrigins,
      client_metadata: this.clientMetadata(enc),
    };
    return { jwt: await this.keystore.signRequestObject(payload, rp), nonce };
  }

  /**
   * `client_metadata` advertising the response-encryption key + parameters (HAIP mandates encrypted responses).
   * The wallet encrypts to the `alg=ECDH-ES` JWK (matching its `kid`); `encrypted_response_enc_values_supported`
   * selects A256GCM; `deviceauth_alg_values` offers the P-256 mdoc `deviceMac` alg (OpenID4VP App. B.2.2).
   */
  private clientMetadata(enc: EncKeyInput): Record<string, unknown> {
    return {
      jwks: { keys: [encClientMetadataJwk(enc.publicJwk, enc.kid)] },
      encrypted_response_enc_values_supported: ['A256GCM'],
      vp_formats_supported: { mso_mdoc: { deviceauth_alg_values: [-65537] } },
    };
  }

  private commonClaims(keys: RequestableKey[], nonce: string, rp: RpProfile): Record<string, unknown> {
    return {
      client_id: this.keystore.clientId(rp),
      response_type: 'vp_token',
      nonce,
      dcql_query: buildDcqlQuery(keys),
      verifier_info: this.verifierInfo(rp),
    };
  }

  /**
   * `verifier_info` (ETSI TS 119 472-2 §6.3 / OpenID4VP): the RP registrar dataset + the WRPRC by value.
   * Neither element carries `credential_ids` (REQ-RO-03/14). The `registration_cert` element is present only
   * when a WRPRC is configured (else the wallet simply has no RP registration to surface).
   */
  private verifierInfo(rp: RpProfile): Array<{ format: string; data: unknown }> {
    const info: Array<{ format: string; data: unknown }> = [{ format: 'registrar_dataset', data: this.registrarDataset }];
    const wrprc = this.keystore.wrprc(rp);
    if (wrprc) {
      info.push({ format: 'registration_cert', data: Buffer.from(wrprc, 'utf8').toString('base64url') });
    }
    return info;
  }
}
