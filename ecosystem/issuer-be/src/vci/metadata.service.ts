import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CREDENTIAL_CONFIGS, type CredentialConfig } from './credential-configs';
import { IssuerJwtService } from '../jwt/issuer-jwt.service';
import { RequestEncryptionService } from '../crypto/request-encryption.service';
import { ISSUER_PROFILES, credentialIssuerId, type IssuerProfile } from './issuer-profiles';

// The `jwt` proof type. `key_attestations_required` (HAIP §4.5.1 / ETSI TS 119 472-3 CRED-REQ-4.6.1.2-03)
// is advertised PER credential config — only for those that mandate a Key Attestation (the WUA). See
// `CredentialConfig.keyAttestationRequired` (default true).
const JWT_PROOF_SIGNING = { proof_signing_alg_values_supported: ['ES256'] };
const KEY_ATTESTATIONS_REQUIRED = { key_storage: ['iso_18045_moderate', 'iso_18045_high'] };

/**
 * Builds the OpenID4VCI 1.0 Credential Issuer metadata and the RFC 8414 Authorization Server metadata from
 * the credential configs. The AS is the Issuer itself. Everything is derived from `ISSUER_BASE_URL` (the
 * credential issuer identifier, which already includes the /eudi-issuer path segment).
 *
 * Per ETSI TS 119 472-3 the Credential Issuer metadata is served as **signed metadata** (OpenID4VCI §12.2.3):
 * a JWS whose x5c carries the Issuer's access certificate (ISS-MDATA-4.2.1/ACC_CERT-4.2.2) and whose payload
 * carries `issuer_info` = the Provider's registrar_dataset (+ optional registration_cert) so the wallet can see
 * and verify who the issuer is and what it is registered to issue (ISS-MDATA-REG_CERT-4.2.3).
 */
@Injectable()
export class MetadataService {
  constructor(
    private readonly config: ConfigService,
    private readonly issuerJwt: IssuerJwtService,
    private readonly reqEnc: RequestEncryptionService,
  ) {}

  private get iss(): string {
    return this.config.getOrThrow<string>('ISSUER_BASE_URL');
  }

  /**
   * The signed Credential Issuer metadata (ETSI TS 119 472-3 ISS-MDATA-4.2.1-01, OpenID4VCI §12.2.3). Returns
   * the plain metadata object PLUS a `signed_metadata` compact JWS (ES256, `x5c` = access cert, `iss`/`sub` =
   * credential_issuer, `iat`) whose payload additionally carries the top-level `issuer_info` array. We also echo
   * `issuer_info` unsigned for the benefit of clients that don't parse `signed_metadata`.
   */
  async signedCredentialIssuerMetadata(profile: IssuerProfile = ISSUER_PROFILES[0]) {
    const metadata = this.credentialIssuerMetadata(profile);
    const issuer_info = this.issuerInfo();
    const signed_metadata = await this.issuerJwt.sign(
      { ...metadata, issuer_info },
      // Signed with the Provider's ACCESS certificate in x5c (ETSI TS 119 472-3 ISS-MDATA-4.2.1-02/ACC_CERT-4.2.2),
      // NOT a Document Signer; iss = sub = this profile's Credential Issuer Identifier (OID4VCI §12.2.3).
      { typ: 'openidvci-issuer-metadata+jwt', x5c: true, signerType: 'access', iss: metadata.credential_issuer, sub: metadata.credential_issuer },
    );
    return { ...metadata, issuer_info, signed_metadata };
  }

  /**
   * `issuer_info` — same structure as OpenID4VP `verifier_info` (ISS-MDATA-REG_CERT-4.2.3-03): an array of
   * `{ format, data }`. The mandatory `registrar_dataset` element carries the Provider's registration info
   * (identifier, srvDescription, registryURI, providesAttestations); a `registration_cert` element is added
   * only when the Provider has a registrar-issued registration certificate configured.
   */
  private issuerInfo(): Array<{ format: string; data: unknown }> {
    const info: Array<{ format: string; data: unknown }> = [
      { format: 'registrar_dataset', data: this.registrarDataset() },
    ];
    const regCert = this.config.get<string>('ISSUER_REGISTRATION_CERT')?.trim();
    if (regCert) {
      // 4.2.3-04..06: the registration certificate carried by value (base64url of the compact JWS).
      info.unshift({ format: 'registration_cert', data: Buffer.from(regCert, 'utf8').toString('base64url') });
    }
    return info;
  }

  /**
   * The Provider's `registrar_dataset` (ETSI TS 119 475 Annex B). `identifier`/`srvDescription`/`registryURI`
   * come from `ISSUER_REGISTRAR_DATASET` (JSON) when set, else a sandbox default; `providesAttestations` is
   * always derived from what this Issuer actually issues (ISS-MDATA-REG_CERT-4.2.3-13).
   */
  private registrarDataset(): Record<string, unknown> {
    const raw = this.config.get<string>('ISSUER_REGISTRAR_DATASET');
    const base = (raw ? JSON.parse(raw) : null) ?? {
      identifier: [{ type: 'http://data.europa.eu/eudi/id/LEI', identifier: 'HOPAE-EUDI-SANDBOX-ISSUER-LU-01' }],
      srvDescription: [{ lang: 'en', content: 'Hopae EUDI Sandbox Issuer' }],
      registryURI: 'https://api.dev.hopae.app/registrar/registry',
    };
    return { ...base, providesAttestations: base.providesAttestations ?? this.providesAttestations() };
  }

  /** The attestation types this Issuer is registered to issue (TS05 §2.1) — one entry per credential config. */
  private providesAttestations(): Array<{ format: string; meta: Record<string, unknown> }> {
    const seen = new Set<string>();
    const out: Array<{ format: string; meta: Record<string, unknown> }> = [];
    for (const c of CREDENTIAL_CONFIGS) {
      const meta = c.format === 'dc+sd-jwt' ? { vct_values: [c.vct] } : { doctype_value: c.doctype };
      const key = `${c.format}:${JSON.stringify(meta)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ format: c.format, meta });
    }
    return out;
  }

  /**
   * Credential Issuer Metadata for a profile. All profiles share the base endpoints + authorization server;
   * `credential_issuer` is the profile's identifier and `encryption_required` / `batch_size` reflect its policy.
   */
  credentialIssuerMetadata(profile: IssuerProfile = ISSUER_PROFILES[0]) {
    const iss = this.iss; // base — the real endpoints live here for every profile
    const credential_configurations_supported: Record<string, unknown> = {};
    for (const c of CREDENTIAL_CONFIGS) {
      credential_configurations_supported[c.id] = this.configMetadata(c);
    }
    return {
      credential_issuer: credentialIssuerId(iss, profile),
      authorization_servers: [iss],
      credential_endpoint: `${iss}/credential`,
      nonce_endpoint: `${iss}/nonce`,
      deferred_credential_endpoint: `${iss}/deferred_credential`,
      notification_endpoint: `${iss}/notification`,
      // OID4VCI: batch_size MUST be >= 2, so advertise batch_credential_issuance only on the batch profiles;
      // a batch_size of 1 (single issuance) is the default and is expressed by omitting the member.
      ...(profile.batch >= 2 ? { batch_credential_issuance: { batch_size: profile.batch } } : {}),
      // Credential Response Encryption (OID4VCI §8.3 / ETSI TS 119 472-3 CRYPTO-5-01). `encryption_required`
      // is the standard lever the wallet obeys — true on the `enc` profiles forces an encrypted response.
      credential_response_encryption: {
        alg_values_supported: ['ECDH-ES'],
        enc_values_supported: ['A128GCM', 'A256GCM'],
        encryption_required: profile.enc,
      },
      // Credential Request Encryption (OID4VCI §8.2 / §12.2). §8.2: the wallet MUST encrypt the request whenever
      // it asks for an encrypted response — so this is required on the `enc` profiles (jwks = issuer key).
      credential_request_encryption: {
        jwks: [this.reqEnc.publicJwk()],
        enc_values_supported: ['A128GCM', 'A256GCM'],
        encryption_required: profile.enc,
      },
      display: [{ name: 'Hopae EUDI Sandbox Issuer', locale: 'en' }],
      credential_configurations_supported,
    };
  }

  private configMetadata(c: CredentialConfig) {
    // Advertise key_attestations_required — and the standalone `attestation` proof type — only when this config
    // mandates a WUA (default: true). A non-WUA config (e.g. the demo mDL) offers just the bare `jwt` proof type.
    const proof_types_supported =
      c.keyAttestationRequired === false
        ? { jwt: JWT_PROOF_SIGNING }
        : {
            jwt: { ...JWT_PROOF_SIGNING, key_attestations_required: KEY_ATTESTATIONS_REQUIRED },
            attestation: { ...JWT_PROOF_SIGNING, key_attestations_required: KEY_ATTESTATIONS_REQUIRED },
          };
    const common = {
      scope: c.scope,
      cryptographic_binding_methods_supported: c.format === 'mso_mdoc' ? ['cose_key'] : ['jwk'],
      credential_signing_alg_values_supported: ['ES256'],
      proof_types_supported,
      display: [
        {
          name: c.display.name,
          locale: c.display.locale,
          background_color: c.display.background_color,
          text_color: c.display.text_color,
        },
      ],
    };
    if (c.format === 'dc+sd-jwt') {
      return { format: 'dc+sd-jwt', vct: c.vct, ...common };
    }
    return { format: 'mso_mdoc', doctype: c.doctype, ...common };
  }

  authorizationServerMetadata() {
    const iss = this.iss;
    return {
      issuer: iss,
      authorization_endpoint: `${iss}/authorize`,
      pushed_authorization_request_endpoint: `${iss}/par`,
      require_pushed_authorization_requests: true,
      token_endpoint: `${iss}/token`,
      jwks_uri: `${iss}/jwks.json`,
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: [
        'authorization_code',
        'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'refresh_token',
      ],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['attest_jwt_client_auth'],
      token_endpoint_auth_signing_alg_values_supported: ['ES256'],
      dpop_signing_alg_values_supported: ['ES256'],
      authorization_response_iss_parameter_supported: true,
      scopes_supported: CREDENTIAL_CONFIGS.map((c) => c.scope),
    };
  }
}
