# EUDI Verifier — backend

OpenID4VP 1.0 + HAIP **Relying Party**. Builds and verifies presentations of **PID** (SD-JWT VC and mdoc) and
**mDL** (mdoc) over two channels: (1) the cross-device **QR / `request_uri` + `direct_post`** flow, and
(2) the browser-native **W3C Digital Credentials API** (`response_mode=dc_api.jwt`). HAIP-conformant throughout:
JAR-signed request objects (signed with a registrar-issued **WRPAC** reader access cert — no self-signed
signing), **always-encrypted** responses (ECDH-ES JWE), and **DCQL** queries. NestJS 11 + Fastify, mirrors the
sibling `issuer-be` / `wallet-provider` (pino, Prometheus, terminus, env-loaded keys) — but holds **no relational
DB**: presentation state lives in **Redis** (`ioredis`) or an in-memory Map. Verification uses `jose`,
`@lukas.j.han/mdoc`, and `@sd-jwt/*`. TypeScript, `pnpm`.

Everything is served under a single **`API_PREFIX`** (default **`eudi-verifier`**; the dev deployment sets
`API_PREFIX=trp` → `dev.api.hopae.com/trp`). The health probes and Prometheus scrape sit under the same prefix,
so `VERIFIER_BASE_URL` **must include the prefix**. Listens on port **3500**.

## Endpoints

All paths are under the global prefix.

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/presentations` | Create a request. Body: `mode: 'qr'\|'dc_api'`, `credentials` (`pid_sd_jwt`\|`pid_mdoc`\|`mdl`), `rp: 'plain'\|'intermediary'`, `same_device`, `origins`, `dc_api_protocol: 'openid4vp'\|'org-iso-mdoc'` (dc_api only; default `openid4vp`). Returns an `openid4vp://` QR URL (`qr` mode) or a DC-API request object (`dc_api` mode) |
| GET | `/request/:id` | The signed request object (compact JWS, `application/oauth-authz-req+jwt`) — the `request_uri` target for the QR channel |
| POST | `/response/:id` | Wallet `direct_post` / `direct_post.jwt` — the encrypted JWE response is posted here |
| POST | `/presentations/:id/dc-api-response` | The frontend posts the Digital Credentials API response back |
| POST | `/presentations/exchange` | Same-device return: exchange the one-time `response_code` (from the `redirect_uri`) for the result |
| GET | `/presentations/:id` | Poll the verified result (`pending` / `verified` / `failed`, per-credential claims, plus a debug inspector view) |
| GET | `/health` · `/live` · `/ready` | terminus health probes (heap check; no DB to gate readiness) |

## Verification

`VpTokenVerifierService` verifies the DCQL-keyed `vp_token` per credential format, anchoring trust in the
JAdES Trusted Lists (`src/trust/`, PID Issuer CA + Attestation CA, ETSI TS 119 602):

- **`dc+sd-jwt`** (SD-JWT VC): the issuer JWT's `x5c` is chain-built to a trusted PID/Attestation anchor; the
  key-binding JWT is checked for the request `nonce` and audience — `origin:<origin>` for the DC API, else the
  `client_id`.
- **`mso_mdoc`** (ISO/IEC 18013-5): the `DeviceResponse` is verified against a **reconstructed OpenID4VP
  `SessionTranscript`** (channel-specific: `forOid4Vp` for QR, `forOid4VpDcApi` for the DC API, both bound to
  the response-encryption key thumbprint) plus the issuer MSO and device signature (`deviceSignature` only —
  the request metadata forbids `deviceMac`), with the leaf DSC chained to a trusted anchor.
- **Revocation**: both formats run an **IETF Token Status List** check — fetch the `statuslist+jwt`
  (`x5c` → trusted anchor, `sub == uri`), decode the zlib-DEFLATE bit array, reject a non-valid entry. A
  credential without a status reference is accepted.

Responses are always encrypted: the wallet's compact JWE is decrypted with the session's per-transaction
ECDH-ES key, with the JWE `apv` bound to the request nonce and `state` bound to the transaction.

## DC-API protocols

The Digital Credentials API channel offers **two** protocols; the frontend picks one via `dc_api_protocol`:

- **`openid4vp`** (default) — **OpenID4VP-over-DC-API** (`protocol: openid4vp-v1-signed`): the same signed JAR
  request object as the QR channel, returned inline; the response is an encrypted `dc_api.jwt` `vp_token`. Carries
  **any** requested format (SD-JWT VC and mdoc).
- **`org-iso-mdoc`** — the ISO/IEC **18013-7 Annex C** protocol (`protocol: org-iso-mdoc`): a raw CBOR
  `DeviceRequest` + an `EncryptionInfo` (recipient HPKE P-256 key + nonce), with **no** OpenID4VP envelope,
  `vp_token`, or JAR. The wallet returns an **HPKE-sealed** `DeviceResponse` (DHKEM-P256 + HKDF-SHA256 +
  AES-128-GCM). Only **mso_mdoc** credentials (`pid_mdoc`, `mdl`) are presentable this way — SD-JWT VC has no ISO
  DeviceResponse. Both the HPKE `info` and the mdoc device-auth `SessionTranscript` are
  `[null, null, ["dcapi", SHA-256(CBOR([EncryptionInfo, origin]))]]`, binding the presentation to this verifier's
  `EncryptionInfo` and the calling web origin. Handled by `src/vp/iso-mdoc.service.ts`.

  Each `DocRequest` carries **reader authentication** (ISO 18013-5 §9.1.4) — the ISO analogue of the signed
  OpenID4VP request: a COSE_Sign1 over `ReaderAuthentication = ["ReaderAuthentication", SessionTranscript,
  ItemsRequestBytes]`, signed ES256 with the RP profile's **WRPAC** key (the WRPAC chain is the `x5chain`). The
  wallet chains it to a reader trust anchor to show *who is asking* (a "trusted reader" verdict). Reader auth is
  bound to the primary `expected_origins[0]`; a wallet invoked from a different allowed origin still presents, but
  the reader shows as untrusted. There is **no** WRPRC/registrar verdict here — that transport is OpenID4VP-only.

## RP onboarding

The verifier authenticates to wallets with registrar-issued certs. The `tools/` scripts provision them against
the live RP Registrar (`REGISTRAR_URL`, default `https://api.dev.hopae.app/registrar`); the registrar signs a
leaf over a caller-supplied public key and never sees the private key.

- **`node tools/mint-rp.mjs`** — registers a **direct** RP and mints its **WRPAC** (X.509 reader access cert,
  ETSI TS 119 411-8) + **WRPRC** (`rc-wrp+jwt`, ETSI TS 119 475). Emits the JSON to drop into `VERIFIER_WRPAC`
  / `VERIFIER_WRPRC`.
- **`node tools/mint-intermediary-rp.mjs`** — the **intermediated** flow: an intermediary WRP is registered,
  the final RP is created as a mediated RP under it, and the request is signed with the **intermediary's own
  WRPAC** (ETSI TS 119 475 §5.1), while the mediated RP's WRPRC carries `sub` = final RP and
  `intermediary.sub` / `act.sub` = the intermediary. Populates the `VERIFIER_WRPAC_INTERMEDIARY` /
  `VERIFIER_WRPRC_INTERMEDIARY` profile.

## Run locally

```bash
cp .env.example .env            # then paste the WRPAC keystore JSON (from tools/mint-rp.mjs)
# Redis optional (in-memory fallback for a single replica); then:
pnpm install
pnpm build
pnpm start:prod                 # or: pnpm start:dev
```

## Configuration

| Var | Required | Purpose |
| --- | --- | --- |
| `STAGE` | yes | Deployment stage label (e.g. `dev`) |
| `PORT` | — | Listen port (default `3500`) |
| `API_PREFIX` | — | Global path prefix (default `eudi-verifier`; dev deploy: `trp`) |
| `VERIFIER_BASE_URL` | yes | Public base URL, **including the prefix** — base for `/request`, `/response`, `/presentations`, the wallet's `request_uri`/`response_uri`, and the SD-JWT KB-JWT audience. No trailing slash |
| `VERIFIER_FE_URL` | — | verifier-fe base URL (default `http://localhost:5176`); the same-device `redirect_uri` target |
| `VERIFIER_WRPAC` | yes* | Reader access cert + key JSON `{privateKeyPem,certPem,caCertPem}`, minted via `tools/mint-rp.mjs`. HAIP forbids a self-signed request-signing cert, so this is required |
| `DEV_ALLOW_EPHEMERAL_WRPAC` | — | Local-dev only: boot without `VERIFIER_WRPAC` using an ephemeral self-signed cert (default `false`; never set in prod) |
| `VERIFIER_WRPRC` | — | Registrar registration cert (compact `rc-wrp+jwt`), sent by value in `verifier_info.registration_cert` |
| `VERIFIER_WRPAC_INTERMEDIARY` / `VERIFIER_WRPRC_INTERMEDIARY` | — | The intermediated-RP profile (`rp: 'intermediary'`), from `tools/mint-intermediary-rp.mjs` |
| `VERIFIER_REGISTRAR_DATASET` | — | RP registrar dataset JSON for `verifier_info.registrar_dataset` (a minimal default is derived) |
| `TRUSTED_LIST_BASE_URL` | — | Base URL of the JAdES Trusted Lists used to verify presentations (default `https://trusted-list.vercel.app/tl`) |
| `LOG_LEVEL` | — | pino level (default `debug` non-prod, `info` prod) |
| `REDIS_URL` | — | Redis session store (shared across replicas); unset ⇒ in-memory (single-replica only). `rediss://` selects TLS |

\* required unless `DEV_ALLOW_EPHEMERAL_WRPAC=true`.

## Deploy

Container is built by the `Dockerfile` — `node:24-alpine` multi-stage, non-root (`verifier` uid 1001),
`CMD ["node", "dist/main"]`. No migration step (stateless bar Redis). The k8s manifests live in the separate
infra repo (as with `wallet-provider`). Set `API_PREFIX`, `VERIFIER_BASE_URL` (with the prefix), the WRPAC/WRPRC
secrets, `REDIS_URL`, `TRUSTED_LIST_BASE_URL`, and leave `DEV_ALLOW_EPHEMERAL_WRPAC` unset. The reference
frontend that drives this backend is live at **https://eudi-verifier.vercel.app/**.

## Standards

OpenID4VP 1.0 · OpenID4VC HAIP 1.0 · W3C Digital Credentials API · DCQL · IETF SD-JWT VC ·
ISO/IEC 18013-5 & 18013-7 (mdoc over OpenID4VP) · ETSI TS 119 475 (RP registration / WRPRC) ·
ETSI TS 119 411-8 (WRPAC) · ETSI TS 119 472-2 (`verifier_info` transport) · IETF Token Status List.
Sandbox — not a production verifier.
</content>
</invoke>
