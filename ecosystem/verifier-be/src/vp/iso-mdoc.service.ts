import { Injectable, Logger } from '@nestjs/common';
import { createHash, randomBytes } from 'node:crypto';
import { type JWK } from 'jose';
import { cborEncode, cborDecode, DataItem } from '@lukas.j.han/mdoc';
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core';
import { REQUESTABLE, type RequestableCredential, type RequestableKey } from './dcql';
import { generateEncKey } from './enc-key';
import { KeystoreService, type RpProfile } from '../crypto/keystore.service';

/**
 * The `org-iso-mdoc` Digital Credentials API protocol (ISO/IEC 18013-7 Annex C) — the ISO-native alternative to
 * OpenID4VP-over-DC-API. The verifier hands the browser a CBOR `DeviceRequest` plus an `EncryptionInfo` blob
 * (a recipient HPKE public key + nonce); the wallet returns an HPKE-sealed `DeviceResponse`. There is no JAR /
 * `vp_token` envelope and no OpenID4VP metadata — the request is the raw mdoc `DeviceRequest`, and the response
 * is bound to the browser `origin` through the DC-API `SessionTranscript`.
 *
 * Each `DocRequest` carries **reader authentication** (ISO 18013-5 §9.1.4): a COSE_Sign1 over
 * `ReaderAuthentication = ["ReaderAuthentication", SessionTranscript, ItemsRequestBytes]`, signed with the
 * verifier's WRPAC reader key (x5chain in the header) — the wallet chains it to a reader trust anchor to
 * establish *who is asking*. This is the ISO analogue of the OpenID4VP signed request object.
 *
 * Response encryption is HPKE base mode (DHKEM P-256 + HKDF-SHA256 + AES-128-GCM, ISO 18013-7 §C.4), keyed by a
 * per-transaction P-256 key (the private half stays in the session; the public half is the `EncryptionInfo`
 * recipient key). This mirrors the EUDI research module's `iso-mdoc` protocol path.
 */
@Injectable()
export class IsoMdocService {
  private readonly logger = new Logger(IsoMdocService.name);

  constructor(private readonly keystore: KeystoreService) {}

  /** The credential kinds presentable over org-iso-mdoc: mso_mdoc only (SD-JWT VC has no ISO DeviceResponse). */
  static isSupportedKey(key: string): key is RequestableKey {
    const cred = REQUESTABLE[key as RequestableKey];
    return !!cred && cred.format === 'mso_mdoc';
  }

  /**
   * Builds an org-iso-mdoc session: a base64url CBOR `DeviceRequest` (one reader-authenticated `DocRequest` per
   * requested mdoc credential) and an `EncryptionInfo` carrying a fresh recipient HPKE key + nonce. Reader auth
   * is signed with the resolved RP profile's WRPAC (`plain` or `intermediary`) and bound to `origin`. Returns
   * the per-transaction private JWK (to decrypt the response) and the `EncryptionInfo`.
   */
  async createSession(
    keys: RequestableKey[],
    rp: RpProfile,
    origin: string,
  ): Promise<{ deviceRequest: string; encryptionInfo: string; nonce: string; encPrivateJwk: JWK }> {
    const mdocKeys = keys.filter((k) => IsoMdocService.isSupportedKey(k));
    if (mdocKeys.length === 0) {
      throw new Error('org-iso-mdoc requires at least one mso_mdoc credential (pid_mdoc, mdl)');
    }

    // Per-transaction recipient key for HPKE response encryption (ISO 18013-7 §C.4 — DHKEM P-256).
    const { publicJwk, privateJwk } = await generateEncKey();
    const nonce = randomBytes(16);
    const encryptionInfoPayload = ['dcapi', { nonce, recipientPublicKey: this.coseKey(publicJwk) }];
    const encryptionInfo = Buffer.from(cborEncode(encryptionInfoPayload)).toString('base64url');

    // The reader-auth SessionTranscript is bound to the (expected) origin — the wallet rebuilds the same one.
    const transcript = isoMdocTranscriptStructure(origin, encryptionInfo);
    const deviceRequest = await this.encodeDeviceRequest(mdocKeys.map((k) => REQUESTABLE[k]), transcript, rp);

    this.logger.debug(`org-iso-mdoc session built (docTypes=${mdocKeys.map((k) => REQUESTABLE[k].type).join(',')}, rp=${rp})`);
    return { deviceRequest, encryptionInfo, nonce: nonce.toString('base64url'), encPrivateJwk: privateJwk };
  }

  /** CBOR `DeviceRequest` (ISO 18013-5 §8.3.2.1.2.1): `{ version, docRequests:[{ itemsRequest, readerAuth }] }`. */
  private async encodeDeviceRequest(
    creds: RequestableCredential[],
    transcript: unknown,
    rp: RpProfile,
  ): Promise<string> {
    const docRequests = await Promise.all(
      creds.map(async (c) => {
        const nameSpaces = { [c.namespace!]: Object.fromEntries(c.claimNames.map((n) => [n, false])) };
        // ItemsRequestBytes is a tagged CBOR data item (#6.24); the SAME instance signs and rides in the request.
        const itemsRequest = DataItem.fromData({ docType: c.type, nameSpaces });
        const readerAuth = await this.buildReaderAuth(itemsRequest, transcript, rp);
        return { itemsRequest, readerAuth };
      }),
    );
    return Buffer.from(cborEncode({ version: '1.0', docRequests })).toString('base64url');
  }

  /**
   * A COSE_Sign1 reader authentication (ISO 18013-5 §9.1.4) over `ReaderAuthentication = ["ReaderAuthentication",
   * SessionTranscript, ItemsRequestBytes]` (detached payload), signed ES256 with the WRPAC key; the WRPAC chain
   * is the `x5chain` (unprotected header 33). Encoded as the untagged 4-element array the wallet parses.
   */
  private async buildReaderAuth(itemsRequest: DataItem, transcript: unknown, rp: RpProfile): Promise<unknown[]> {
    const readerAuthentication = ['ReaderAuthentication', transcript, itemsRequest];
    const readerAuthBytes = cborEncode(DataItem.fromData(readerAuthentication)); // #6.24(bstr(cbor(...)))

    const protectedHeader = cborEncode(new Map<number, number>([[1, -7]])); // { alg: ES256 }
    // Sig_structure (RFC 9052 §4.4): ["Signature1", body_protected, external_aad (empty), payload].
    const toBeSigned = cborEncode(['Signature1', protectedHeader, new Uint8Array(0), readerAuthBytes]);
    const signature = await this.keystore.signCoseRaw(toBeSigned, rp);

    const x5chain = this.keystore.readerChainDer(rp);
    const unprotected = new Map<number, unknown>([[33, x5chain]]); // x5chain: leaf-first bstr array (RFC 9360)
    return [protectedHeader, unprotected, null, signature]; // [protected bstr, unprotected map, payload null, sig]
  }

  /** The recipient public key as a COSE_Key map (EC2 / P-256) for the DC-API `EncryptionInfo`. */
  private coseKey(jwk: JWK): Map<number, number | Uint8Array> {
    const b64u = (v?: string) => new Uint8Array(Buffer.from(v ?? '', 'base64url'));
    return new Map<number, number | Uint8Array>([
      [1, 2], // kty: EC2
      [-1, 1], // crv: P-256
      [-2, b64u(jwk.x)], // x
      [-3, b64u(jwk.y)], // y
    ]);
  }

  /**
   * Decrypts the wallet's HPKE-sealed DC-API response to the base64url `DeviceResponse`. The response CBOR is
   * `[ "dcapi", { enc, cipherText } ]`; the HPKE `info` is the same SessionTranscript the DeviceResponse is
   * verified against (origin- + EncryptionInfo-bound), so a response replayed to another origin fails to open.
   */
  async decryptResponse(response: string, origin: string, encryptionInfo: string, encPrivateJwk: JWK): Promise<string> {
    const [, body] = cborDecode(Buffer.from(response, 'base64url')) as [unknown, Map<string, Uint8Array>];
    const enc = body.get('enc');
    const cipherText = body.get('cipherText');
    if (!enc || !cipherText) throw new Error('org-iso-mdoc response missing enc/cipherText');

    const info = buildIsoMdocSessionTranscript(origin, encryptionInfo);
    const toAb = (u8: Uint8Array): ArrayBuffer =>
      u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;

    const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
    const recipientKey = await suite.kem.importKey('jwk', encPrivateJwk as JsonWebKey, false);
    const recipient = await suite.createRecipientContext({ recipientKey, enc: toAb(enc), info: toAb(info) });
    const pt = await recipient.open(toAb(cipherText));
    return Buffer.from(new Uint8Array(pt)).toString('base64url');
  }
}

/**
 * The DC-API `SessionTranscript` **structure** for org-iso-mdoc (ISO/IEC 18013-7 Annex C):
 *   `[ null, null, [ "dcapi", SHA-256( CBOR([ EncryptionInfo, origin ]) ) ] ]`
 * Returned as a decodable JS structure so it can be embedded verbatim in `ReaderAuthentication`.
 */
export function isoMdocTranscriptStructure(origin: string, encryptionInfo: string): unknown {
  const dcapiInfoHash = createHash('sha256').update(cborEncode([encryptionInfo, origin])).digest();
  return [null, null, ['dcapi', new Uint8Array(dcapiInfoHash)]];
}

/**
 * The encoded org-iso-mdoc DC-API `SessionTranscript` — used as the HPKE `info` (response confidentiality) and
 * as the mdoc device-auth transcript (integrity), binding the presentation to the `EncryptionInfo` + web origin.
 */
export function buildIsoMdocSessionTranscript(origin: string, encryptionInfo: string): Uint8Array {
  return cborEncode(isoMdocTranscriptStructure(origin, encryptionInfo));
}
