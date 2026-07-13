import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import type { RpProfile } from '../crypto/keystore.service';

/**
 * A presentation session: the state a verifier holds between issuing a request and verifying the wallet's
 * response. Keyed by an opaque transaction id.
 */
export interface PresentationSession {
  id: string;
  /** The `nonce` bound into the request (and checked against the vp_token / key-binding). */
  nonce: string;
  /** The credential kinds requested (for result shaping). */
  requested: string[];
  /** Delivery channel: `qr` (request_uri + direct_post) or `dc_api` (Digital Credentials API). */
  mode: 'qr' | 'dc_api';
  /** Same-device flow: only then does the verifier return a `redirect_uri` + one-time response_code (HAIP). */
  sameDevice: boolean;
  /** Which RP profile signed the request (its client_id binds the response / mdoc SessionTranscript). */
  rp: RpProfile;
  /** The signed request object (compact JWS) served at `/request/:id` or embedded for the DC API. */
  requestJwt: string;
  /** Web origins the DC API response may come from (dc_api mode only). */
  expectedOrigins?: string[];
  /** Per-transaction ephemeral response-encryption key (ECDH-ES). The public JWK rode in client_metadata;
   *  the private JWK decrypts the wallet's JWE response. `encKid` is the key id echoed in the JWE header. */
  encPrivateJwk?: Record<string, unknown>;
  encPublicJwk?: Record<string, unknown>;
  encKid?: string;
  createdAt: number;
  /** The raw vp_token the wallet submitted (DCQL-keyed raw presentations), kept for the debug inspector. */
  submittedVpToken?: Record<string, unknown>;
  /** Populated once the wallet responds and the vp_token is verified (or verification fails). */
  result?: PresentationResult;
}

export interface PresentationResult {
  status: 'verified' | 'failed';
  /** Per-credential verified claims, keyed by DCQL query id. */
  credentials?: Array<{ queryId: string; format: string; type: string; claims: Record<string, unknown> }>;
  error?: string;
  verifiedAt: number;
}

/**
 * Short-lived presentation state. Redis-backed when `REDIS_URL` is set (shared across replicas, production);
 * otherwise an in-memory Map with lazy TTL expiry (single-replica dev). Keys are namespaced `trp:pres:` so
 * the verifier can share a Redis instance/DB with other services without collisions.
 */
@Injectable()
export class SessionStore implements OnModuleDestroy {
  private readonly logger = new Logger(SessionStore.name);
  private readonly redis?: Redis;
  private readonly mem = new Map<string, { session: PresentationSession; exp: number }>();
  private readonly ttlSec = 10 * 60; // presentation requests are short-lived
  private readonly prefix = 'trp:pres:';

  constructor(config: ConfigService) {
    const url = config.get<string>('REDIS_URL');
    if (url) {
      // `rediss://` selects TLS automatically (ElastiCache in-transit encryption).
      this.redis = new Redis(url, { maxRetriesPerRequest: 3, lazyConnect: false, keyPrefix: this.prefix });
      this.redis.on('error', (e) => this.logger.error(`redis: ${e.message}`));
      this.logger.log('session state: Redis');
    } else {
      this.logger.warn('REDIS_URL unset — using in-memory session state (single-replica only)');
    }
  }

  async put(session: PresentationSession): Promise<void> {
    if (this.redis) {
      await this.redis.set(session.id, JSON.stringify(session), 'EX', this.ttlSec);
    } else {
      this.mem.set(session.id, { session, exp: Date.now() + this.ttlSec * 1000 });
    }
  }

  async get(id: string): Promise<PresentationSession | undefined> {
    if (this.redis) {
      const v = await this.redis.get(id);
      return v ? (JSON.parse(v) as PresentationSession) : undefined;
    }
    const e = this.mem.get(id);
    if (!e) return undefined;
    if (e.exp < Date.now()) {
      this.mem.delete(id);
      return undefined;
    }
    return e.session;
  }

  // --- one-time response_code -> transaction id (HAIP same-device redirect binding) ---
  private readonly memRc = new Map<string, { id: string; exp: number }>();

  /** Binds a fresh one-time response_code to a transaction (OpenID4VP §8.2 / HAIP same-device return). */
  async bindResponseCode(code: string, transactionId: string): Promise<void> {
    if (this.redis) {
      await this.redis.set(`rc:${code}`, transactionId, 'EX', this.ttlSec);
    } else {
      this.memRc.set(code, { id: transactionId, exp: Date.now() + this.ttlSec * 1000 });
    }
  }

  /** Resolves + consumes (single-use) a response_code to its transaction id, or undefined if unknown/expired. */
  async resolveResponseCode(code: string): Promise<string | undefined> {
    if (this.redis) {
      const id = await this.redis.getdel(`rc:${code}`);
      return id ?? undefined;
    }
    const e = this.memRc.get(code);
    this.memRc.delete(code);
    if (!e || e.exp < Date.now()) return undefined;
    return e.id;
  }

  async onModuleDestroy() {
    await this.redis?.quit();
  }
}
