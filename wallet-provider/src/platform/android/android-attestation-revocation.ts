import { Injectable, Logger } from '@nestjs/common';
import { normalizeSerial } from './android-key-attestation';

const DEFAULT_STATUS_URL = 'https://android.googleapis.com/attestation/status';
const FALLBACK_TTL_SECONDS = 24 * 60 * 60;

/**
 * Google's Android Key Attestation revocation status list (the set of revoked/suspended certificate serials).
 * Fetched from https://android.googleapis.com/attestation/status and cached per its Cache-Control. The list
 * changes over time, so it is fetched at runtime (not pinned). Fail-open: if it can't be fetched we keep the
 * last-good copy, or proceed without revocation and warn — a Google outage must not block all attestations.
 */
@Injectable()
export class AndroidAttestationRevocation {
  private readonly logger = new Logger(AndroidAttestationRevocation.name);
  private cache: { serials: Set<string>; expiresAt: number } | null = null;

  async getRevokedSerials(): Promise<Set<string>> {
    const now = Date.now();
    if (this.cache && this.cache.expiresAt > now) return this.cache.serials;

    const url = process.env.ANDROID_ATTESTATION_STATUS_URL ?? DEFAULT_STATUS_URL;
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = (await res.json()) as { entries?: Record<string, unknown> };
      const serials = new Set<string>();
      for (const serial of Object.keys(body.entries ?? {})) serials.add(normalizeSerial(serial));

      const ttl = parseMaxAge(res.headers.get('cache-control')) ?? FALLBACK_TTL_SECONDS;
      this.cache = { serials, expiresAt: now + ttl * 1000 };
      this.logger.log(`loaded ${serials.size} revoked attestation serials (ttl ${ttl}s)`);
      return serials;
    } catch (e) {
      this.logger.warn(
        `could not fetch attestation revocation list (${(e as Error).message}); ` +
          (this.cache ? 'using last-good copy' : 'proceeding without revocation checks'),
      );
      return this.cache?.serials ?? new Set();
    }
  }
}

function parseMaxAge(cacheControl: string | null): number | undefined {
  const match = cacheControl?.match(/max-age=(\d+)/);
  return match ? Number(match[1]) : undefined;
}
