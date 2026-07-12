import { readFileSync } from 'fs';
import { join } from 'path';
import { verifyAndroidKeyAttestation } from './android-key-attestation';

/**
 * Verifies against a real Android Key Attestation chain captured from a device (Samsung SM-F731N),
 * challenge = "eudi-attestation-challenge". Proves the WP can verify a hardware chain (validity, chain
 * signatures, revocation, pinned Google root) and derive the true storage level — the basis for asserting
 * `iso_18045_high` truthfully. `now` is pinned inside the chain's validity so the short-lived intermediate
 * (valid ~2 weeks) doesn't turn this into a time-bomb.
 */
describe('verifyAndroidKeyAttestation', () => {
  const chain = new Uint8Array(readFileSync(join(__dirname, '..', '..', '..', 'test', 'fixtures', 'key-attestation-chain.der')));
  const challenge = new TextEncoder().encode('eudi-attestation-challenge');
  const now = new Date('2026-07-15T00:00:00Z'); // inside every certificate's validity window

  it('verifies a real device chain against the pinned Google roots: hardware-backed, matching challenge', async () => {
    const verdict = await verifyAndroidKeyAttestation(chain, challenge, { now });
    expect(verdict.verified).toBe(true);
    expect(verdict.challengeMatches).toBe(true);
    expect(['trustedEnvironment', 'strongBox']).toContain(verdict.securityLevel);
  });

  it('rejects a wrong challenge (anti-replay)', async () => {
    const verdict = await verifyAndroidKeyAttestation(chain, new TextEncoder().encode('a-different-nonce'), { now });
    expect(verdict.verified).toBe(true); // chain is still valid
    expect(verdict.challengeMatches).toBe(false); // but the challenge does not match
  });

  it('rejects a chain that does not root in a Google attestation root', async () => {
    // Flip a byte in the last (root) certificate region so the root thumbprint no longer matches.
    const tampered = new Uint8Array(chain);
    tampered[tampered.length - 40] ^= 0xff;
    const verdict = await verifyAndroidKeyAttestation(tampered, challenge, { now });
    expect(verdict.verified).toBe(false);
  });

  it('rejects an expired chain (validity-period check)', async () => {
    const verdict = await verifyAndroidKeyAttestation(chain, challenge, { now: new Date('2026-08-01T00:00:00Z') });
    expect(verdict.verified).toBe(false);
    expect(verdict.reason).toMatch(/validity period/);
  });

  it('rejects a chain whose certificate is revoked by Google', async () => {
    // The device leaf/intermediate carries this serial; simulate it appearing in Google's status list.
    const revokedSerials = new Set(['7d0404735dff5187f8f851289bc21eb0']);
    const verdict = await verifyAndroidKeyAttestation(chain, challenge, { now, revokedSerials });
    expect(verdict.verified).toBe(false);
    expect(verdict.reason).toMatch(/revoked or suspended/);
  });
});
