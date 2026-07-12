import { Module } from '@nestjs/common';
import { AndroidVerifier } from './android/android.verifier';
import { AndroidAttestationRevocation } from './android/android-attestation-revocation';
import { IosVerifier } from './ios/ios.verifier';
import { PLATFORM_VERIFIERS, PlatformVerifierRegistry } from './platform-verifier';

/** Registers the per-platform integrity/attestation verifiers behind a lookup registry. */
@Module({
  providers: [
    AndroidAttestationRevocation,
    AndroidVerifier,
    IosVerifier,
    {
      provide: PLATFORM_VERIFIERS,
      useFactory: (android: AndroidVerifier, ios: IosVerifier) => [android, ios],
      inject: [AndroidVerifier, IosVerifier],
    },
    PlatformVerifierRegistry,
  ],
  exports: [PlatformVerifierRegistry],
})
export class PlatformModule {}
