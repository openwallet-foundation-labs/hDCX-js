import { plainToInstance } from 'class-transformer';
import { IsJSON, IsNotEmpty, IsOptional, IsString, validateSync } from 'class-validator';

class EnvironmentVariables {
  @IsString()
  @IsNotEmpty()
  STAGE: string;

  @IsString()
  @IsNotEmpty()
  PORT: string;

  @IsString()
  @IsNotEmpty()
  DATABASE_URL: string;

  /** The Wallet Provider issuer/base URL — the `iss` of the WUA/key-attestation JWTs and the PoP audience. */
  @IsString()
  @IsNotEmpty()
  WP_ISSUER: string;

  /** pino log level override (default: debug in non-prod, info in prod). */
  @IsOptional()
  @IsString()
  LOG_LEVEL?: string;

  /** Android app package for real Play Integrity verification (else the dev-integrity stub is used). */
  @IsOptional()
  @IsString()
  PLAY_INTEGRITY_PACKAGE_NAME?: string;

  /** Override the Android Key Attestation trust anchors (PEM bundle); default = pinned Google roots. */
  @IsOptional()
  @IsString()
  ANDROID_ATTESTATION_ROOTS?: string;

  /** Override the Android Key Attestation revocation status URL (default = Google's attestation/status). */
  @IsOptional()
  @IsString()
  ANDROID_ATTESTATION_STATUS_URL?: string;

  /**
   * Google service-account key as a JSON *string* (not a file path) for Play Integrity decode.
   * Injected as a k8s secret; parsed and handed to google-auth-library at runtime. Omit to fall
   * back to Application Default Credentials (e.g. `gcloud auth` locally).
   */
  @IsOptional()
  @IsJSON()
  GOOGLE_SERVICE_ACCOUNT_JSON?: string;
}

export function validate(config: Record<string, unknown>) {
  const validated = plainToInstance(EnvironmentVariables, config, {
    enableImplicitConversion: true,
  });
  const errors = validateSync(validated, { skipMissingProperties: false });
  if (errors.length > 0) {
    throw new Error(
      `Environment validation failed:\n${errors.map((e) => `  - ${Object.values(e.constraints ?? {}).join(', ')}`).join('\n')}`,
    );
  }
  return validated;
}
