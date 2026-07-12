import { ConfigService } from '@nestjs/config';
import type { Params } from 'nestjs-pino';
import type { IncomingMessage, ServerResponse } from 'node:http';

/**
 * Structured (JSON) pino logging. Health/metrics probes are not request-logged (they'd dominate), auth
 * headers are redacted, and request/response *bodies are never logged* — they carry PoP JWTs, attestations
 * and holder keys.
 */
export function createLoggerConfig(config: ConfigService): Params {
  const isProd = config.get<string>('STAGE') === 'prod';
  const level = config.get<string>('LOG_LEVEL') ?? (isProd ? 'info' : 'debug');

  const IGNORED = new Set(['/health', '/live', '/ready', '/metrics']);

  return {
    pinoHttp: {
      level,
      redact: {
        paths: ['req.headers.authorization', 'req.headers.cookie', 'req.headers.dpop'],
        censor: '[REDACTED]',
      },
      serializers: {
        req: (req: IncomingMessage) => ({ method: req.method, url: req.url }),
        res: (res: ServerResponse) => ({ statusCode: res.statusCode }),
      },
      customLogLevel: (_req, res, err) => (res.statusCode >= 500 || err ? 'error' : 'info'),
      autoLogging: {
        ignore: (req) => {
          const url = (req as IncomingMessage & { originalUrl?: string }).originalUrl ?? req.url ?? '';
          return IGNORED.has(url.split('?')[0]);
        },
      },
    },
  };
}
