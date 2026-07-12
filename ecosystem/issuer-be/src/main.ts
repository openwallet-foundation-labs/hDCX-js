import { NestFactory } from '@nestjs/core';
import { RequestMethod, ValidationPipe } from '@nestjs/common';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { Logger } from 'nestjs-pino';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter({ trustProxy: true }),
    { bufferLogs: true },
  );
  app.useLogger(app.get(Logger));
  app.enableShutdownHooks();

  // Wallets read DPoP-Nonce (RFC 9449) and WWW-Authenticate cross-origin.
  app.enableCors({ exposedHeaders: ['DPoP-Nonce', 'WWW-Authenticate'] });

  // OAuth token/PAR use application/x-www-form-urlencoded, which the Nest Fastify adapter already parses into
  // an object. We only add the OpenID4VCI encrypted-credential-request parser (raw JWE string).
  const fastify = app.getHttpAdapter().getInstance();
  fastify.addContentTypeParser('application/jwt', { parseAs: 'string' }, (_req, body, done) => {
    done(null, body);
  });

  app.useGlobalPipes(new ValidationPipe({ whitelist: false, transform: true }));

  // VCI endpoints are served under /eudi-issuer (the Credential Issuer identifier is `${origin}/eudi-issuer`).
  // Kept at the root: the OpenID4VCI / OAuth metadata (RFC 8414 places `.well-known/...` at the origin root
  // with the issuer path segment appended) and the infra probes (health/live/ready) + metrics scrape.
  app.setGlobalPrefix('eudi-issuer', {
    exclude: [
      { path: '.well-known/openid-credential-issuer/eudi-issuer', method: RequestMethod.GET },
      { path: '.well-known/oauth-authorization-server/eudi-issuer', method: RequestMethod.GET },
      { path: 'health', method: RequestMethod.GET },
      { path: 'live', method: RequestMethod.GET },
      { path: 'ready', method: RequestMethod.GET },
      { path: 'metrics', method: RequestMethod.GET },
    ],
  });

  const port = process.env.PORT ?? 3400;
  await app.listen(port, '0.0.0.0');
  app.get(Logger).log(`EUDI Issuer listening on :${port}`, 'Bootstrap');
}
void bootstrap();
