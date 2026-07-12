import { Injectable, NestInterceptor, ExecutionContext, CallHandler, Logger } from '@nestjs/common';
import { Observable, tap, catchError } from 'rxjs';
import { InjectMetric } from '@willsoto/nestjs-prometheus';
import { Histogram } from 'prom-client';

export const HTTP_REQUEST_DURATION = 'http_request_duration_seconds';

// Route templates that must not be timed — health probes and the metrics scrape would dominate the series.
const EXCLUDED_ROUTES = new Set(['/health', '/live', '/ready', '/metrics']);

@Injectable()
export class HttpMetricsInterceptor implements NestInterceptor {
  private readonly logger = new Logger(HttpMetricsInterceptor.name);

  constructor(
    @InjectMetric(HTTP_REQUEST_DURATION)
    private readonly httpRequestDuration: Histogram,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const ctx = context.switchToHttp();
    const request = ctx.getRequest();
    // Fastify exposes the matched route template (low cardinality) here; unmatched requests are skipped.
    const route: string | undefined = request.routeOptions?.url;

    if (!route || EXCLUDED_ROUTES.has(route)) {
      return next.handle();
    }

    const method: string = request.method;
    const end = this.httpRequestDuration.startTimer();

    return next.handle().pipe(
      tap(() => {
        try {
          end({ method, route, status_code: ctx.getResponse().statusCode });
        } catch (e) {
          this.logger.warn(e, 'Failed to record HTTP metrics');
        }
      }),
      catchError((err: unknown) => {
        try {
          const error = err as { status?: number; getStatus?: () => number };
          end({ method, route, status_code: error?.status ?? error?.getStatus?.() ?? 500 });
        } catch (e) {
          this.logger.warn(e, 'Failed to record HTTP metrics');
        }
        throw err;
      }),
    );
  }
}
