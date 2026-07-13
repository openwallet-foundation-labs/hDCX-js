import { Body, Controller, Get, Header, HttpCode, NotFoundException, Param, Post } from '@nestjs/common';
import { VpService, type CreatePresentationInput } from './vp.service';

/**
 * OpenID4VP verifier endpoints (served under the `/eudi-verifier` global prefix):
 *   POST /presentations            — create a request (QR openid4vp:// URL, or a DC API request object)
 *   GET  /request/:id              — the signed request object (request_uri target for the QR channel)
 *   POST /response/:id             — direct_post response_uri (the wallet POSTs { vp_token, state })
 *   POST /presentations/:id/dc-api-response — the frontend posts back the Digital Credentials API response
 *   GET  /presentations/:id        — poll the verification result
 */
@Controller()
export class VpController {
  constructor(private readonly vp: VpService) {}

  @Post('presentations')
  async create(@Body() body: CreatePresentationInput) {
    return this.vp.createPresentation(body ?? {});
  }

  @Get('request/:id')
  @Header('Content-Type', 'application/oauth-authz-req+jwt')
  async request(@Param('id') id: string): Promise<string> {
    try {
      return await this.vp.getRequestJwt(id);
    } catch {
      throw new NotFoundException('unknown or expired transaction');
    }
  }

  @Post('response/:id')
  @HttpCode(200)
  async respond(@Param('id') id: string, @Body() body: Record<string, unknown>) {
    return this.vp.submitDirectPost(id, body ?? {});
  }

  @Post('presentations/:id/dc-api-response')
  @HttpCode(200)
  async dcApiResponse(@Param('id') id: string, @Body() body: { vp_token?: unknown; response?: string; origin?: string }) {
    return this.vp.submitDcApi(id, body ?? {});
  }

  /** Same-device return: the frontend (reopened via the redirect_uri) exchanges the one-time response_code. */
  @Post('presentations/exchange')
  @HttpCode(200)
  async exchange(@Body() body: { response_code?: string }) {
    if (!body?.response_code) throw new NotFoundException('missing response_code');
    try {
      return await this.vp.exchangeResponseCode(body.response_code);
    } catch {
      throw new NotFoundException('unknown or expired response_code');
    }
  }

  @Get('presentations/:id')
  async result(@Param('id') id: string) {
    try {
      return await this.vp.getResult(id);
    } catch {
      throw new NotFoundException('unknown or expired transaction');
    }
  }
}
