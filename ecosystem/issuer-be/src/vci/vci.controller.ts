import { Body, Controller, Get, Header, HttpCode, Param, Post, Query, Req, Res, UseGuards } from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { KeystoreService } from '../crypto/keystore.service';
import { WalletAttestationGuard } from '../attestation/wallet-attestation.guard';
import { DpopGuard } from '../dpop/dpop.guard';
import { Dpop } from '../dpop/dpop.decorator';
import { VciService } from './vci.service';

/** OpenID4VCI 1.0 + HAIP endpoints, served under the /eudi-issuer global prefix. */
@Controller()
export class VciController {
  constructor(
    private readonly vci: VciService,
    private readonly keystore: KeystoreService,
  ) {}

  @Get('jwks.json')
  jwks() {
    const s = this.keystore.getSigner('pid');
    return { keys: [{ ...s.publicJwk, kid: s.kid, alg: 'ES256', use: 'sig' }] };
  }

  // ---- Authorization code flow ----
  @Post('par')
  @HttpCode(201)
  @UseGuards(WalletAttestationGuard)
  par(@Body() body: Record<string, string>, @Req() req: { attestation: never }) {
    return this.vci.pushAuthorizationRequest(body, req.attestation);
  }

  @Get('authorize')
  async authorize(@Query() query: Record<string, string>, @Res() reply: FastifyReply) {
    const redirect = await this.vci.authorize(query);
    void reply.redirect(redirect, 302);
  }

  // Consent handshake with issuer-fe.
  @Get('interaction/:id')
  getInteraction(@Param('id') id: string) {
    return this.vci.getInteraction(id);
  }

  @Post('interaction/:id/decide')
  @HttpCode(200)
  decide(@Param('id') id: string, @Body() body: { approve?: boolean }) {
    return this.vci.decideInteraction(id, body.approve === true);
  }

  // ---- Pre-authorized code flow (mDL) ----
  @Post('credential-offer/create')
  @HttpCode(200)
  createOffer(
    @Body()
    body: {
      credential_configuration_id: string;
      flow?: 'authorization_code' | 'pre-authorized_code';
      deferred?: boolean;
      encrypted?: boolean;
      batch_size?: number;
      tx_code?: boolean;
    },
  ) {
    return this.vci.createCredentialOffer(body.credential_configuration_id, {
      flow: body.flow,
      deferred: body.deferred === true,
      encrypted: body.encrypted === true,
      batchSize: Number(body.batch_size) === 3 ? 3 : 1,
      txCode: body.tx_code === true,
    });
  }

  @Get('credential-offer/:id')
  getOffer(@Param('id') id: string) {
    return this.vci.getCredentialOffer(id);
  }

  // ---- Token / nonce / credential ----
  @Post('token')
  @HttpCode(200)
  @Header('Cache-Control', 'no-store')
  @Dpop('as')
  @UseGuards(WalletAttestationGuard, DpopGuard)
  token(@Body() body: Record<string, string>, @Req() req: { attestation: never; dpopJkt: string }) {
    return this.vci.token(body, req.attestation, req.dpopJkt);
  }

  @Post('nonce')
  @HttpCode(200)
  @Header('Cache-Control', 'no-store')
  nonce() {
    return this.vci.nonce();
  }

  @Post('credential')
  @Dpop('rs')
  @UseGuards(DpopGuard)
  async credential(
    @Body() body: Record<string, unknown> | string,
    @Req() req: { accessToken: Record<string, unknown> },
    @Res() reply: FastifyReply,
  ) {
    // Body is JSON, or a compact JWE string (`application/jwt`) when the request is encrypted (§8.2). Response
    // is JSON, or a compact JWE when the wallet asked for an encrypted response.
    const { contentType, payload } = await this.vci.credential(body, req.accessToken);
    void reply.header('Cache-Control', 'no-store').type(contentType).send(payload);
  }

  @Post('deferred_credential')
  @Dpop('rs')
  @UseGuards(DpopGuard)
  async deferredCredential(
    @Body() body: Record<string, unknown> | string,
    @Req() req: { accessToken: Record<string, unknown> },
    @Res() reply: FastifyReply,
  ) {
    const { contentType, payload } = await this.vci.deferredCredential(body, req.accessToken);
    void reply.header('Cache-Control', 'no-store').type(contentType).send(payload);
  }

  @Post('notification')
  @HttpCode(204)
  @Header('Cache-Control', 'no-store')
  @Dpop('rs')
  @UseGuards(DpopGuard)
  notification(@Body() body: Record<string, unknown>) {
    return this.vci.notification(body);
  }
}
