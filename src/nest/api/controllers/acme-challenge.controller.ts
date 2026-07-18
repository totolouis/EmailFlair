import { Controller, Get, Param, Res } from '@nestjs/common';
import { Response } from 'express';

let acmeManagerRef: { getChallengeResponse: (token: string) => string | undefined } | null = null;

export function setAcmeManagerRef(ref: typeof acmeManagerRef) {
  acmeManagerRef = ref;
}

@Controller('.well-known/acme-challenge')
export class AcmeChallengeController {
  @Get(':token')
  getChallenge(@Param('token') token: string, @Res() res: Response) {
    if (!acmeManagerRef) {
      res.status(404).end();
      return;
    }
    const keyAuth = acmeManagerRef.getChallengeResponse(token);
    if (keyAuth) {
      res.end(keyAuth);
    } else {
      res.status(404).end();
    }
  }
}