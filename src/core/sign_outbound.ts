import { SignJWT } from 'jose';
import { JumpError, type OutboundJumpClaim } from './types';

type SignKey = Parameters<SignJWT['sign']>[0];

export interface OutboundSigner {
  sign(claim: OutboundJumpClaim): Promise<string>;
  readonly kid: string;
}

export class JoseOutboundSigner implements OutboundSigner {
  constructor(
    private readonly privateKey: SignKey,
    readonly kid: string,
    private readonly alg = 'ES384',
  ) {}

  async sign(claim: OutboundJumpClaim): Promise<string> {
    return new SignJWT(claim)
      .setProtectedHeader({ typ: 'JWT', alg: this.alg, kid: this.kid })
      .sign(this.privateKey);
  }
}

export class NoopOutboundSigner implements OutboundSigner {
  readonly kid = 'noop';

  async sign(): Promise<string> {
    throw new JumpError('signer_unavailable', 'outbound signer not configured');
  }
}
