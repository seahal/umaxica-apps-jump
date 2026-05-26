import { JumpError, type InboundJumpClaim, type IssuerConfig } from './types';
import type { NormalizedUrl } from './normalize_url';

export function assertDestinationPolicy(
  claim: InboundJumpClaim,
  issuer: IssuerConfig,
  target: NormalizedUrl,
) {
  if (claim.dst === 'internal') {
    if (!issuer.allowed_dst_internal.includes(target.origin)) {
      throw new JumpError('invalid_dst', 'internal destination rejected');
    }
    return;
  }

  if (claim.dst === 'external') {
    const allowed = issuer.allowed_dst_external;
    if (allowed === true) return;
    if (Array.isArray(allowed) && allowed.includes(target.origin)) return;
    throw new JumpError('invalid_dst', 'external destination rejected');
  }

  throw new JumpError('invalid_dst', 'unknown dst');
}
