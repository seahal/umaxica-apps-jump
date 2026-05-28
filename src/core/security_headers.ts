import type { Context, Next } from 'hono';
import { secureHeaders } from 'hono/secure-headers';

export const CUSHION_INLINE_SCRIPT = 'history.replaceState(null,"",location.pathname)';
const CUSHION_INLINE_SCRIPT_SHA256 = '8A+3er73YJf04rRHGhbZwZQACPiiipi9EPduIeAAIDk=';
const STRICT_TRANSPORT_SECURITY = 'max-age=63072000; includeSubDomains; preload';

export function jumpSecureHeaders() {
  return secureHeaders({
    contentSecurityPolicy: {
      defaultSrc: ["'none'"],
      baseUri: ["'none'"],
      formAction: ["'none'"],
      frameAncestors: ["'none'"],
      imgSrc: ["'self'"],
      scriptSrc: [`'sha256-${CUSHION_INLINE_SCRIPT_SHA256}'`],
      styleSrc: ["'none'"],
    },
    crossOriginEmbedderPolicy: true,
    strictTransportSecurity: STRICT_TRANSPORT_SECURITY,
    xContentTypeOptions: 'nosniff',
    xFrameOptions: 'DENY',
    referrerPolicy: 'no-referrer',
    permissionsPolicy: {
      accelerometer: [],
      camera: [],
      geolocation: [],
      gyroscope: [],
      microphone: [],
      payment: [],
      usb: [],
    },
    removePoweredBy: true,
  });
}

export async function responseHygiene(c: Context, next: Next) {
  await next();
  c.header('Cache-Control', 'no-store');
  c.res.headers.set('Strict-Transport-Security', STRICT_TRANSPORT_SECURITY);
  c.header('X-Robots-Tag', 'noindex, nofollow, noarchive');
  c.res.headers.delete('Set-Cookie');
}
