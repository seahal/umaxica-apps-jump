import { JumpError, SERVICE, type RuntimeInfo } from './types';

export type NormalizedUrl = {
  href: string;
  origin: string;
  hostname: string;
  hasNonAsciiHostname: boolean;
};

const FORBIDDEN_PROTOCOLS = new Set(['javascript:', 'data:', 'file:', 'blob:']);
const METADATA_V4 = '169.254.169.254';

export function normalizeUrl(input: string, runtime: RuntimeInfo): NormalizedUrl {
  let parsed: URL;
  try {
    parsed = new URL(input);
  } catch {
    throw new JumpError('invalid_url', 'url parse failed');
  }

  if (FORBIDDEN_PROTOCOLS.has(parsed.protocol))
    throw new JumpError('invalid_url', 'forbidden protocol');
  if (parsed.username || parsed.password) throw new JumpError('invalid_url', 'userinfo rejected');
  if (runtime.production && parsed.protocol === 'http:')
    throw new JumpError('invalid_url', 'http rejected');
  if (!['https:', 'http:'].includes(parsed.protocol))
    throw new JumpError('invalid_url', 'protocol rejected');

  const rawHost = parsed.hostname;
  const hostname = rawHost.endsWith('.')
    ? rawHost.slice(0, -1).toLowerCase()
    : rawHost.toLowerCase();
  parsed.hostname = hostname;

  if (hostname === new URL(SERVICE.origin).hostname)
    throw new JumpError('invalid_url', 'self link rejected');
  if (isForbiddenHost(hostname)) throw new JumpError('invalid_url', 'forbidden host');

  return {
    href: parsed.href,
    origin: parsed.origin,
    hostname: parsed.hostname.toLowerCase(),
    hasNonAsciiHostname: hasNonAscii(inputHost(input)),
  };
}

function inputHost(input: string) {
  try {
    return new URL(input).hostname;
  } catch {
    return '';
  }
}

function hasNonAscii(value: string) {
  for (let index = 0; index < value.length; index += 1) {
    if (value.charCodeAt(index) > 0x7f) return true;
  }
  return false;
}

function isForbiddenHost(hostname: string) {
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) return true;
  if (hostname === METADATA_V4 || hostname === 'metadata.google.internal') return true;
  if (hostname === '::1' || hostname === '[::1]') return true;
  const ipv4 = parseIpv4(hostname);
  if (ipv4) return isPrivateIpv4(ipv4);
  return false;
}

function parseIpv4(hostname: string) {
  const parts = hostname.split('.');
  if (parts.length !== 4) return null;
  const nums = parts.map((part) => {
    if (!/^\d+$/.test(part)) return Number.NaN;
    const value = Number(part);
    return value >= 0 && value <= 255 ? value : Number.NaN;
  });
  return nums.every(Number.isInteger) ? (nums as [number, number, number, number]) : null;
}

function isPrivateIpv4([a, b]: [number, number, number, number]) {
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 0) return true;
  return false;
}
