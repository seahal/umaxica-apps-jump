import type { JWK } from 'jose';
import type { FetchJwks } from './jwks_cache';

const FETCH_TIMEOUT_MS = 2_000;
const MAX_BYTES = 64 * 1024;
const JSON_CONTENT_TYPE = /^application\/(?:[a-z0-9.+-]+\+)?json(?:\s*;|$)/i;

export const fetchRegistryJwks: FetchJwks = async (issuer) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(issuer.jwks_uri, {
      headers: { Accept: 'application/json' },
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`JWKS fetch failed: ${response.status}`);

    const contentType = response.headers.get('content-type') ?? '';
    if (!JSON_CONTENT_TYPE.test(contentType)) {
      throw new Error(`JWKS content-type rejected: ${contentType || 'missing'}`);
    }
    const advertisedLength = Number(response.headers.get('content-length') ?? '');
    if (Number.isFinite(advertisedLength) && advertisedLength > MAX_BYTES) {
      throw new Error('JWKS response too large');
    }

    const body = await readBodyWithCap(response, MAX_BYTES);
    return JSON.parse(body) as { keys: JWK[] };
  } finally {
    clearTimeout(timer);
  }
};

async function readBodyWithCap(response: Response, maxBytes: number): Promise<string> {
  if (!response.body) {
    const text = await response.text();
    if (text.length > maxBytes) throw new Error('JWKS response too large');
    return text;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) throw new Error('JWKS response too large');
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}
