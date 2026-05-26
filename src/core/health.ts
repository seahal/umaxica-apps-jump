import { SERVICE, type RuntimeInfo } from './types';

export function healthJson(runtime: RuntimeInfo, now = new Date()) {
  return {
    ok: true,
    service: SERVICE.name,
    version: SERVICE.version,
    edge: runtime.edge,
    region: runtime.region || 'unknown',
    time: now.toISOString(),
  };
}

export function wantsJson(accept: string | null) {
  return accept?.includes('application/json') || false;
}

export function renderHealthHtml(runtime: RuntimeInfo) {
  const h = healthJson(runtime);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>Jump health</title>
</head>
<body>
<main>
<h1>OK</h1>
<dl>
<dt>edge</dt><dd>${h.edge}</dd>
<dt>region</dt><dd>${escapeHtml(h.region)}</dd>
<dt>version</dt><dd>${h.version}</dd>
</dl>
</main>
</body>
</html>`;
}

function escapeHtml(value: string) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}
