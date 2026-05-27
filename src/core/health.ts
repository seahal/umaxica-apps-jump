import { SERVICE, type RuntimeInfo } from './types';
import { escapeHtml } from './escape';
import { messages, type Locale } from './i18n';

export function healthJson(runtime: RuntimeInfo, now = new Date()) {
  return {
    ok: true,
    service: SERVICE.name,
    version: runtime.version === undefined ? SERVICE.version : runtime.version,
    edge: runtime.edge,
    time: now.toISOString(),
  };
}

export function wantsJson(accept: string | null) {
  return accept?.includes('application/json') || false;
}

export function renderHealthHtml(runtime: RuntimeInfo, locale: Locale = 'ja') {
  const t = messages[locale];
  const h = healthJson(runtime);
  return `<!doctype html>
<html lang="${locale}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>${t.healthTitle}</title>
</head>
<body>
<main>
<h1>${t.healthOk}</h1>
<dl>
<dt>edge</dt><dd>${escapeHtml(h.edge)}</dd>
<dt>version</dt><dd>${escapeHtml(h.version)}</dd>
</dl>
</main>
</body>
</html>`;
}
