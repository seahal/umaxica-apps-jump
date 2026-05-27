import type { NormalizedUrl } from './normalize_url';
import { escapeAttribute, escapeHtml } from './escape';
import { messages, type Locale } from './i18n';
import { CUSHION_INLINE_SCRIPT } from './security_headers';

export function renderCushion(target: NormalizedUrl, locale: Locale = 'ja') {
  const t = messages[locale];
  const displayUrl = truncate(target.href, 180);
  const warning = target.hasNonAsciiHostname ? `<p role="alert">${t.nonAsciiWarning}</p>` : '';

  return `<!doctype html>
<html lang="${locale}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>${t.cushionTitle}</title>
<script>${CUSHION_INLINE_SCRIPT}</script>
</head>
<body>
<main>
<h1>${t.cushionTitle}</h1>
${warning}
<dl>
<dt>${t.host}</dt><dd>${escapeHtml(target.hostname)}</dd>
<dt>${t.url}</dt><dd>${escapeHtml(displayUrl)}</dd>
</dl>
<a href="${escapeAttribute(target.href)}" rel="noopener noreferrer">${t.continue}</a>
</main>
</body>
</html>`;
}

function truncate(value: string, max: number) {
  return value.length > max ? `${value.slice(0, max - 1)}...` : value;
}
