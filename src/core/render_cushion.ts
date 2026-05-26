import type { NormalizedUrl } from './normalize_url';

export function renderCushion(target: NormalizedUrl) {
  const displayUrl = truncate(target.href, 180);
  const warning = target.hasNonAsciiHostname
    ? '<p role="alert">The destination hostname contains non-ASCII characters.</p>'
    : '';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>Continue to external site</title>
<script>history.replaceState(null,"",location.pathname)</script>
</head>
<body>
<main>
<h1>Continue to external site</h1>
${warning}
<dl>
<dt>host</dt><dd>${escapeHtml(target.hostname)}</dd>
<dt>url</dt><dd>${escapeHtml(displayUrl)}</dd>
</dl>
<a href="${escapeAttribute(target.href)}" rel="noopener noreferrer">Continue</a>
</main>
</body>
</html>`;
}

function truncate(value: string, max: number) {
  return value.length > max ? `${value.slice(0, max - 1)}...` : value;
}

function escapeHtml(value: string) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function escapeAttribute(value: string) {
  return escapeHtml(value).replaceAll("'", '&#39;');
}
