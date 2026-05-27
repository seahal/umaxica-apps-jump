import { SERVICE } from './types';
import { messages, type Locale } from './i18n';

export function renderAbout(locale: Locale = 'ja') {
  const t = messages[locale];
  return `<!doctype html>
<html lang="${locale}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>${t.aboutTitle}</title>
</head>
<body>
<main>
<h1>${t.aboutTitle}</h1>
<p>${t.aboutDescription} ${SERVICE.origin}</p>
<p>${t.version} ${SERVICE.version}</p>
</main>
</body>
</html>`;
}
