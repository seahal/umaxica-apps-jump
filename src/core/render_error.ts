import { messages, type Locale } from './i18n';

export function renderError(locale: Locale = 'ja') {
  const t = messages[locale];
  return `<!doctype html>
<html lang="${locale}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>${t.errorTitle}</title>
</head>
<body><main><h1>${t.errorHeading}</h1><p>${t.errorBody}</p></main></body>
</html>`;
}
