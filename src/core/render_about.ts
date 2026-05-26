import { SERVICE } from './types';

export function renderAbout() {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>Jump Gateway</title>
</head>
<body>
<main>
<h1>Jump Gateway</h1>
<p>This stateless gateway validates redirect tokens for ${SERVICE.origin} before crossing fully qualified domain names.</p>
<p>Version ${SERVICE.version}</p>
</main>
</body>
</html>`;
}
