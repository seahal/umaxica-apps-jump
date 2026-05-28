import type { Child } from 'hono/jsx';
import { raw } from 'hono/html';
import { renderToString } from 'hono/jsx/dom/server';
import { PRODUCTION_SERVICE_ORIGIN } from './types';
import { messages, type Locale } from './i18n';
import type { NormalizedUrl } from './normalize_url';
import { CUSHION_INLINE_SCRIPT } from './security_headers';

type PageProps = {
  title: string;
  locale: Locale;
  children: Child;
  now?: Date;
};

export function renderHomePage(locale: Locale = 'ja', now = new Date()) {
  const t = messages[locale];
  return renderDocument({
    title: t.homeTitle,
    locale,
    now,
    children: (
      <main>
        <h1>{t.aboutTitle}</h1>
        <p>{t.aboutDescription}</p>
      </main>
    ),
  });
}

export function renderAboutPage(
  locale: Locale = 'ja',
  serviceOrigin: string = PRODUCTION_SERVICE_ORIGIN,
  now = new Date(),
) {
  const t = messages[locale];
  return renderDocument({
    title: t.aboutPageTitle,
    locale,
    now,
    children: (
      <main>
        <h1>{t.aboutTitle}</h1>
        <p>{t.aboutDescription}</p>
        <p>{serviceOrigin}</p>
      </main>
    ),
  });
}

export function renderHealthPage(
  entries: Array<[string, string | boolean | null | undefined]>,
  locale: Locale = 'ja',
  now = new Date(),
) {
  const t = messages[locale];
  return renderDocument({
    title: t.healthTitle,
    locale,
    now,
    children: (
      <main>
        <h1>{t.healthOk}</h1>
        <dl>
          {entries.map(([key, value]) => (
            <>
              <dt>{key}</dt>
              <dd>{displayValue(value)}</dd>
            </>
          ))}
        </dl>
      </main>
    ),
  });
}

export function renderErrorPage(locale: Locale = 'ja', now = new Date()) {
  const t = messages[locale];
  return renderDocument({
    title: t.errorTitle,
    locale,
    now,
    children: (
      <main>
        <h1>{t.errorHeading}</h1>
        <p>{t.errorBody}</p>
      </main>
    ),
  });
}

export function renderCushionPage(target: NormalizedUrl, locale: Locale = 'ja', now = new Date()) {
  const t = messages[locale];
  const displayUrl = truncate(target.href, 180);
  return renderDocument({
    title: t.cushionTitle,
    locale,
    now,
    children: (
      <>
        <main>
          <h1>{t.cushionTitle}</h1>
          {target.hasNonAsciiHostname ? <p role="alert">{t.nonAsciiWarning}</p> : null}
          <dl>
            <dt>{t.host}</dt>
            <dd>{target.hostname}</dd>
            <dt>{t.url}</dt>
            <dd>{displayUrl}</dd>
          </dl>
          <a href={target.href} rel="noopener noreferrer">
            {t.continue}
          </a>
        </main>
        <script>{raw(CUSHION_INLINE_SCRIPT)}</script>
      </>
    ),
  });
}

function renderDocument({ title, locale, children, now = new Date() }: PageProps) {
  const document = (
    <html lang={locale}>
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width,initial-scale=1" />
        <meta name="robots" content="noindex,nofollow,noarchive" />
        <title>{title}</title>
      </head>
      <body>
        <header>
          <a href="/">UMAXICA</a>
        </header>
        {children}
        <footer>© {now.getUTCFullYear()} UMAXICA</footer>
      </body>
    </html>
  );
  return `<!doctype html>${renderToString(document)}`;
}

function displayValue(value: string | boolean | null | undefined) {
  if (value === null || value === undefined) return '';
  return String(value);
}

function truncate(value: string, max: number) {
  return value.length > max ? `${value.slice(0, max - 1)}...` : value;
}
