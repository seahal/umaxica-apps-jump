import { type Locale } from './i18n';
import { renderAboutPage } from './page';
import { PRODUCTION_SERVICE_ORIGIN } from './types';

export function renderAbout(
  locale: Locale = 'ja',
  serviceOrigin: string = PRODUCTION_SERVICE_ORIGIN,
) {
  return renderAboutPage(locale, serviceOrigin);
}
