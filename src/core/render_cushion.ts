import type { NormalizedUrl } from './normalize_url';
import { type Locale } from './i18n';
import { renderCushionPage } from './page';

export function renderCushion(target: NormalizedUrl, locale: Locale = 'ja') {
  return renderCushionPage(target, locale);
}
