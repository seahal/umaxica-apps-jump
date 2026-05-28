import { type Locale } from './i18n';
import { renderErrorPage } from './page';

export function renderError(locale: Locale = 'ja') {
  return renderErrorPage(locale);
}
