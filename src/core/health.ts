import { SERVICE, type RuntimeInfo } from './types';
import { type Locale } from './i18n';
import { renderHealthPage } from './page';

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
  const h = healthJson(runtime);
  return renderHealthPage(Object.entries(h), locale);
}
