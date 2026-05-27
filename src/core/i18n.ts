export type Locale = 'ja' | 'en';

export function asLocale(value: string | undefined): Locale {
  return value === 'en' ? 'en' : 'ja';
}

export const messages = {
  ja: {
    aboutTitle: 'Jump Gateway',
    aboutDescription:
      'このステートレスゲートウェイは、FQDN をまたぐ前にリダイレクトトークンを検証します。',
    version: 'バージョン',
    healthTitle: 'Jump health',
    healthOk: 'OK',
    errorTitle: '無効な Jump',
    errorHeading: '無効な Jump リクエスト',
    errorBody: 'このリダイレクトリクエストは使用できません。',
    cushionTitle: '外部サイトへ移動',
    nonAsciiWarning: '移動先のホスト名には非 ASCII 文字が含まれています。',
    host: 'ホスト',
    url: 'URL',
    continue: '続行',
  },
  en: {
    aboutTitle: 'Jump Gateway',
    aboutDescription:
      'This stateless gateway validates redirect tokens before crossing fully qualified domain names.',
    version: 'Version',
    healthTitle: 'Jump health',
    healthOk: 'OK',
    errorTitle: 'Invalid jump',
    errorHeading: 'Invalid jump request',
    errorBody: 'The redirect request could not be used.',
    cushionTitle: 'Continue to external site',
    nonAsciiWarning: 'The destination hostname contains non-ASCII characters.',
    host: 'host',
    url: 'url',
    continue: 'Continue',
  },
} as const;
