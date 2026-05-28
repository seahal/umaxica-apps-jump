export type Locale = 'ja' | 'en';

export function asLocale(value: string | undefined): Locale {
  return value === 'en' ? 'en' : 'ja';
}

export const messages = {
  ja: {
    homeTitle: 'UMAXICA Jump Gateway',
    aboutTitle: 'UMAXICA Jump Gateway',
    aboutPageTitle: 'UMAXICA Jump Gateway | About',
    aboutDescription: 'UMAXICA のジャンプページです。',
    healthTitle: 'UMAXICA Jump Gateway | Health status',
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
    homeTitle: 'UMAXICA Jump Gateway',
    aboutTitle: 'UMAXICA Jump Gateway',
    aboutPageTitle: 'UMAXICA Jump Gateway | About',
    aboutDescription: 'This is the UMAXICA jump page.',
    healthTitle: 'UMAXICA Jump Gateway | Health status',
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
