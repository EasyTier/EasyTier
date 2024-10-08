import type { Locale } from 'vue-i18n'
import { createI18n } from 'vue-i18n'
import type { UseModule } from '~/types/modules'

// Import i18n resources
// https://vitejs.dev/guide/features.html#glob-import
//
// Don't need this? Try vitesse-lite: https://github.com/antfu/vitesse-lite
const i18n = createI18n({
  legacy: false,
  locale: '',
  messages: {},
})

const DEFAULT_LANG = 'zh-CN'
const langStore = useStorage('lang', DEFAULT_LANG)

const localesMap = Object.fromEntries(
  Object.entries(import.meta.glob('../../locales/*.yml'))
    .map(([path, loadLocale]) => [path.match(/([\w-]*)\.yml$/)?.[1], loadLocale]),
) as Record<Locale, () => Promise<{ default: Record<string, string> }>>

export const availableLocales = Object.keys(localesMap)

const loadedLanguages: string[] = []

function setI18nLanguage(lang: Locale) {
  i18n.global.locale.value = lang as any
  if (typeof document !== 'undefined')
    document.querySelector('html')?.setAttribute('lang', lang)
  return lang
}

export async function loadLanguageAsync(lang: string): Promise<Locale> {
  // If the same language
  if (i18n.global.locale.value === lang)
    return setI18nLanguage(lang)

  // If the language was already loaded
  if (loadedLanguages.includes(lang))
    return setI18nLanguage(lang)

  // If the language hasn't been loaded yet
  let messages

  try {
    messages = await localesMap[lang]()
  }
  catch {
    lang = DEFAULT_LANG
    messages = await localesMap[lang]()
  }
  langStore.value = lang
  i18n.global.setLocaleMessage(lang, messages.default)
  loadedLanguages.push(lang)
  return setI18nLanguage(lang)
}

export const install: UseModule = (app) => {
  app.use(i18n)
  loadLanguageAsync(langStore.value)
}
