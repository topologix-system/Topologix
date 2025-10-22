import { useTranslation } from 'react-i18next'
import { Globe } from 'lucide-react'

/**
 * Language switcher component for internationalization (i18n)
 * Allows users to switch between English and Japanese
 * Uses react-i18next for translation management
 */
export function LanguageSwitcher() {
  const { i18n, t } = useTranslation()

  /**
   * Handle language change event from dropdown
   * @param lang - Language code ('en' or 'ja')
   */
  const handleLanguageChange = (lang: string) => {
    i18n.changeLanguage(lang)
  }

  return (
    <div className="flex items-center gap-2">
      <Globe className="w-5 h-5 text-gray-600" aria-hidden="true" />
      <select
        id="language-select"
        value={i18n.language}
        onChange={(e) => handleLanguageChange(e.target.value)}
        className="px-3 py-1.5 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1"
        aria-label={t('language.switchLanguage')}
      >
        <option value="en">{t('language.english')}</option>
        <option value="ja">{t('language.japanese')}</option>
      </select>
    </div>
  )
}