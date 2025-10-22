import { useTranslation } from 'react-i18next'
import { CheckCircle, XCircle } from 'lucide-react'

interface PasswordPolicyHelperProps {
  password: string
  className?: string
}

interface PolicyCheck {
  key: string
  test: (pwd: string) => boolean
}

export function PasswordPolicyHelper({ password, className = '' }: PasswordPolicyHelperProps) {
  const { t } = useTranslation()

  const policyChecks: PolicyCheck[] = [
    {
      key: 'length',
      test: (pwd: string) => pwd.length >= 12,
    },
    {
      key: 'uppercase',
      test: (pwd: string) => /[A-Z]/.test(pwd),
    },
    {
      key: 'lowercase',
      test: (pwd: string) => /[a-z]/.test(pwd),
    },
    {
      key: 'number',
      test: (pwd: string) => /[0-9]/.test(pwd),
    },
    {
      key: 'special',
      test: (pwd: string) => /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pwd),
    },
  ]

  return (
    <div className={`bg-gray-50 border border-gray-200 rounded-lg p-4 ${className}`}>
      <p className="text-sm font-medium text-gray-700 mb-3">{t('passwordPolicy.title')}</p>
      <ul className="space-y-2">
        {policyChecks.map((check) => {
          const passes = check.test(password)
          return (
            <li key={check.key} className="flex items-center gap-2 text-sm">
              {passes ? (
                <CheckCircle className="w-4 h-4 text-green-600 flex-shrink-0" aria-hidden="true" />
              ) : (
                <XCircle className="w-4 h-4 text-gray-400 flex-shrink-0" aria-hidden="true" />
              )}
              <span className={passes ? 'text-green-700' : 'text-gray-600'}>
                {t(`passwordPolicy.${check.key}`)}
              </span>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
