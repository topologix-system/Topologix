import { useCallback, useState, useRef } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { Network, Menu, X, Settings, RefreshCw, LogOut, User, Users, ChevronDown, FolderOpen, Shield } from 'lucide-react'
import { APP_VERSION, IS_PRODUCTION } from '../constants'
import { useTranslation } from 'react-i18next'
import { useUIStore, useSnapshotStore, useAuthStore } from '../store'
import { useHealth, useSnapshots, useActivateSnapshot } from '../hooks'
import { LanguageSwitcher } from './LanguageSwitcher'
import { authAPI } from '../services/api'

/**
 * Application header component with snapshot selection and user menu
 * Handles snapshot activation, health status display, and navigation
 */
export function Header() {
  const { t } = useTranslation()
  const location = useLocation()
  const navigate = useNavigate()
  const sidebarOpen = useUIStore((state) => state.sidebarOpen)
  const setSidebarOpen = useUIStore((state) => state.setSidebarOpen)

  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)
  const setCurrentSnapshotName = useSnapshotStore((state) => state.setCurrentSnapshotName)

  const user = useAuthStore((state) => state.user)
  const logout = useAuthStore((state) => state.logout)

  // Fetch health status and snapshots using React Query (NO useEffect!)
  const { data: health, isLoading } = useHealth()
  const activateMutation = useActivateSnapshot()
  const { data: snapshots } = useSnapshots()

  const [dropdownOpen, setDropdownOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)
  // Check if current user has admin role for conditional menu rendering
  const isAdmin = authAPI.hasRole('admin')

  /**
   * Handle snapshot selection change from dropdown
   * Triggers snapshot activation mutation and updates global state
   */
  const handleSnapshotChange = useCallback(
    (snapshotName: string) => {
      if (!snapshotName) return

      console.log('[Header] Activating snapshot:', snapshotName)

      activateMutation.mutate(snapshotName, {
        onSuccess: () => {
          console.log('[Header] Snapshot activated successfully:', snapshotName)
          setCurrentSnapshotName(snapshotName)
        },
        onError: (error) => {
          console.error('[Header] Failed to activate snapshot:', snapshotName, error)
        },
      })
    },
    [activateMutation, setCurrentSnapshotName]
  )

  /**
   * Reload the currently active snapshot
   * Useful for refreshing network data after configuration changes
   */
  const handleSnapshotReload = useCallback(() => {
    if (!currentSnapshotName) return

    console.log('[Header] Reloading snapshot:', currentSnapshotName)

    activateMutation.mutate(currentSnapshotName, {
      onSuccess: () => {
        console.log('[Header] Snapshot reloaded successfully:', currentSnapshotName)
      },
      onError: (error) => {
        console.error('[Header] Failed to reload snapshot:', currentSnapshotName, error)
      },
    })
  }, [currentSnapshotName, activateMutation])

  /**
   * Handle user logout action
   * Clears authentication state and redirects to login page
   */
  const handleLogout = useCallback(async () => {
    await logout()
    navigate('/login')
  }, [logout, navigate])

  const handleToggleDropdown = useCallback(() => {
    setDropdownOpen((prev) => !prev)
  }, [])

  const handleClickOutside = useCallback((e: MouseEvent) => {
    if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
      setDropdownOpen(false)
    }
  }, [])

  const handleDocumentClick = useCallback((e: MouseEvent) => {
    handleClickOutside(e)
  }, [handleClickOutside])

  /**
   * Click-outside detection for dropdown menu
   * Uses setTimeout to avoid immediate closure on button click
   * IMPORTANT: Manual event listener management (not useEffect) for SSR compatibility
   */
  if (dropdownOpen && typeof document !== 'undefined') {
    setTimeout(() => {
      document.addEventListener('click', handleDocumentClick)
    }, 0)
  } else if (typeof document !== 'undefined') {
    document.removeEventListener('click', handleDocumentClick)
  }

  return (
    <header className="bg-white border-b border-gray-200 px-4 py-3 flex items-center justify-between" role="banner">
      <div className="flex items-center gap-3">
        <Link
          to="/"
          className="flex items-center gap-3 hover:opacity-80 transition-opacity focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2 rounded-lg"
          aria-label="Go to home page - Topologix Network Topology Visualization"
        >
          <Network className="w-8 h-8 text-primary-600" aria-hidden="true" />
          <div>
            <div className="flex items-baseline gap-2">
              <h1 className="text-xl font-bold text-gray-900">{t('app.title')}</h1>
              {!IS_PRODUCTION && <span className="text-xs font-medium text-gray-500">v{APP_VERSION}</span>}
            </div>
            <p className="text-xs text-gray-600">{t('app.subtitle')}</p>
          </div>
        </Link>
      </div>

      <div className="flex items-center gap-4">
        {location.pathname === '/' && (
          <div className="flex items-center gap-2">
            <label htmlFor="snapshot-select" className="text-sm font-medium text-gray-700">
              {t('header.snapshot')}:
            </label>
            <select
              id="snapshot-select"
              value={currentSnapshotName || ''}
              onChange={(e) => handleSnapshotChange(e.target.value)}
              disabled={!snapshots || snapshots.length === 0 || activateMutation.isPending}
              className="px-3 py-1.5 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1 disabled:opacity-50 disabled:cursor-not-allowed"
              aria-label="Select network snapshot"
              aria-describedby={activateMutation.isPending ? 'snapshot-loading' : undefined}
            >
              <option value="">{t('header.selectSnapshot')}</option>
              {snapshots?.map((snapshot) => (
                <option key={snapshot.name} value={snapshot.name}>
                  {snapshot.name} ({t('header.filesCount', { count: snapshot.file_count })})
                </option>
              ))}
            </select>
            {activateMutation.isPending && (
              <span id="snapshot-loading" className="sr-only" role="status" aria-live="polite">
                Loading snapshot...
              </span>
            )}
            <button
              onClick={handleSnapshotReload}
              disabled={!currentSnapshotName || activateMutation.isPending}
              className="p-2 hover:bg-gray-100 rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1 disabled:opacity-50 disabled:cursor-not-allowed"
              aria-label={t('header.reloadSnapshot')}
              title={t('header.reloadSnapshot')}
            >
              <RefreshCw className={`w-5 h-5 ${activateMutation.isPending ? 'animate-spin' : ''}`} aria-hidden="true" />
              <span className="sr-only">{t('header.reloadSnapshot')}</span>
            </button>
            <Link
              to="/snapshots"
              className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-100 rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1"
              aria-label={t('header.manageSnapshots')}
            >
              <FolderOpen className="w-4 h-4" aria-hidden="true" />
              {t('header.manageSnapshots')}
            </Link>
          </div>
        )}

        <LanguageSwitcher />

        {authAPI.isAuthEnabled() && user && (
          <div className="relative border-l border-gray-300 pl-4 ml-4" ref={dropdownRef}>
            <button
              onClick={handleToggleDropdown}
              className="flex items-center gap-2 px-3 py-1.5 text-sm text-gray-700 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1"
              aria-label="User menu"
              aria-expanded={dropdownOpen}
              aria-haspopup="true"
            >
              <User className="w-4 h-4" aria-hidden="true" />
              <span className="font-medium">{user.username}</span>
              <ChevronDown className={`w-4 h-4 transition-transform ${dropdownOpen ? 'rotate-180' : ''}`} aria-hidden="true" />
            </button>

            {dropdownOpen && (
              <div className="absolute right-0 mt-2 w-56 bg-white rounded-lg shadow-lg border border-gray-200 py-1 z-50">
                <Link
                  to="/profile"
                  onClick={() => setDropdownOpen(false)}
                  className="flex items-center gap-3 px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 transition-colors"
                >
                  <User className="w-4 h-4" aria-hidden="true" />
                  My Profile
                </Link>

                {isAdmin && (
                  <>
                    <Link
                      to="/admin/users"
                      onClick={() => setDropdownOpen(false)}
                      className="flex items-center gap-3 px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 transition-colors"
                    >
                      <Users className="w-4 h-4" aria-hidden="true" />
                      User Management
                    </Link>
                    <Link
                      to="/admin/security-logs"
                      onClick={() => setDropdownOpen(false)}
                      className="flex items-center gap-3 px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 transition-colors"
                    >
                      <Shield className="w-4 h-4" aria-hidden="true" />
                      Security Logs
                    </Link>
                  </>
                )}

                <hr className="my-1 border-gray-200" />

                <button
                  onClick={() => {
                    setDropdownOpen(false)
                    handleLogout()
                  }}
                  className="w-full flex items-center gap-3 px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 transition-colors text-left"
                >
                  <LogOut className="w-4 h-4" aria-hidden="true" />
                  {t('auth.logout')}
                </button>
              </div>
            )}
          </div>
        )}

        <div className="flex items-center gap-2" role="status" aria-live="polite" aria-atomic="true">
          <div
            className={`w-2 h-2 rounded-full ${
              isLoading ? 'bg-yellow-400' : health ? 'bg-green-400' : 'bg-red-400'
            }`}
            aria-hidden="true"
          />
          <span className="text-sm text-gray-700">
            {isLoading ? t('header.connecting') : health ? t('header.connected') : t('header.disconnected')}
          </span>
          <span className="sr-only">
            {t('header.connectionStatus', { status: isLoading ? 'connecting' : health ? 'connected' : 'disconnected' })}
          </span>
        </div>

        {location.pathname === '/' && (
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1"
            aria-label={sidebarOpen ? 'Close sidebar' : 'Open sidebar'}
            aria-expanded={sidebarOpen}
            aria-controls="main-sidebar"
          >
            {sidebarOpen ? <X className="w-5 h-5" aria-hidden="true" /> : <Menu className="w-5 h-5" aria-hidden="true" />}
            <span className="sr-only">{sidebarOpen ? t('header.closeSidebar') : t('header.openSidebar')}</span>
          </button>
        )}
      </div>
    </header>
  )
}