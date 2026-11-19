import { Outlet } from 'react-router-dom'
import { Header } from './Header'
import { Sidebar } from './Sidebar'
import { useUIStore } from '../store'

/**
 * Main application layout component
 * Provides the overall page structure with header, sidebar, and main content area
 */
export function Layout() {
  const sidebarOpen = useUIStore((state) => state.sidebarOpen)
  const sidebarWidth = useUIStore((state) => state.sidebarWidth)

  return (
    <div className="flex flex-col min-h-screen bg-gray-50">
      <Header />
      <div className="flex-1 flex relative">
        <main
          className="flex-1 overflow-auto"
          style={{ marginRight: sidebarOpen ? `${sidebarWidth}px` : 0 }}
        >
          <Outlet />
        </main>
        {sidebarOpen && <Sidebar />}
      </div>
    </div>
  )
}