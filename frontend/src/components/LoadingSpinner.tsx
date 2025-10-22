/**
 * Loading spinner components for displaying loading states
 * Provides two variants: inline spinner and full-page spinner
 */

/**
 * Inline loading spinner for component-level loading states
 * Displays within container with minimum 200px height
 */
export function LoadingSpinner() {
  return (
    <div className="flex items-center justify-center h-full min-h-[200px]">
      <div className="relative">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600" />
        <div className="sr-only">Loading...</div>
      </div>
    </div>
  )
}

/**
 * Full-page loading spinner for application-level loading states
 * Covers entire viewport with larger spinner size
 */
export function FullPageSpinner() {
  return (
    <div className="flex items-center justify-center h-screen w-full bg-gray-50">
      <div className="relative">
        <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-primary-600" />
        <div className="sr-only">Loading application...</div>
      </div>
    </div>
  )
}