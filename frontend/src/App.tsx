/**
 * Root React component
 * Simple wrapper that renders the Layout component containing all routes
 * Actual routing logic and lazy loading handled in main.tsx entry point
 */
import { Layout } from './components/Layout'

function App() {
  return <Layout />
}

export default App