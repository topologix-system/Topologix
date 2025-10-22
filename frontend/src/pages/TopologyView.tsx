/**
 * Topology view page wrapper
 * Provides full-screen container for TopologyViewer component with overflow handling
 */
import { TopologyViewer } from '../components/TopologyViewer'

export function TopologyView() {
  return (
    <div className="h-screen overflow-hidden">
      <TopologyViewer />
    </div>
  )
}