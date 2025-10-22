/**
 * Routing policy and AAA authentication type definitions
 * Route-maps, ACLs, and authentication configuration
 */
export interface RoutePolicy {
  node: string
  policy_name: string
  action: string
  input_routes: any[]
  output_routes: any[]
  trace: any[]
}

export interface AAAAuthenticationLogin {
  node: string
  methods: string[]
  list_name: string
}