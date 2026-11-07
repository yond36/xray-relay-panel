export type UserRole = 'admin' | 'user'

export interface User {
  id: string
  username: string
  role: UserRole
}

export interface Bootstrap {
  initialized: boolean
  authenticated: boolean
  registration_open: boolean
  user?: User | null
  version: string
}

export interface Node {
  id: string
  owner_id: string
  name: string
  kind: 'local' | 'ssh'
  host: string
  ssh_port: number
  username: string
  auth_mode: 'password' | 'privatekey'
  password?: string
  private_key?: string
  key_passphrase?: string
  fingerprint: string
  public_host: string
  core_version: string
  status: string
  last_error?: string
  applied_revision?: string
  has_credentials: boolean
  created_at: string
  updated_at: string
}

export interface Upstream {
  id: string
  owner_id: string
  name: string
  protocol: string
  server: string
  port: number
  outbound?: Record<string, unknown>
  source_id?: string
  created_at: string
  updated_at: string
}

export interface Relay {
  id: string
  owner_id: string
  name: string
  node_id: string
  upstream_id: string
  enabled: boolean
  protocol: string
  listen: string
  public_host: string
  port: number
  network: string
  security: string
  uuid?: string
  password?: string
  cipher?: string
  flow?: string
  server_name?: string
  target?: string
  reality_private_key?: string
  reality_public_key?: string
  short_id?: string
  path?: string
  certificate?: string
  certificate_key?: string
  share_url?: string
  created_at: string
  updated_at: string
}

export interface Job {
  id: string
  owner_id: string
  node_id: string
  action: string
  status: string
  message: string
  error?: string
  revision?: string
  created_at: string
  finished_at?: string | null
}

export interface ProbeResult {
  id: string
  owner_id: string
  node_id: string
  upstream_id: string
  ipv4?: string
  ipv6?: string
  latency_ms: number
  status: string
  error?: string
  ipv6_error?: string
  checked_at: string
}

export interface NodeInspection {
  fingerprint: string
  requires_trust: boolean
  os: string
  architecture: string
  service_state: string
  core_version: string
  existing_xray: boolean
  ports: number[]
  message: string
}

export interface Subscription {
  id: string
  owner_id: string
  name: string
  url?: string
  count: number
  last_error?: string
  updated_at: string
}

export interface Settings {
  subscription_token?: string
  panel_url: string
  core_version: string
  registration_open: boolean
}

export interface CoreRelease {
  tag: string
  name: string
  published_at: string
  prerelease: boolean
  html_url: string
}

export interface CoreReleases {
  releases: CoreRelease[]
  fetched_at: string
  stale: boolean
  error?: string
}

export interface State {
  current_user: User
  users?: User[]
  nodes: Node[]
  upstreams: Upstream[]
  relays: Relay[]
  jobs: Job[]
  probes: ProbeResult[]
  subscriptions: Subscription[]
  settings: Settings
}

export type Page = 'dashboard' | 'nodes' | 'upstreams' | 'relays' | 'jobs' | 'users' | 'settings'
export type ToastKind = 'success' | 'error' | 'info'
export interface Toast { id: number; kind: ToastKind; message: string }
export interface PendingProbe { job: Job; started_at: string }
export type ProbeJobs = Record<string, PendingProbe>
