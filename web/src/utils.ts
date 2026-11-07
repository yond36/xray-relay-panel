import type { Job, Node, Relay, State, UserRole } from './types'

export const accountSecretMinBytes = 12
export const accountSecretMaxBytes = 1024
export const accountSecretHint = `密码至少 ${accountSecretMinBytes} 字节，最多 ${accountSecretMaxBytes} 字节；英文字符、数字或符号各计 1 字节。`
export function accountSecretError(value: string) {
  const bytes = new TextEncoder().encode(value).length
  if (bytes < accountSecretMinBytes) return `密码至少需要 ${accountSecretMinBytes} 字节。`
  if (bytes > accountSecretMaxBytes) return `密码最多允许 ${accountSecretMaxBytes} 字节。`
  return ''
}
export const roleLabel = (role: UserRole) => role === 'admin' ? '管理员' : '普通用户'
export function ownerName(state: State, ownerID: string) {
  if (state.current_user.id === ownerID) return state.current_user.username
  return state.users?.find(user => user.id === ownerID)?.username || (ownerID ? `用户 ${ownerID.slice(0, 10)}` : '归属未知')
}

// Keep the administrator's complete view; regular users only render their own resources.
export function scopeState(state: State): State {
  const populated = { ...state, users: state.users || [], nodes: state.nodes || [], upstreams: state.upstreams || [], relays: state.relays || [], jobs: state.jobs || [], probes: state.probes || [], subscriptions: state.subscriptions || [] }
  if (state.current_user.role === 'admin') return populated
  const own = <T extends { owner_id: string }>(items: T[]) => items.filter(item => item.owner_id === state.current_user.id)
  return { ...populated, users: [], nodes: own(populated.nodes), upstreams: own(populated.upstreams), relays: own(populated.relays), jobs: own(populated.jobs), probes: own(populated.probes), subscriptions: own(populated.subscriptions) }
}

const dates = new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
export function formatDate(value?: string | null) {
  if (!value || value.startsWith('0001-')) return '尚无记录'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '时间未知' : dates.format(date)
}
export const stamp = (value?: string | null) => value ? new Date(value).getTime() || 0 : 0
export const shortID = (value?: string) => value ? value.slice(0, 10) : '—'
export const isRunning = (job: Job) => ['queued', 'pending', 'running', 'in_progress'].includes(job.status.toLowerCase())
export const isSuccess = (value: string) => ['success', 'succeeded', 'completed', 'done', 'ok', 'active', 'running', 'ready', 'applied', 'deployed'].includes(value.toLowerCase())
export const isFailure = (value: string) => ['failed', 'failure', 'error', 'unhealthy', 'offline'].includes(value.toLowerCase())
export const sortedJobs = (jobs: Job[]) => [...jobs].sort((a, b) => stamp(b.created_at) - stamp(a.created_at))

export function statusLabel(status: string) {
  const labels: Record<string, string> = {
    queued: '排队中', pending: '待处理', running: '运行中', in_progress: '进行中',
    success: '成功', succeeded: '成功', completed: '已完成', done: '已完成', ok: '正常',
    failed: '失败', failure: '失败', error: '异常', unhealthy: '异常', offline: '离线',
    active: '运行中', inactive: '未运行', stopped: '已停止', ready: '就绪',
    deployed: '已部署', applied: '已应用', new: '未部署', unknown: '待检查', saved: '已保存',
    connected: '已连接', disconnected: '未连接', timeout: '超时', cancelled: '已取消',
  }
  return labels[status.toLowerCase()] || status || '待检查'
}
export function actionLabel(action: string) {
  const labels: Record<string, string> = { apply: '部署 / 应用配置', deploy: '部署节点', probe: '探测出口 IP', start: '启动服务', stop: '停止服务', restart: '重启服务', rollback: '回滚配置', 'service:start': '启动服务', 'service:stop': '停止服务', 'service:restart': '重启服务', 'service:rollback': '回滚配置' }
  return labels[action] || action
}

export function relayApplyState(relay: Relay, state: State): { label: string; tone: 'neutral' | 'warning' | 'success' } {
  const node = state.nodes.find(item => item.id === relay.node_id)
  if (state.jobs.some(job => job.node_id === relay.node_id && ['apply', 'deploy'].includes(job.action) && isRunning(job))) return { label: '正在应用', tone: 'warning' }
  if (!node?.applied_revision) return { label: '已保存 · 未应用', tone: 'neutral' }
  const applied = sortedJobs(state.jobs).find(job => job.node_id === relay.node_id && ['apply', 'deploy'].includes(job.action) && isSuccess(job.status) && job.revision === node.applied_revision)
  const upstream = state.upstreams.find(item => item.id === relay.upstream_id)
  const latestChange = Math.max(stamp(relay.updated_at), stamp(upstream?.updated_at))
  if (!applied || latestChange > stamp(applied.created_at)) return { label: '待应用', tone: 'warning' }
  return { label: '已应用', tone: 'success' }
}

export function nodeTitle(nodes: Node[], id: string) {
  return nodes.find(node => node.id === id)?.name || (id ? `已移除节点 ${shortID(id)}` : '—')
}

export const probeKey = (node: string, upstream: string) => `${node}:${upstream}`
export function subscriptionURL(token: string | undefined, panelURL: string) {
  if (!token) return ''
  return `${(panelURL || window.location.origin).replace(/\/+$/, '')}/sub/${encodeURIComponent(token)}`
}
