import type { Job, Node, ProbeJobs, ProbeResult, Relay, State, Upstream, UserRole } from './types'

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
export const isFailure = (value: string) => ['failed', 'failure', 'error', 'unhealthy', 'offline', 'interrupted', 'timeout', 'cancelled', 'canceled'].includes(value.toLowerCase())
export const sortedJobs = (jobs: Job[]) => [...jobs].sort((a, b) => stamp(b.created_at) - stamp(a.created_at))
export const isJobSuccess = (status: string) => ['success', 'succeeded', 'completed', 'done', 'ok'].includes(status.toLowerCase())

export function mergeJobs(jobs: Job[], registered: Job[]) {
  return [...registered.filter(item => !jobs.some(job => job.id === item.id)), ...jobs]
}

export interface RelayDeleteView {
  phase: 'idle' | 'deleting' | 'succeeded' | 'failed'
  job?: Job
  error?: string
}

export function relayDeleteState(jobs: Job[], relayID: string, jobID?: string): RelayDeleteView {
  const job = jobID ? jobs.find(item => item.id === jobID && item.action === 'delete-relay' && (!item.relay_id || item.relay_id === relayID)) : sortedJobs(jobs).find(item => item.action === 'delete-relay' && item.relay_id === relayID)
  if (!job) return { phase: jobID ? 'deleting' : 'idle' }
  if (isFailure(job.status)) return { phase: 'failed', job, error: job.error || job.message || statusLabel(job.status) }
  if (isJobSuccess(job.status)) return { phase: 'succeeded', job }
  return { phase: 'deleting', job }
}

export function relayDeleteNotice(previous: Job | undefined, job: Job): { message: string; kind: 'success' | 'error' } | undefined {
  if (!previous || previous.id !== job.id || job.action !== 'delete-relay' || isJobSuccess(previous.status) || isFailure(previous.status)) return
  const view = relayDeleteState([job], job.relay_id || '', job.id)
  if (view.phase === 'succeeded') return { message: '转发删除完成', kind: 'success' }
  if (view.phase === 'failed') return { message: `转发删除未完成：${view.error}。转发记录已保留，可直接重试删除。`, kind: 'error' }
}

export class JobRegistry {
  private registered = new Map<string, Job>()
  private observed = new Map<string, Job>()

  register(job: Job) {
    // An accepted DELETE still needs an authoritative state refresh, even if it already finished.
    const submitted = job.action === 'delete-relay' && !isRunning(job) ? { ...job, status: 'pending' } : job
    this.registered.set(job.id, submitted)
    this.observed.set(job.id, submitted)
    return submitted
  }

  reconcile(jobs: Job[]) {
    const notices: { message: string; kind: 'success' | 'error' }[] = []
    for (const job of jobs) {
      const notice = relayDeleteNotice(this.observed.get(job.id), job)
      if (notice) notices.push(notice)
      this.observed.set(job.id, job)
      this.registered.delete(job.id)
    }
    return { jobs: mergeJobs(jobs, [...this.registered.values()]), notices }
  }

  clear() { this.registered.clear(); this.observed.clear() }
}

export function statusLabel(status: string) {
  const labels: Record<string, string> = {
    queued: '排队中', pending: '待处理', running: '运行中', in_progress: '进行中',
    success: '成功', succeeded: '成功', completed: '已完成', done: '已完成', ok: '正常',
    failed: '失败', failure: '失败', error: '异常', unhealthy: '异常', offline: '离线',
    active: '运行中', inactive: '未运行', stopped: '已停止', ready: '就绪',
    deployed: '已部署', applied: '已应用', new: '未部署', unknown: '待检查', saved: '已保存',
    connected: '已连接', disconnected: '未连接', timeout: '超时', cancelled: '已取消', canceled: '已取消', interrupted: '已中断', partial: '部分可用',
  }
  return labels[status.toLowerCase()] || status || '待检查'
}
export function actionLabel(action: string) {
  const labels: Record<string, string> = { apply: '部署 / 应用配置', deploy: '部署节点', 'delete-relay': '删除转发 / 应用配置', probe: '检测出口节点', start: '启动服务', stop: '停止服务', restart: '重启服务', rollback: '回滚配置', 'service:start': '启动服务', 'service:stop': '停止服务', 'service:restart': '重启服务', 'service:rollback': '回滚配置' }
  return labels[action] || action
}

export function relayApplyState(relay: Relay, state: State): { label: string; tone: 'neutral' | 'warning' | 'success' } {
  const node = state.nodes.find(item => item.id === relay.node_id)
  if (state.jobs.some(job => job.node_id === relay.node_id && ['apply', 'deploy', 'delete-relay'].includes(job.action) && isRunning(job))) return { label: '正在应用', tone: 'warning' }
  if (!node?.applied_revision) return { label: '已保存 · 未应用', tone: 'neutral' }
  const applied = sortedJobs(state.jobs).find(job => job.node_id === relay.node_id && ['apply', 'deploy', 'delete-relay'].includes(job.action) && isJobSuccess(job.status) && job.revision === node.applied_revision)
  const upstream = state.upstreams.find(item => item.id === relay.upstream_id)
  const latestChange = Math.max(stamp(relay.updated_at), stamp(upstream?.updated_at))
  if (!applied || latestChange > stamp(applied.created_at)) return { label: '待应用', tone: 'warning' }
  return { label: '已应用', tone: 'success' }
}

export function nodeTitle(nodes: Node[], id: string) {
  return nodes.find(node => node.id === id)?.name || (id ? `已移除节点 ${shortID(id)}` : '—')
}

export const probeKey = (node: string, upstream: string) => `${node}:${upstream}`

export function probeNodes(state: Pick<State, 'nodes' | 'current_user'>, upstream: Upstream) {
  const admin = state.current_user.role === 'admin'
  return state.nodes.filter(node => upstream.owner_id && node.owner_id === upstream.owner_id && (admin || node.owner_id === state.current_user.id && node.kind !== 'local'))
}

export function latestProbeNode(state: Pick<State, 'jobs' | 'probes'>, pending: ProbeJobs, upstreamID: string, nodes: Node[]) {
  const ids = new Set(nodes.map(node => node.id))
  const events = state.probes.filter(probe => probe.upstream_id === upstreamID && ids.has(probe.node_id)).map(probe => ({
    nodeID: probe.node_id,
    at: stamp(state.jobs.find(job => job.id === probe.job_id)?.created_at || probe.checked_at),
  }))
  for (const job of state.jobs) {
    if (job.action === 'probe' && job.upstream_id === upstreamID && ids.has(job.node_id)) events.push({ nodeID: job.node_id, at: stamp(job.created_at) })
  }
  for (const node of nodes) {
    const queued = pending[probeKey(node.id, upstreamID)]
    if (queued) events.push({ nodeID: node.id, at: stamp(queued.started_at) })
  }
  return events.sort((a, b) => b.at - a.at)[0]?.nodeID || ''
}

export interface ProbeView {
  phase: 'unchecked' | 'checking' | 'available' | 'partial' | 'failed' | 'missing'
  result?: ProbeResult
  job?: Job
  error?: string
}

export function probeState(state: Pick<State, 'jobs' | 'probes'>, pending: ProbeJobs, nodeID: string, upstreamID: string): ProbeView {
  const result = state.probes.filter(probe => probe.node_id === nodeID && probe.upstream_id === upstreamID).sort((a, b) => stamp(b.checked_at) - stamp(a.checked_at))[0]
  const jobs = state.jobs.filter(job => job.action === 'probe' && job.node_id === nodeID && job.upstream_id === upstreamID)
  const queued = pending[probeKey(nodeID, upstreamID)]
  if (queued && !jobs.some(job => job.id === queued.job.id)) jobs.push(state.jobs.find(job => job.id === queued.job.id) || queued.job)
  const job = jobs.sort((a, b) => stamp(b.created_at) - stamp(a.created_at))[0]
  if (job && isRunning(job)) return { phase: 'checking', result, job }
  const currentJob = job && (!result || result.job_id === job.id || stamp(job.finished_at || job.created_at) >= stamp(result.checked_at))
  if (currentJob && isFailure(job.status)) return { phase: 'failed', result, job, error: job.error || job.message || statusLabel(job.status) }
  if (currentJob && (!result || result.job_id && result.job_id !== job.id)) return { phase: 'missing', result, job }
  if (!result) return { phase: 'unchecked', job }
  if (isFailure(result.status) || !(result.ipv4 || result.ipv6)) return { phase: 'failed', result, job, error: result.error || '未获得有效出口 IP' }
  return { phase: result.status === 'partial' ? 'partial' : 'available', result, job }
}

export function subscriptionURL(token: string | undefined, panelURL: string) {
  if (!token) return ''
  return `${(panelURL || window.location.origin).replace(/\/+$/, '')}/sub/${encodeURIComponent(token)}`
}
