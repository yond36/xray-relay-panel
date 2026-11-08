import { useEffect, useId, useRef, useState } from 'react'
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { AlertCircle, Check, CheckCircle2, Copy, Download, Info, Loader2, X } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import QRCode from 'qrcode'
import { api, copyText, downloadText } from '../api'
import { useAction, useApp } from '../context'
import type { Job, Settings } from '../types'
import { accountSecretError, actionLabel, formatDate, isFailure, isRunning, isSuccess, nodeTitle, ownerName, probeState, sortedJobs, statusLabel, subscriptionURL } from '../utils'

export function Spinner({ size = 16 }: { size?: number }) { return <Loader2 size={size} className="spin" aria-hidden="true" /> }

export function SecretInput(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} type={['pass', 'word'].join('')} />
}

export function AccountSecretInput({ onChange, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  const input = useRef<HTMLInputElement>(null)
  // HTML minLength counts characters; the account API validates UTF-8 bytes.
  useEffect(() => { input.current?.setCustomValidity(props.value ? accountSecretError(String(props.value)) : '') }, [props.value])
  return <input {...props} ref={input} type={['pass', 'word'].join('')} onChange={event => {
    event.currentTarget.setCustomValidity(event.currentTarget.value ? accountSecretError(event.currentTarget.value) : '')
    onChange?.(event)
  }} />
}

export function OwnerLabel({ ownerID }: { ownerID: string }) {
  const { state, isAdmin } = useApp()
  return isAdmin ? <span className="owner-label">所属用户：{ownerName(state, ownerID)}</span> : null
}

export function Button({ children, variant = 'secondary', size, busy, className = '', disabled, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'ghost' | 'danger'; size?: 'sm'; busy?: boolean }) {
  return <button className={`button button-${variant} ${size ? 'button-sm' : ''} ${className}`} disabled={disabled || busy} aria-busy={busy || undefined} {...props}>{busy && <Spinner />}{children}</button>
}

export function IconButton({ icon: Icon, label, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { icon: LucideIcon; label: string }) {
  return <button {...props} type="button" className={`icon-button ${props.className || ''}`} aria-label={label} title={label}><Icon size={17} /></button>
}

export function Badge({ children, tone = 'neutral', dot = false }: { children: ReactNode; tone?: 'neutral' | 'success' | 'warning' | 'danger' | 'info'; dot?: boolean }) {
  return <span className={`badge badge-${tone}`}>{dot && <span className="status-dot" />}{children}</span>
}

export function StatusBadge({ status }: { status: string }) {
  return <Badge dot tone={isFailure(status) ? 'danger' : isRunning({ status } as Job) ? 'info' : isSuccess(status) ? 'success' : 'neutral'}>{statusLabel(status)}</Badge>
}

export function PageHeader({ eyebrow, title, description, actions }: { eyebrow: string; title: string; description: string; actions?: ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>{actions && <div className="heading-actions">{actions}</div>}</div>
}

export function Card({ title, description, action, children, className = '' }: { title?: string; description?: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return <section className={`card ${className}`}>{(title || action) && <div className="card-header"><div><h2>{title}</h2>{description && <p>{description}</p>}</div>{action}</div>}{children}</section>
}

export function Empty({ icon: Icon, title, description, action, compact = false }: { icon: LucideIcon; title: string; description: string; action?: ReactNode; compact?: boolean }) {
  return <div className={`empty-state ${compact ? 'empty-compact' : ''}`}><span className="empty-icon"><Icon size={25} /></span><h3>{title}</h3><p>{description}</p>{action}</div>
}

export function Alert({ children, tone = 'info', title }: { children: ReactNode; tone?: 'info' | 'warning' | 'danger' | 'success'; title?: string }) {
  const Icon = tone === 'danger' || tone === 'warning' ? AlertCircle : tone === 'success' ? CheckCircle2 : Info
  return <div className={`alert alert-${tone}`} role={tone === 'danger' ? 'alert' : undefined}><Icon size={18} /><div>{title && <strong>{title}</strong>}<div>{children}</div></div></div>
}

export function Field({ label, hint, required, children, className = '' }: { label: string; hint?: ReactNode; required?: boolean; children: ReactNode; className?: string }) {
  return <label className={`field ${className}`}><span className="field-label">{label}{required && <span className="required">*</span>}</span>{children}{hint && <span className="field-hint">{hint}</span>}</label>
}

export function Modal({ title, description, onClose, children, wide = false, busy = false }: { title: string; description?: string; onClose: () => void; children: ReactNode; wide?: boolean; busy?: boolean }) {
  const ref = useRef<HTMLDivElement>(null)
  const titleID = useId()
  const closeRef = useRef(onClose)
  closeRef.current = onClose
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null
    const overflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    ref.current?.querySelector<HTMLElement>('input:not([disabled]),select:not([disabled]),textarea:not([disabled]),button:not([disabled])')?.focus()
    return () => { document.body.style.overflow = overflow; previous?.focus() }
  }, [])
  useEffect(() => {
    const handle = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !busy) closeRef.current()
      if (event.key === 'Tab' && ref.current) {
        const elements = Array.from(ref.current.querySelectorAll<HTMLElement>('button:not([disabled]),input:not([disabled]),textarea:not([disabled]),select:not([disabled]),a[href]')).filter(el => el.offsetParent !== null)
        const first = elements[0], last = elements[elements.length - 1]
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus() }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus() }
      }
    }
    document.addEventListener('keydown', handle)
    return () => document.removeEventListener('keydown', handle)
  }, [busy])
  return createPortal(<div className="modal-backdrop" onMouseDown={event => { if (event.target === event.currentTarget && !busy) onClose() }}><div ref={ref} role="dialog" aria-modal="true" aria-labelledby={titleID} className={`modal ${wide ? 'modal-wide' : ''}`}><div className="modal-header"><div><h2 id={titleID}>{title}</h2>{description && <p>{description}</p>}</div><IconButton icon={X} label="关闭对话框" onClick={onClose} disabled={busy} /></div>{children}</div></div>, document.body)
}

export function ConfirmDialog({ title, description, confirmLabel = '确认删除', busyLabel, onClose, action, success, danger = true, disabled = false }: { title: string; description: ReactNode; confirmLabel?: string; busyLabel?: string; onClose: () => void; action: () => Promise<unknown>; success?: string; danger?: boolean; disabled?: boolean }) {
  const { busy, error, run } = useAction()
  return <Modal title={title} onClose={onClose} busy={busy}><div className="modal-body"><Alert tone={danger ? 'warning' : 'info'}>{description}</Alert>{error && <Alert tone="danger">{error}</Alert>}</div><div className="modal-footer"><Button onClick={onClose} disabled={busy}>取消</Button><Button variant={danger ? 'danger' : 'primary'} busy={busy} disabled={disabled} onClick={async () => { if (disabled || busy) return; const result = await run(action, { success }); if (result.ok) onClose() }}>{busy ? busyLabel || confirmLabel : confirmLabel}</Button></div></Modal>
}

export function CopyButton({ value, label = '复制', small = false }: { value: string; label?: string; small?: boolean }) {
  const { toast } = useApp()
  const [copied, setCopied] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout>>()
  useEffect(() => () => clearTimeout(timer.current), [])
  return <Button size={small ? 'sm' : undefined} onClick={async () => { try { await copyText(value); setCopied(true); clearTimeout(timer.current); timer.current = setTimeout(() => setCopied(false), 2000) } catch (error) { toast((error as Error).message, 'error') } }} disabled={!value}>{copied ? <Check size={15} /> : <Copy size={15} />}{copied ? '已复制' : label}</Button>
}

export function QRCodeBlock({ value }: { value: string }) {
  const [image, setImage] = useState('')
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    setImage(''); setError('')
    QRCode.toDataURL(value, { width: 280, margin: 2, errorCorrectionLevel: 'M', color: { dark: '#102d3d', light: '#ffffff' } }).then(data => { if (active) setImage(data) }).catch(() => { if (active) setError('链接过长，无法生成二维码。请复制链接导入客户端。') })
    return () => { active = false }
  }, [value])
  if (error) return <Alert tone="warning">{error}</Alert>
  return <div className="qr-block">{image ? <><img src={image} width="240" height="240" alt="在本地生成的连接二维码" /><a className="text-link" href={image} download="relay-qrcode.png"><Download size={14} />保存二维码</a></> : <Spinner size={24} />}<span className="field-hint">二维码在当前浏览器生成</span></div>
}

export function ProbeStatus({ nodeID, upstreamID, detailed = false }: { nodeID: string; upstreamID: string; detailed?: boolean }) {
  const { state, probeJobs } = useApp()
  const { phase, result, job, error } = probeState(state, probeJobs, nodeID, upstreamID)
  if (phase === 'checking') return <div className="probe-result" role="status" aria-live="polite"><span className="inline muted"><Spinner size={15} />检测中…</span>{(result?.ipv4 || result?.ipv6) && <small className="mono muted">上次记录 {result.ipv4 || result.ipv6}</small>}</div>
  if (phase === 'failed') return <div className="probe-result" role="status" aria-live="polite"><Badge tone="danger">检测失败</Badge><small className="text-danger wrap" title={error}>{error}</small><small className="muted">{formatDate(job?.finished_at || result?.checked_at)}</small></div>
  if (phase === 'missing') return <span className="muted">暂无本次检测结果，请重新检测。</span>
  if (!result) return <span className="muted">尚未检测</span>
  return <div className="probe-result" role="status" aria-live="polite"><Badge tone={phase === 'partial' ? 'warning' : 'success'}>{phase === 'partial' ? '部分可用' : '可用'}</Badge><span className="mono">{result.ipv4 || result.ipv6}</span>{result.ipv4 && result.ipv6 && <small className="mono muted">{result.ipv6}</small>}<small className="muted">{result.latency_ms > 0 ? `请求耗时 ${result.latency_ms} ms · ` : ''}{formatDate(result.checked_at)}</small>{result.error && <small className="text-warning wrap">{result.error}</small>}{result.ipv6_error && <small className="text-warning wrap" title={result.ipv6_error}>IPv6：{result.ipv6_error}</small>}{detailed && <small className="muted">检测验证所选入口节点经出口节点的出站链路，不验证客户端转发端口的公网可达性。</small>}</div>
}

export function JobsTable({ jobs, compact = false }: { jobs: Job[]; compact?: boolean }) {
  const { state, isAdmin } = useApp()
  const [selected, setSelected] = useState<Job | null>(null)
  return <><div className="table-scroll"><table><thead><tr><th>任务 / 入口节点</th>{isAdmin && <th>所属用户</th>}<th>状态</th><th>执行信息</th>{!compact && <th>配置版本</th>}<th>创建时间</th><th className="align-right">详情</th></tr></thead><tbody>{sortedJobs(jobs).map(job => <tr key={job.id}><td><div className="cell-title">{actionLabel(job.action)}</div><div className="cell-subtitle">{nodeTitle(state.nodes, job.node_id)}</div></td>{isAdmin && <td className="wrap">{ownerName(state, job.owner_id)}</td>}<td><StatusBadge status={job.status} /></td><td><div className={`truncate-cell ${job.error ? 'text-danger' : 'muted'}`} title={job.error || job.message}>{job.error || job.message || '等待任务执行'}</div></td>{!compact && <td className="mono muted">{job.revision?.slice(0, 10) || '—'}</td>}<td className="nowrap muted">{formatDate(job.created_at)}</td><td className="align-right"><Button size="sm" variant="ghost" onClick={() => setSelected(job)}>查看</Button></td></tr>)}</tbody></table></div>{selected && <JobDetails job={selected} onClose={() => setSelected(null)} />}</>
}

export function JobDetails({ job, onClose }: { job: Job; onClose: () => void }) {
  const { state } = useApp()
  const current = state.jobs.find(item => item.id === job.id) || job
  return <Modal title="任务详情" description={actionLabel(current.action)} onClose={onClose}><div className="modal-body"><OwnerLabel ownerID={current.owner_id} /><dl className="detail-grid"><dt>任务 ID</dt><dd className="mono wrap">{current.id}</dd><dt>入口节点</dt><dd>{nodeTitle(state.nodes, current.node_id)}</dd>{current.relay_id && <><dt>转发 ID</dt><dd className="mono wrap">{current.relay_id}</dd></>}<dt>当前状态</dt><dd><StatusBadge status={current.status} /></dd><dt>创建时间</dt><dd>{formatDate(current.created_at)}</dd><dt>完成时间</dt><dd>{formatDate(current.finished_at)}</dd><dt>配置版本</dt><dd className="mono wrap">{current.revision || '—'}</dd></dl><pre className="log-output">{current.error || current.message || '暂无执行信息'}</pre></div><div className="modal-footer"><Button onClick={onClose}>关闭</Button></div></Modal>
}

export function SubscriptionExport({ onClose, settings }: { onClose: () => void; settings?: Settings }) {
  const { state } = useApp()
  const { busy, error, run } = useAction()
  const ownSettings = settings || state.settings
  const url = subscriptionURL(ownSettings.subscription_token, ownSettings.panel_url)
  return <Modal title="导出我的转发订阅" description="个人订阅仅包含当前账户自己的已启用转发规则。" onClose={onClose} busy={busy}><div className="modal-body"><Alert title="个人订阅">使用当前账户的独立令牌，仅导出自己的已启用入口。管理员也使用个人订阅范围。</Alert>{url ? <><QRCodeBlock value={url} /><Field label="我的订阅地址"><input readOnly value={url} className="mono" onFocus={event => event.currentTarget.select()} /></Field><Alert>订阅地址含有访问令牌，请只分享给可信任的人。入口变更在客户端刷新订阅后生效。</Alert>{error && <Alert tone="danger">{error}</Alert>}</> : <Alert tone="warning">服务尚未提供订阅令牌，请在账户设置中生成订阅令牌。</Alert>}</div><div className="modal-footer"><Button onClick={onClose}>关闭</Button><Button disabled={!url} busy={busy} onClick={() => run(async () => { const response = await fetch(`/sub/${encodeURIComponent(ownSettings.subscription_token || '')}`, { credentials: 'same-origin', cache: 'no-store' }); if (!response.ok) { const body = await response.json().catch(() => ({})) as { error?: string }; throw new Error(body.error || `导出失败（HTTP ${response.status}）`) } downloadText(await response.text(), 'relay-subscription.txt') }, { refresh: false, success: '订阅文件已导出' })}><Download size={15} />下载订阅</Button><CopyButton value={url} label="复制地址" /></div></Modal>
}

export function useProbeAction() {
  const { registerProbe } = useApp()
  const action = useAction()
  return { ...action, probe: async (nodeID: string, upstreamID: string) => action.run(async () => { const job = await api<Job>(`/api/nodes/${encodeURIComponent(nodeID)}/probe`, 'POST', { upstream_id: upstreamID }); registerProbe(nodeID, upstreamID, job); return job }, { success: '出口节点检测已提交，结果将自动更新。' }) }
}
