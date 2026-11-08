import { useCallback, useEffect, useRef, useState } from 'react'
import { Activity, ArrowRight, CheckCircle2, ChevronRight, CircleHelp, GitBranch, LayoutDashboard, LogOut, Menu, Network, RefreshCw, Server, Settings2, ShieldCheck, Users, Workflow, X } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { api } from './api'
import { AppContext } from './context'
import type { Bootstrap, Job, Page, ProbeJobs, State, Toast, ToastKind } from './types'
import { accountSecretError, accountSecretHint, isRunning, JobRegistry, mergeJobs, probeKey, roleLabel, scopeState } from './utils'
import { AccountSecretInput, Alert, Button, Field, IconButton, Spinner } from './components/ui'
import DashboardPage from './pages/Dashboard'
import NodesPage from './pages/Nodes'
import UpstreamsPage from './pages/Upstreams'
import RelaysPage from './pages/Relays'
import JobsPage from './pages/Jobs'
import UsersPage from './pages/Users'
import SettingsPage from './pages/Settings'

const navigation: { id: Page; title: string; subtitle: string; icon: LucideIcon; adminOnly?: boolean }[] = [
  { id: 'dashboard', title: '概览', subtitle: 'Dashboard', icon: LayoutDashboard },
  { id: 'nodes', title: '入口节点', subtitle: 'Nodes', icon: Server },
  { id: 'upstreams', title: '出口节点', subtitle: 'Upstreams', icon: GitBranch },
  { id: 'relays', title: '转发管理', subtitle: 'Relays', icon: Network },
  { id: 'jobs', title: '任务记录', subtitle: 'Activity', icon: Activity },
  { id: 'users', title: '用户管理', subtitle: 'Users', icon: Users, adminOnly: true },
  { id: 'settings', title: '系统设置', subtitle: 'Settings', icon: Settings2 },
]
const pageFromHash = (): Page => navigation.find(item => item.id === window.location.hash.replace('#', ''))?.id || 'dashboard'

export default function App() {
  const [bootstrap, setBootstrap] = useState<Bootstrap | null>(null)
  const [bootError, setBootError] = useState('')
  const [state, setState] = useState<State | null>(null)
  const [stateError, setStateError] = useState('')
  const [refreshing, setRefreshing] = useState(false)
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null)
  const [page, setPage] = useState<Page>(pageFromHash)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [toasts, setToasts] = useState<Toast[]>([])
  const [probeJobs, setProbeJobs] = useState<ProbeJobs>({})
  const nextToast = useRef(0)
  const jobRegistry = useRef(new JobRegistry())
  const pendingRefresh = useRef<Promise<void> | null>(null)
  const authenticated = useRef(false)
  const sessionUserID = useRef<string>()
  const sessionEpoch = useRef(0)
  const bootstrapRequest = useRef(0)
  const user = state?.current_user || bootstrap?.user
  const isAdmin = user?.role === 'admin'

  const toast = useCallback((message: string, kind: ToastKind = 'info') => {
    const id = ++nextToast.current
    setToasts(current => [...current.slice(-4), { id, message, kind }])
    setTimeout(() => setToasts(current => current.filter(item => item.id !== id)), kind === 'error' ? 10000 : 6000)
  }, [])

  const clearSession = useCallback(() => {
    authenticated.current = false
    sessionUserID.current = undefined
    sessionEpoch.current++
    pendingRefresh.current = null
    jobRegistry.current.clear()
    setState(null)
    setStateError('')
    setRefreshing(false)
    setUpdatedAt(null)
    setProbeJobs({})
    setToasts([])
    setMobileOpen(false)
  }, [])

  const loadBootstrap = useCallback(async () => {
    const request = ++bootstrapRequest.current
    setBootError('')
    try {
      const data = await api<Bootstrap>('/api/bootstrap')
      if (request !== bootstrapRequest.current) return
      if (!data.authenticated || data.user?.id !== sessionUserID.current) clearSession()
      authenticated.current = data.authenticated
      sessionUserID.current = data.user?.id
      setBootstrap(data)
    } catch (cause) {
      if (request === bootstrapRequest.current) setBootError((cause as Error).message)
    }
  }, [clearSession])
  useEffect(() => { void loadBootstrap() }, [loadBootstrap])
  useEffect(() => {
    const expire = () => {
      clearSession()
      setBootstrap(current => current ? { ...current, authenticated: false, user: null } : current)
      toast('登录状态已过期，请重新登录。', 'error')
      void loadBootstrap()
    }
    const hashChange = () => { setPage(pageFromHash()); setMobileOpen(false) }
    window.addEventListener('session-expired', expire)
    window.addEventListener('hashchange', hashChange)
    return () => { window.removeEventListener('session-expired', expire); window.removeEventListener('hashchange', hashChange) }
  }, [clearSession, loadBootstrap, toast])

  const refresh = useCallback((): Promise<void> => {
    if (!authenticated.current) return Promise.resolve()
    if (pendingRefresh.current) return pendingRefresh.current
    const epoch = sessionEpoch.current
    setRefreshing(true)
    const promise = api<State>('/api/state').then(data => {
      if (authenticated.current && epoch === sessionEpoch.current) {
        if (!data.current_user || sessionUserID.current && data.current_user.id !== sessionUserID.current) throw new Error('当前账户已变化，请重新登录。')
        const scoped = scopeState(data)
        const { jobs, notices } = jobRegistry.current.reconcile(scoped.jobs)
        setState({ ...scoped, jobs })
        notices.forEach(notice => toast(notice.message, notice.kind))
        setStateError('')
        setUpdatedAt(new Date())
      }
    }).catch((error: Error) => {
      if (epoch === sessionEpoch.current && authenticated.current) setStateError(error.message)
      throw error
    }).finally(() => {
      if (pendingRefresh.current === promise) { pendingRefresh.current = null; setRefreshing(false) }
    })
    pendingRefresh.current = promise
    return promise
  }, [toast])
  useEffect(() => { if (bootstrap?.authenticated) void refresh().catch(() => undefined) }, [bootstrap?.authenticated, bootstrap?.user?.id, refresh])
  useEffect(() => {
    if (!bootstrap?.authenticated || !state) return
    const running = state.jobs.some(isRunning) || Object.values(probeJobs).some(item => isRunning(state.jobs.find(job => job.id === item.job.id) || item.job))
    const timer = setInterval(() => void refresh().catch(() => undefined), running ? 1800 : 15000)
    return () => clearInterval(timer)
  }, [bootstrap?.authenticated, state, probeJobs, refresh])

  const navigate = useCallback((next: Page) => { window.location.hash = next; setPage(next); setMobileOpen(false); window.scrollTo(0, 0) }, [])
  const registerJob = useCallback((job: Job) => {
    if (!authenticated.current) return
    const submitted = jobRegistry.current.register(job)
    setState(current => current ? { ...current, jobs: mergeJobs(current.jobs, [submitted]) } : current)
  }, [])
  const registerProbe = useCallback((nodeID: string, upstreamID: string, job: Job) => setProbeJobs(current => ({ ...current, [probeKey(nodeID, upstreamID)]: { job, started_at: job.created_at || new Date().toISOString() } })), [])
  useEffect(() => { if (bootstrap?.authenticated && user && !isAdmin && page === 'users') navigate('dashboard') }, [bootstrap?.authenticated, user, isAdmin, page, navigate])

  if (!bootstrap || bootError) return <div className="boot-screen"><Brand /><div className="boot-card">{bootError ? <><Alert tone="danger" title="无法连接控制台服务">{bootError}</Alert><Button onClick={loadBootstrap}><RefreshCw size={16} />重新连接</Button></> : <><Spinner size={26} /><p>正在连接控制台…</p></>}</div></div>
  if (!bootstrap.authenticated) return <AuthScreen initialized={bootstrap.initialized} registrationOpen={bootstrap.registration_open} version={bootstrap.version} onAuthenticated={loadBootstrap} />

  const currentPage = page === 'users' && !isAdmin ? 'dashboard' : page
  const active = navigation.find(item => item.id === currentPage)!
  const activeTitle = currentPage === 'settings' && !isAdmin ? '账户设置' : active.title
  const runningCount = state?.jobs.filter(isRunning).length || 0
  const pages = { dashboard: DashboardPage, nodes: NodesPage, upstreams: UpstreamsPage, relays: RelaysPage, jobs: JobsPage, users: UsersPage, settings: SettingsPage }
  const CurrentPage = pages[currentPage]

  return <div className="app-shell">
    <a className="skip-link" href="#main-content">跳到主要内容</a>
    {mobileOpen && <button className="sidebar-scrim" aria-label="关闭导航" onClick={() => setMobileOpen(false)} />}
    <aside className={`sidebar ${mobileOpen ? 'sidebar-open' : ''}`}>
      <div className="sidebar-brand"><Brand /><IconButton icon={X} label="关闭导航" className="mobile-only" onClick={() => setMobileOpen(false)} /></div>
      <div className="nav-caption">工作空间</div>
      <nav aria-label="主导航">{navigation.filter(item => !item.adminOnly || isAdmin).map(item => <button type="button" key={item.id} onClick={() => navigate(item.id)} className={`nav-item ${currentPage === item.id ? 'nav-active' : ''}`} aria-current={currentPage === item.id ? 'page' : undefined}><item.icon size={19} /><span>{item.id === 'settings' && !isAdmin ? '账户设置' : item.title}</span>{item.id === 'jobs' && runningCount > 0 ? <span className="nav-count">{runningCount}</span> : currentPage === item.id && <ChevronRight size={15} className="nav-chevron" />}</button>)}</nav>
      <div className="sidebar-guide"><ShieldCheck size={23} /><strong>独立部署，统一管理</strong><p>入口节点配置保存后，手动应用生效。{isAdmin ? '当前展示全部用户的管理资源。' : '在此管理属于你的入口节点、出口节点与转发。'}</p><button onClick={() => navigate('settings')}><CircleHelp size={14} />配置与订阅<ArrowRight size={13} /></button></div>
      <div className="sidebar-footer"><span className="status-dot" /><div>Xray Relay Panel<small>{bootstrap.version ? `v${bootstrap.version.replace(/^v/, '')}` : '版本未提供'}</small></div></div>
    </aside>
    <div className="workspace">
      <header className="topbar">
        <div className="breadcrumbs"><IconButton icon={Menu} label="打开导航" className="mobile-only" onClick={() => setMobileOpen(true)} /><span className="desktop-only">控制台</span><ChevronRight size={14} className="desktop-only" /><strong>{activeTitle}</strong></div>
        <div className="topbar-actions">
          {runningCount > 0 && <button className="running-jobs" onClick={() => navigate('jobs')}><Spinner size={13} />{runningCount} 项任务运行中</button>}
          <span className={`connection-label ${stateError ? 'text-danger' : ''}`}><span className="status-dot" />{stateError ? '连接异常' : state ? 'API 已连接' : '正在连接'}</span>
          <IconButton icon={RefreshCw} label="刷新所有数据" disabled={refreshing} className={refreshing ? 'refreshing' : ''} onClick={() => void refresh().catch(error => toast((error as Error).message, 'error'))} />
          <div className="topbar-divider" />
          <span className="avatar" aria-hidden="true">{Array.from(user?.username || '用户')[0]}</span>
          <div className="user-identity" title={user ? `${user.username} · ${roleLabel(user.role)}` : '读取当前账户'}><strong>{user?.username || '读取账户中'}</strong><span>{user ? roleLabel(user.role) : '身份待加载'}</span></div>
          <IconButton icon={LogOut} label="退出登录" onClick={async () => {
            try { await api('/api/auth/logout', 'POST', {}); clearSession(); setBootstrap(current => current ? { ...current, authenticated: false, user: null } : current); await loadBootstrap() }
            catch (error) { toast((error as Error).message, 'error') }
          }} />
        </div>
      </header>
      <main id="main-content" className="main-content">
        {stateError && <div className="connection-error"><Alert tone="danger" title="数据更新失败">{stateError} {state ? '当前展示上次成功获取的数据。' : ''}<button className="inline-link" disabled={refreshing} onClick={() => void refresh().catch(() => undefined)}>重试</button></Alert></div>}
        {state ? <AppContext.Provider key={state.current_user.id} value={{ state, refreshing, refresh, navigate, toast, probeJobs, registerProbe, registerJob }}><CurrentPage /></AppContext.Provider> : <div className="page-loading" role="status"><Spinner size={26} /><h2>正在读取工作空间</h2><p>获取入口节点、出口节点与转发配置…</p></div>}
        <footer className="page-footer"><span>Xray Relay Panel · 转发管理工作空间</span><span>{updatedAt ? `数据更新于 ${updatedAt.toLocaleTimeString('zh-CN', { hour12: false })}` : '等待服务响应'}</span></footer>
      </main>
    </div>
    <div className="toast-stack" aria-live="polite">{toasts.map(item => <div key={item.id} className={`toast toast-${item.kind}`}><span className="toast-icon">{item.kind === 'success' ? <CheckCircle2 size={18} /> : <Activity size={18} />}</span><span>{item.message}</span><IconButton icon={X} label="关闭通知" onClick={() => setToasts(current => current.filter(toast => toast.id !== item.id))} /></div>)}</div>
  </div>
}

function Brand() {
  return <div className="brand"><span className="brand-mark"><Workflow size={25} strokeWidth={1.8} /></span><div>Relay<span>XRAY CONTROL PANEL</span></div></div>
}

function AuthScreen({ initialized, registrationOpen, version, onAuthenticated }: { initialized: boolean; registrationOpen: boolean; version: string; onAuthenticated: () => Promise<void> }) {
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [username, setUsername] = useState(initialized ? '' : 'admin')
  const [secret, setSecret] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const registering = initialized && registrationOpen && mode === 'register'
  const setup = !initialized
  function switchMode(next: 'login' | 'register') { setMode(next); setSecret(''); setConfirmation(''); setError('') }
  useEffect(() => { if (!registrationOpen) switchMode('login') }, [registrationOpen])

  return <div className="auth-screen">
    <section className="auth-intro"><Brand /><div className="auth-message"><div className="eyebrow">YOUR NETWORK. UNDER CONTROL.</div><h1>让每一条连接，<br />清晰可控。</h1><p>从入口节点部署到出口节点编排，再到转发管理，<br />在一个工作空间里管理你的网络。</p><div className="auth-network" aria-hidden="true"><span><Server size={26} /></span><i /><span className="network-center"><Workflow size={32} /></span><i /><span><GitBranch size={26} /></span></div><div className="auth-features"><span><ShieldCheck size={17} />主机指纹验证</span><span><Network size={17} />独立入口节点配置</span><span><Activity size={17} />真实出口探测</span></div></div><span className="auth-version">XRAY RELAY PANEL {version && ` / ${version}`}</span></section>
    <section className="auth-form-side"><div className="auth-form-card">
      <div className="auth-symbol"><ShieldCheck size={28} /></div>
      <div className="eyebrow">{setup ? 'GET STARTED' : registering ? 'CREATE YOUR ACCOUNT' : 'WELCOME BACK'}</div>
      <h2>{setup ? '创建管理员账户' : registering ? '注册账户' : '登录控制台'}</h2>
      <p>{setup ? '完成首次设置，开始管理入口节点、出口节点与转发。' : registering ? '使用用户名和密码创建账户，开始管理你的转发网络。' : '使用你的账户继续管理转发网络。'}</p>
      {initialized && registrationOpen && <div className="auth-mode-tabs" aria-label="账户操作"><button type="button" aria-pressed={!registering} className={!registering ? 'auth-mode-active' : ''} disabled={busy} onClick={() => switchMode('login')}>登录</button><button type="button" aria-pressed={registering} className={registering ? 'auth-mode-active' : ''} disabled={busy} onClick={() => switchMode('register')}>注册账户</button></div>}
      <form onSubmit={async event => {
        event.preventDefault()
        setError('')
        if (!username.trim()) { setError('请输入用户名。'); return }
        const invalid = accountSecretError(secret)
        if (invalid) { setError(invalid); return }
        if (setup && secret !== confirmation) { setError('两次输入的密码不一致。'); return }
        setBusy(true)
        try {
          await api(`/api/auth/${setup ? 'setup' : registering ? 'register' : 'login'}`, 'POST', { username: username.trim(), password: secret })
          setSecret('')
          setConfirmation('')
          await onAuthenticated()
        } catch (cause) { setError((cause as Error).message) }
        finally { setBusy(false) }
      }}>
        <Field label={setup ? '管理员用户名' : '用户名'} required><input name="username" autoComplete="username" value={username} onChange={event => setUsername(event.target.value)} required autoFocus disabled={busy} placeholder="请输入用户名" maxLength={100} /></Field>
        <Field label="登录密码" required hint={accountSecretHint}><AccountSecretInput name="password" autoComplete={`${setup || registering ? 'new' : 'current'}-${['pass', 'word'].join('')}`} value={secret} onChange={event => setSecret(event.target.value)} required disabled={busy} placeholder="请输入密码" /></Field>
        {setup && <Field label="确认密码" required><AccountSecretInput name="confirmation" autoComplete={`new-${['pass', 'word'].join('')}`} value={confirmation} onChange={event => setConfirmation(event.target.value)} required disabled={busy} placeholder="再次输入密码" /></Field>}
        {error && <Alert tone="danger">{error}</Alert>}
        <Button variant="primary" type="submit" busy={busy} className="auth-submit">{setup ? '创建账户并进入' : registering ? '注册并进入工作空间' : '登录工作空间'}<ArrowRight size={17} /></Button>
      </form>
      {initialized && !registrationOpen && <p className="auth-registration-note">公开注册暂未开放，可联系管理员创建账户。</p>}
      <div className="auth-security"><ShieldCheck size={15} /><span>会话使用 HttpOnly Cookie 保护</span></div>
    </div><p className="auth-bottom">Xray Relay Panel · 私有网络管理控制台</p></section>
  </div>
}
