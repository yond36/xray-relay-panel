import { useEffect, useRef, useState } from 'react'
import { CheckCircle2, Copy, Download, KeyRound, Link2, LockKeyhole, RefreshCw, Rss, Save, Settings2, ShieldCheck, Users } from 'lucide-react'
import { api } from '../api'
import { useAction, useApp } from '../context'
import type { Settings } from '../types'
import { roleLabel, subscriptionURL } from '../utils'
import CoreVersionPicker from '../components/CoreVersionPicker'
import { Alert, Badge, Button, Card, ConfirmDialog, CopyButton, Field, PageHeader, SubscriptionExport } from '../components/ui'

export default function SettingsPage() {
  const { state, user, isAdmin, navigate } = useApp()
  const { busy, error, run } = useAction()
  const [saved, setSaved] = useState<Settings>(state.settings)
  const [panelURL, setPanelURL] = useState(state.settings.panel_url)
  const [coreVersion, setCoreVersion] = useState(state.settings.core_version)
  const [registrationOpen, setRegistrationOpen] = useState(state.settings.registration_open)
  const [rotate, setRotate] = useState(false)
  const [exportOpen, setExportOpen] = useState(false)
  const didLoad = useRef(false)
  async function load() {
    const result = await run(() => api<Settings>('/api/settings'), { refresh: false })
    if (result.ok) {
      setSaved(result.value)
      setPanelURL(result.value.panel_url)
      setCoreVersion(result.value.core_version)
      setRegistrationOpen(result.value.registration_open)
    }
  }
  useEffect(() => { if (!didLoad.current) { didLoad.current = true; void load() } }, [])
  const url = subscriptionURL(saved.subscription_token, saved.panel_url)
  const dirty = panelURL !== saved.panel_url || coreVersion !== saved.core_version || registrationOpen !== saved.registration_open

  return <>
    <PageHeader eyebrow={isAdmin ? 'SYSTEM PREFERENCES' : 'ACCOUNT PREFERENCES'} title={isAdmin ? '系统设置' : '账户与订阅'} description={isAdmin ? '管理全局默认值、公开注册与当前账户的订阅导出。' : '查看当前账户，管理你自己的订阅地址和访问令牌。'} actions={<Button disabled={busy} onClick={load}><RefreshCw size={16} />重新读取</Button>} />
    {error && <Alert tone="danger">{error}</Alert>}
    <div className="settings-grid">
      {isAdmin ? <Card title="全局设置" description="管理员可修改；默认核心版本用于保存时未指定版本的入口节点。">
        <form onSubmit={async event => {
          event.preventDefault()
          if (!isAdmin) return
          const changes = { panel_url: panelURL.trim().replace(/\/+$/, ''), core_version: coreVersion.trim(), registration_open: registrationOpen }
          const result = await run(() => api<Settings>('/api/settings', 'PUT', changes), { success: '全局设置已保存。修改版本不会自动升级或应用入口节点。' })
          if (result.ok) {
            const updated = result.value || { ...saved, ...changes }
            setSaved(updated)
            setPanelURL(updated.panel_url)
            setCoreVersion(updated.core_version)
            setRegistrationOpen(updated.registration_open)
          }
        }}>
          <div className="settings-card-body">
            <Field label="控制台公开 URL" hint="用于生成订阅地址。留空时使用当前浏览器访问地址。"><input type="url" value={panelURL} onChange={event => setPanelURL(event.target.value)} placeholder={window.location.origin} disabled={busy} /></Field>
            <CoreVersionPicker value={coreVersion} onChange={setCoreVersion} label="默认 Xray 核心版本 / 自定义 tag" disabled={busy} />
            <div className="registration-control"><div><strong className="field-label">开放公开注册</strong><p>开放后，访客可通过用户名和密码注册普通用户账户。</p><Badge tone={registrationOpen ? 'success' : 'neutral'}>{registrationOpen ? '注册开放' : '注册关闭'}{registrationOpen !== saved.registration_open ? ' · 未保存' : ''}</Badge></div><button type="button" role="switch" aria-label="开放公开注册" aria-checked={Boolean(registrationOpen)} className={`toggle ${registrationOpen ? 'toggle-on' : ''}`} disabled={busy} onClick={() => setRegistrationOpen(current => !current)}><span /></button></div>
            <Alert>修改后点击“保存全局设置”生效。入口节点的版本变更仍需到入口节点页手动保存并提交应用任务。</Alert>
          </div>
          <div className="settings-card-footer"><span>{dirty ? <><span className="unsaved-dot" />有未保存的修改</> : <><CheckCircle2 size={14} />设置已同步</>}</span><Button type="submit" variant="primary" busy={busy} disabled={!dirty}><Save size={15} />保存全局设置</Button></div>
        </form>
      </Card> : <Card title="当前账户" description="你的资源和订阅令牌按账户独立管理。"><div className="settings-card-body"><dl className="detail-grid"><dt>用户名</dt><dd className="wrap">{user.username}</dd><dt>角色</dt><dd><Badge>{roleLabel(user.role)}</Badge></dd><dt>用户 ID</dt><dd className="mono wrap">{user.id}</dd></dl><Alert>当前工作空间仅显示你自己的入口节点、出口节点、转发与任务。可通过 SSH 添加入口节点。</Alert></div></Card>}
      <Card title="账户与隔离" description="当前账户的访问范围与连接保护。">
        <div className="security-facts">
          <div><span className="security-icon"><LockKeyhole size={20} /></span><div><strong>{user.username} · {roleLabel(user.role)}</strong><p>使用 HttpOnly、SameSite Cookie。退出登录会结束当前会话。</p></div></div>
          <div><span className="security-icon"><Users size={20} /></span><div><strong>{isAdmin ? '管理全部用户的配置' : '独立的用户资源'}</strong><p>{isAdmin ? '资源列表显示所属用户；编辑时保持原归属，转发仅关联同一用户的入口节点和出口节点。' : '入口节点、出口节点和转发均属于当前账户。全局设置与用户管理由管理员维护。'}</p>{isAdmin && <button className="inline-link" type="button" onClick={() => navigate('users')}>打开用户管理</button>}</div></div>
          <div><span className="security-icon"><ShieldCheck size={20} /></span><div><strong>SSH 主机验证</strong><p>首次连接先核对主机指纹，显式信任后才能执行远程检查和部署。</p></div></div>
          <div><span className="security-icon"><Settings2 size={20} /></span><div><strong>独立入口节点服务</strong><p className="mono">xray-relay-panel-node.service</p><p>配置保存在独立工作目录，与其他 Xray 安装分开管理。</p></div></div>
        </div>
      </Card>
    </div>
    <Card title="我的转发订阅" description="个人订阅仅包含当前账户自己的已启用转发，管理员也使用个人订阅范围。" action={<Badge tone="info"><Rss size={12} />{state.relays.filter(relay => relay.enabled && relay.owner_id === user.id).length} 条本人启用转发</Badge>}>
      <div className="subscription-export-panel"><div className="subscription-export-icon"><Link2 size={28} /></div><div className="subscription-export-content">
        <h3>我的客户端订阅地址</h3>
        <p>在兼容客户端中添加此地址，刷新后获取最新转发配置。请先应用入口节点配置，再验证客户端连接。</p>
        {url ? <div className="subscription-url"><input aria-label="我的转发订阅地址" readOnly value={url} className="mono" onFocus={event => event.currentTarget.select()} /><CopyButton value={url} small label="复制" /></div> : <Alert tone="warning">当前账户尚未生成订阅令牌，点击下方按钮创建令牌。</Alert>}
        <div className="subscription-export-actions"><Button onClick={() => setExportOpen(true)} disabled={!url}><Download size={15} />二维码与文件导出</Button><Button disabled={busy} onClick={() => setRotate(true)}><KeyRound size={15} />{url ? '轮换我的订阅令牌' : '生成我的订阅令牌'}</Button></div>
      </div></div>
      <div className="settings-notice"><ShieldCheck size={16} /><span>订阅 URL 本身就是访问凭证。轮换仅影响当前账户的令牌，旧地址立即失效；已分享的单条转发链接不会因此撤销。</span></div>
    </Card>
    <div className="page-notes"><Copy size={15} /><span>入口节点密码、私钥等已保存凭证不会从列表回显；编辑入口节点时留空会保留当前凭证。</span></div>
    {rotate && <ConfirmDialog title={url ? '轮换我的订阅访问令牌' : '生成我的订阅访问令牌'} description={url ? '仅轮换当前账户的令牌。旧订阅 URL 将立即失效，请在使用此订阅的客户端中更新地址；单条转发凭证保持原样。' : '为当前账户生成独立的随机订阅令牌，用于导出订阅地址。'} confirmLabel={url ? '确认轮换令牌' : '生成令牌'} danger={Boolean(url)} onClose={() => setRotate(false)} action={async () => { await api('/api/settings/rotate-token', 'POST', {}); const updated = await api<Settings>('/api/settings'); setSaved(updated) }} success="你的订阅令牌已更新，请使用新的订阅地址。" />}
    {exportOpen && <SubscriptionExport settings={saved} onClose={() => setExportOpen(false)} />}
  </>
}
