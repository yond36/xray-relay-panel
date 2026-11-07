import { useCallback, useEffect, useRef, useState } from 'react'
import { CheckCircle2, Plus, RefreshCw, Users } from 'lucide-react'
import { api } from '../api'
import { useAction, useApp } from '../context'
import type { User, UserRole } from '../types'
import { accountSecretError, accountSecretHint, roleLabel } from '../utils'
import { AccountSecretInput, Alert, Badge, Button, Card, Empty, Field, Modal, PageHeader, Spinner } from '../components/ui'

export default function UsersPage() {
  const { state, isAdmin } = useApp()
  const [users, setUsers] = useState<User[]>(state.users || [])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [creating, setCreating] = useState(false)
  const request = useRef(0)
  const load = useCallback(async () => {
    if (!isAdmin) return
    const id = ++request.current
    setLoading(true)
    setError('')
    try {
      const result = await api<User[] | { users: User[] }>('/api/users')
      if (id === request.current) setUsers(Array.isArray(result) ? result : result.users || [])
    } catch (cause) {
      if (id === request.current) setError((cause as Error).message)
    } finally {
      if (id === request.current) setLoading(false)
    }
  }, [isAdmin])
  useEffect(() => { void load(); return () => { request.current++ } }, [load])

  if (!isAdmin) return <Alert tone="warning" title="需要管理员权限">用户管理仅对管理员开放。</Alert>

  return <>
    <PageHeader eyebrow="USER MANAGEMENT" title="用户管理" description="查看账户并创建新用户。关闭公开注册后，管理员仍可在此创建账户。" actions={<><Button disabled={loading} onClick={() => void load()}><RefreshCw size={16} />刷新列表</Button><Button variant="primary" onClick={() => setCreating(true)}><Plus size={16} />创建账户</Button></>} />
    <Alert>每个账户拥有独立的节点、上游、转发和订阅令牌；管理员可以管理全部用户的配置。</Alert>
    {error && <Alert tone="danger" title="用户列表读取失败">{error} <button className="inline-link" disabled={loading} onClick={() => void load()}>重试</button></Alert>}
    <Card>
      <div className="table-toolbar"><div className="toolbar-title"><Users size={18} /><strong>全部账户</strong><Badge>{users.length}</Badge></div>{loading && <span className="inline muted" role="status"><Spinner size={14} />正在读取</span>}</div>
      {users.length ? <div className="table-scroll"><table className="users-table"><thead><tr><th>用户名</th><th>角色</th><th>用户 ID</th></tr></thead><tbody>{users.map(user => <tr key={user.id}><td><div className="inline"><strong className="wrap">{user.username}</strong>{user.id === state.current_user.id && <Badge>当前账户</Badge>}</div></td><td><Badge tone={user.role === 'admin' ? 'info' : 'neutral'}>{roleLabel(user.role)}</Badge></td><td className="mono wrap muted">{user.id}</td></tr>)}</tbody></table></div> : !loading && <Empty icon={Users} title={error ? '暂时无法显示用户' : '暂无用户记录'} description={error ? '请重试读取用户列表。' : '创建账户后，用户可使用用户名和密码登录。'} />}
    </Card>
    {creating && <CreateUser onClose={() => setCreating(false)} onCreated={() => { setCreating(false); void load() }} />}
  </>
}

function CreateUser({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const { busy, error, run } = useAction()
  const [username, setUsername] = useState('')
  const [secret, setSecret] = useState('')
  const [role, setRole] = useState<UserRole>('user')
  return <Modal title="创建账户" description="新账户默认使用普通用户角色，创建后即可登录。" onClose={onClose} busy={busy}>
    <form onSubmit={async event => {
      event.preventDefault()
      const result = await run(async () => {
        if (!username.trim()) throw new Error('请输入用户名。')
        const invalid = accountSecretError(secret)
        if (invalid) throw new Error(invalid)
        return api<User>('/api/users', 'POST', { username: username.trim(), password: secret, role })
      }, { success: '账户已创建。' })
      if (result.ok) { setSecret(''); onCreated() }
    }}>
      <div className="modal-body">
        <Field label="用户名" required><input name="username" value={username} onChange={event => setUsername(event.target.value)} required maxLength={100} autoComplete="off" disabled={busy} placeholder="请输入用户名" /></Field>
        <Field label="登录密码" required hint={accountSecretHint}><AccountSecretInput name="password" value={secret} onChange={event => setSecret(event.target.value)} required autoComplete={`new-${['pass', 'word'].join('')}`} disabled={busy} placeholder="为新账户设置密码" /></Field>
        <Field label="角色"><select value={role} onChange={event => setRole(event.target.value as UserRole)} disabled={busy}><option value="user">普通用户（user）</option><option value="admin">管理员（admin）</option></select></Field>
        {error && <Alert tone="danger">{error}</Alert>}
      </div>
      <div className="modal-footer"><Button type="button" onClick={onClose} disabled={busy}>取消</Button><Button type="submit" variant="primary" busy={busy}><CheckCircle2 size={15} />创建账户</Button></div>
    </form>
  </Modal>
}
