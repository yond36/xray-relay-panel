import { useCallback, useEffect, useId, useRef, useState } from 'react'
import { ExternalLink, RefreshCw } from 'lucide-react'
import { api } from '../api'
import type { CoreReleases } from '../types'
import { formatDate } from '../utils'
import { Alert, Badge, Button, Field, Spinner } from './ui'

interface CoreVersionPickerProps {
  value: string
  onChange: (tag: string) => void
  label?: string
  allowDefault?: boolean
  defaultVersion?: string
  disabled?: boolean
}

export default function CoreVersionPicker({ value, onChange, label = 'Xray 核心版本', allowDefault = false, defaultVersion, disabled = false }: CoreVersionPickerProps) {
  const [data, setData] = useState<CoreReleases | null>(null)
  const [loading, setLoading] = useState(false)
  const [loadError, setLoadError] = useState('')
  const request = useRef(0)
  const selectID = useId()
  const statusID = useId()
  const load = useCallback(async (refresh = false) => {
    const id = ++request.current
    setLoading(true)
    setLoadError('')
    try {
      const result = await api<CoreReleases>(`/api/core/releases${refresh ? '?refresh=true' : ''}`)
      if (id === request.current) setData({ ...result, releases: result.releases || [] })
    } catch (cause) {
      if (id === request.current) setLoadError((cause as Error).message)
    } finally {
      if (id === request.current) setLoading(false)
    }
  }, [])
  useEffect(() => { void load(); return () => { request.current++ } }, [load])

  const releases = data?.releases || []
  const selected = releases.find(release => release.tag === value)
  const unavailable = loadError || data?.error
  const defaultLabel = defaultVersion ? `当前系统默认 ${defaultVersion}` : '当前系统默认版本'
  const releaseURL = selected?.html_url && /^https:\/\/github\.com\/XTLS\/Xray-core\/releases\//i.test(selected.html_url) ? selected.html_url : ''

  return <div className="core-version-picker">
    <div className="version-picker-heading"><label htmlFor={selectID} className="field-label">官方 Xray 版本</label><Button type="button" size="sm" busy={loading} disabled={disabled} onClick={() => void load(true)}><RefreshCw size={13} />刷新列表</Button></div>
    <select id={selectID} aria-describedby={statusID} value={value} disabled={disabled || loading && !data} onChange={event => onChange(event.target.value)}>
      <option value="" disabled={!allowDefault}>{allowDefault ? `留空：保存时使用${defaultLabel}` : '手动选择官方发布版本'}</option>
      {value && !selected && <option value={value}>当前 tag：{value}（未在当前列表中）</option>}
      {releases.map(release => <option key={release.tag} value={release.tag}>{release.tag}{release.prerelease ? ' · 预发布' : ''}{release.name && release.name !== release.tag ? ` · ${release.name}` : ''}</option>)}
    </select>
    <div id={statusID} className="version-picker-status" role="status">
      {loading ? <span className="inline muted"><Spinner size={12} />正在获取官方版本列表…</span> : <span className="field-hint">{data?.fetched_at ? `列表缓存更新于 ${formatDate(data.fetched_at)}` : '官方版本列表尚未缓存'}{data?.stale ? ' · 缓存已过期' : ''}</span>}
      {selected && <div className="version-release-detail">{selected.prerelease && <Badge tone="warning">预发布</Badge>}<span className="field-hint">{selected.published_at ? `发布于 ${formatDate(selected.published_at)}` : selected.name}</span>{releaseURL && <a className="text-link" href={releaseURL} target="_blank" rel="noreferrer">发布说明<ExternalLink size={11} /></a>}</div>}
    </div>
    {unavailable || data?.stale ? <Alert tone="warning" title={releases.length ? '官方列表暂时无法更新，保留已有缓存' : '官方版本列表暂不可用'}>{unavailable || '服务器返回了过期缓存，请稍后刷新。'} 仍可在下方手动填写版本 tag；当前选择不会改变。</Alert> : data && !loading && !releases.length ? <Alert>官方列表暂时为空，可刷新列表或手动填写版本 tag。</Alert> : null}
    <Field label={label} required={!allowDefault} hint={allowDefault ? `可手动输入官方 tag。留空时，保存节点会固定使用${defaultLabel}。` : '可手动输入官方 tag，例如 v26.10.31、26.10.31 或带预发布后缀的版本。'}>
      <input value={value} onChange={event => onChange(event.target.value)} required={!allowDefault} disabled={disabled} maxLength={64} autoComplete="off" spellCheck={false} placeholder={allowDefault ? `留空使用${defaultLabel}` : '选择官方版本或手动输入 tag'} />
    </Field>
    <span className="field-hint">选择或刷新版本不会自动保存、升级或应用节点配置。</span>
  </div>
}
