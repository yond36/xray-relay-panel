import type { RelayDeleteResult } from './types'

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function request<T>(path: string, method = 'GET', body?: unknown): Promise<{ status: number; data: T }> {
  let response: Response
  try {
    response = await fetch(path, {
      method,
      credentials: 'same-origin',
      headers: body === undefined ? { Accept: 'application/json' } : { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: 'no-store',
    })
  } catch {
    throw new Error('无法连接服务，请检查网络或后端服务后重试。')
  }
  if (response.status === 401 && !path.startsWith('/api/auth/')) {
    window.dispatchEvent(new Event('session-expired'))
  }
  if (!response.ok) {
    const data = await response.json().catch(() => ({})) as { error?: string }
    throw new ApiError(data.error || `请求失败（HTTP ${response.status}）`, response.status)
  }
  if (response.status === 204) return { status: response.status, data: undefined as T }
  const text = await response.text()
  if (!text) return { status: response.status, data: undefined as T }
  try {
    return { status: response.status, data: JSON.parse(text) as T }
  } catch {
    throw new Error('服务返回了无效的数据，请确认 API 服务已启动。')
  }
}

export async function api<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
  return (await request<T>(path, method, body)).data
}

export const endpoint = (collection: string, id: string) => `/api/${collection}/${encodeURIComponent(id)}`

export async function deleteRelay(id: string): Promise<RelayDeleteResult> {
  const { status, data } = await request<RelayDeleteResult>(endpoint('relays', id), 'DELETE')
  if (status === 202 && data && typeof data === 'object' && 'id' in data && data.id && data.action === 'delete-relay' && typeof data.status === 'string' && (!data.relay_id || data.relay_id === id)) return data
  if (status === 204 || status === 200 && data && typeof data === 'object' && 'deleted' in data && data.deleted === true) return data
  throw new Error('服务未返回有效的删除结果，请刷新任务记录确认进度后重试。')
}

export async function copyText(value: string) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(value)
    return
  }
  const field = document.createElement('textarea')
  field.value = value
  field.style.position = 'fixed'
  field.style.opacity = '0'
  document.body.appendChild(field)
  field.select()
  const copied = document.execCommand('copy')
  field.remove()
  if (!copied) throw new Error('浏览器未允许自动复制，请手动选择并复制内容。')
}

export function downloadText(content: string, filename: string) {
  const url = URL.createObjectURL(new Blob([content], { type: 'text/plain;charset=utf-8' }))
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
