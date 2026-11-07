import { createContext, useContext, useState } from 'react'
import type { Job, Page, ProbeJobs, State, ToastKind } from './types'

interface AppContextValue {
  state: State
  refreshing: boolean
  refresh: () => Promise<void>
  navigate: (page: Page) => void
  toast: (message: string, kind?: ToastKind) => void
  probeJobs: ProbeJobs
  registerProbe: (nodeID: string, upstreamID: string, job: Job) => void
}
export const AppContext = createContext<AppContextValue | null>(null)
export function useApp() {
  const context = useContext(AppContext)
  if (!context) throw new Error('应用上下文尚未加载')
  return { ...context, user: context.state.current_user, isAdmin: context.state.current_user.role === 'admin' }
}

export function useAction() {
  const { refresh, toast } = useApp()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function run<T>(fn: () => Promise<T>, options: { success?: string; refresh?: boolean } = {}): Promise<{ ok: true; value: T } | { ok: false }> {
    setBusy(true)
    setError('')
    try {
      const value = await fn()
      if (options.refresh !== false) {
        try { await refresh() } catch { toast('操作已提交，但状态刷新失败，请稍后刷新。', 'error') }
      }
      if (options.success) toast(options.success, 'success')
      return { ok: true, value }
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : '操作失败，请重试。'
      setError(message)
      toast(message, 'error')
      return { ok: false }
    } finally {
      setBusy(false)
    }
  }
  return { busy, error, run, clearError: () => setError('') }
}
