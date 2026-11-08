import assert from 'node:assert/strict'
import test from 'node:test'
import { api, ApiError, deleteRelay } from '../api.ts'
import { isJobSuccess, isRunning, isSuccess, JobRegistry, relayApplyState, relayDeleteNotice, relayDeleteState } from '../utils.ts'

const time = second => `2026-11-09T00:00:${String(second).padStart(2, '0')}.000Z`
const relay = { id: 'relay-a', node_id: 'entry-a', upstream_id: 'exit-a', enabled: true, updated_at: time(10) }
const job = (id = 'delete-new', status = 'queued', extra = {}) => ({ id, owner_id: 'alice', node_id: 'entry-a', relay_id: relay.id, action: 'delete-relay', status, message: '', created_at: time(20), ...extra })
const response = (status, data) => new Response(data === undefined ? null : JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } })

function registerResult(registry, result) {
  assert.ok(result && 'id' in result, 'an accepted deletion must return a task')
  return registry.register({ ...result, relay_id: result.relay_id || relay.id })
}

test('HTTP 202 registers a pending task and sends DELETE without a body', async t => {
  let request
  t.mock.method(globalThis, 'fetch', async (path, options) => {
    request = { path, ...options }
    return response(202, job('delete-new', 'pending', { relay_id: 'relay/a' }))
  })
  const result = await deleteRelay('relay/a')
  assert.equal(request.path, '/api/relays/relay%2Fa')
  assert.equal(request.method, 'DELETE')
  assert.equal(request.body, undefined)
  assert.equal(request.headers['Content-Type'], undefined)
  assert.equal(result.action, 'delete-relay')
  assert.equal(isJobSuccess(result.status), false)
  const registry = new JobRegistry()
  registry.register(result)
  const current = registry.reconcile([])
  assert.equal(relayDeleteState(current.jobs, 'relay/a', result.id).phase, 'deleting')
  assert.deepEqual(current.notices, [])
})

test('HTTP 200 keeps the immediate deleted result, including pending_apply', async t => {
  const immediate = { deleted: true, pending_apply: true }
  t.mock.method(globalThis, 'fetch', async () => response(200, immediate))
  const result = await deleteRelay(relay.id)
  assert.deepEqual(result, immediate)
  assert.equal('id' in result, false)
})

test('HTTP 204 is immediate success without JSON or a task', async t => {
  t.mock.method(globalThis, 'fetch', async () => response(204))
  assert.equal(await deleteRelay(relay.id), undefined)
})

test('an already finished HTTP 202 task still waits for the state snapshot before reporting success', async t => {
  const completed = job('fast-delete', 'succeeded', { finished_at: time(21) })
  t.mock.method(globalThis, 'fetch', async () => response(202, completed))
  const registry = new JobRegistry()
  const submitted = registerResult(registry, await deleteRelay(relay.id))
  assert.equal(relayDeleteState([submitted], relay.id).phase, 'deleting')
  assert.deepEqual(registry.reconcile([]).notices, [])
  const confirmed = registry.reconcile([completed])
  assert.deepEqual(confirmed.notices, [{ message: '转发删除完成', kind: 'success' }])
  assert.equal(relayDeleteState(confirmed.jobs, relay.id).phase, 'succeeded')
  assert.deepEqual(registry.reconcile([completed]).notices, [])
})

test('empty, unrelated or mismatched HTTP 202 responses cannot become immediate success', async t => {
  for (const data of [undefined, true, { deleted: true }, job('wrong-action', 'queued', { action: 'apply' }), job('wrong-relay', 'queued', { relay_id: 'relay-b' })]) {
    t.mock.method(globalThis, 'fetch', async () => response(202, data))
    await assert.rejects(deleteRelay(relay.id), /未返回有效的删除结果/)
    t.mock.restoreAll()
  }
})

test('HTTP failures and malformed immediate responses remain retryable errors', async t => {
  t.mock.method(globalThis, 'fetch', async () => response(409, { error: '入口节点正在执行任务' }))
  await assert.rejects(deleteRelay(relay.id), error => error instanceof ApiError && error.status === 409 && error.message === '入口节点正在执行任务')
  t.mock.restoreAll()
  t.mock.method(globalThis, 'fetch', async () => response(200, { deleted: false }))
  await assert.rejects(deleteRelay(relay.id), /未返回有效的删除结果/)
})

test('queued, pending, running and in_progress remain deletions in progress', () => {
  for (const status of ['queued', 'pending', 'running', 'in_progress']) {
    const current = job('delete-new', status)
    assert.equal(isRunning(current), true)
    assert.equal(isJobSuccess(status), false)
    assert.equal(relayDeleteState([current], relay.id).phase, 'deleting')
    assert.equal(relayDeleteNotice(job(), current), undefined)
  }
  assert.equal(isSuccess('running'), true, 'service health semantics must not be used as deletion completion')
  for (const status of ['active', 'ready', 'unknown']) assert.equal(relayDeleteState([job('delete-new', status)], relay.id).phase, 'deleting')
})

test('only explicit terminal success statuses report completion', () => {
  for (const status of ['success', 'succeeded', 'completed', 'done', 'ok']) {
    const current = job('delete-new', status)
    assert.equal(relayDeleteState([current], relay.id).phase, 'succeeded')
    assert.equal(relayDeleteNotice(job(), current).kind, 'success')
  }
})

test('a registered task survives a first refresh that still contains only an old successful task', () => {
  const registry = new JobRegistry()
  const submitted = registry.register(job())
  const old = job('delete-old', 'succeeded', { created_at: time(5), finished_at: time(25) })
  const current = registry.reconcile([old])
  assert.equal(current.jobs.length, 2)
  assert.equal(relayDeleteState(current.jobs, relay.id, submitted.id).phase, 'deleting')
  assert.deepEqual(current.notices, [])
  const running = registry.reconcile([old, job('delete-new', 'running')])
  assert.equal(running.jobs.length, 2, 'the registered task must not duplicate its server record')
  assert.equal(relayDeleteState(running.jobs, relay.id, submitted.id).job.status, 'running')
})

test('the requested job ID cannot be replaced by another success or another relay', () => {
  const failed = job('retry', 'failed', { error: 'configuration rejected', created_at: time(20) })
  const older = job('older', 'succeeded', { created_at: time(10), finished_at: time(40) })
  const other = job('unrelated', 'succeeded', { relay_id: 'relay-b', created_at: time(50) })
  assert.equal(relayDeleteState([older, failed, other], relay.id, 'retry').error, 'configuration rejected')
  assert.equal(relayDeleteState([older, other], relay.id, 'retry').phase, 'deleting')
  assert.equal(relayDeleteState([other], relay.id).phase, 'idle')
  assert.equal(relayDeleteNotice(job('retry'), older), undefined)
})

test('failure or interruption overrides old success and uses the task error or message', () => {
  const older = job('older', 'succeeded', { created_at: time(10), finished_at: time(40) })
  for (const status of ['failed', 'interrupted', 'timeout', 'cancelled', 'canceled']) {
    const failed = job('retry', status, { error: 'rollback references could not be updated', message: 'less precise message' })
    const current = relayDeleteState([older, failed], relay.id)
    assert.equal(current.phase, 'failed')
    assert.equal(current.error, failed.error)
    const notice = relayDeleteNotice(job('retry'), failed)
    assert.equal(notice.kind, 'error')
    assert.match(notice.message, /rollback references could not be updated/)
    assert.match(notice.message, /保留.*直接重试/)
  }
  assert.equal(relayDeleteState([job('retry', 'interrupted', { message: '服务重启，任务中断' })], relay.id).error, '服务重启，任务中断')
  assert.equal(relayDeleteState([job('retry', 'interrupted')], relay.id).error, '已中断')
})

test('a new failed retry is followed by its exact ID and not masked by the previous success', () => {
  const registry = new JobRegistry()
  const old = job('old-success', 'succeeded', { created_at: time(5), finished_at: time(25) })
  registry.reconcile([old])
  const submitted = registry.register(job('retry'))
  const failed = job('retry', 'failed', { error: 'xray configuration invalid' })
  const current = registry.reconcile([old, failed])
  assert.equal(relayDeleteState(current.jobs, relay.id, submitted.id).phase, 'failed')
  assert.equal(current.notices.length, 1)
  assert.equal(current.notices[0].kind, 'error')
  assert.deepEqual(registry.reconcile([old, failed]).notices, [])
  const next = registry.register(job('retry-again', 'queued', { created_at: time(30) }))
  assert.equal(relayDeleteState([next, ...current.jobs], relay.id, next.id).phase, 'deleting')
  assert.equal(relay.enabled, true, 'retrying deletion does not require disabling the relay')
})

test('a failed state refresh keeps the relay and pending task, then recovers the actual failure', async t => {
  const registry = new JobRegistry()
  const failed = job('delete-new', 'failed', { error: 'SSH connection lost' })
  let request = 0
  t.mock.method(globalThis, 'fetch', async () => {
    request++
    if (request === 1) return response(202, job())
    if (request === 2) throw new Error('network disconnected')
    return response(200, { jobs: [failed], relays: [relay] })
  })
  const submitted = registerResult(registry, await deleteRelay(relay.id))
  const previous = { relays: [relay], ...registry.reconcile([]) }
  await assert.rejects(api('/api/state'), /无法连接服务/)
  assert.equal(relayDeleteState(previous.jobs, relay.id, submitted.id).phase, 'deleting')
  assert.deepEqual(previous.notices, [])
  assert.deepEqual(previous.relays, [relay])
  const snapshot = await api('/api/state')
  const recovered = registry.reconcile(snapshot.jobs)
  assert.equal(relayDeleteState(recovered.jobs, relay.id, submitted.id).error, 'SSH connection lost')
  assert.equal(recovered.notices[0].kind, 'error')
  assert.deepEqual(snapshot.relays, [relay])
})

test('persisted jobs restore progress and failure after reload or page navigation', () => {
  const registry = new JobRegistry()
  let current = registry.reconcile([job()])
  assert.equal(relayDeleteState(current.jobs, relay.id).phase, 'deleting')
  assert.deepEqual(current.notices, [])
  current = registry.reconcile([job('delete-new', 'running', { message: '正在更新入口配置' })])
  assert.equal(relayDeleteState(current.jobs, relay.id).job.message, '正在更新入口配置')
  const failed = job('delete-new', 'interrupted', { message: '服务重启导致中断' })
  current = registry.reconcile([failed])
  assert.equal(relayDeleteState(current.jobs, relay.id).error, failed.message)
  assert.equal(current.notices[0].kind, 'error')
  const reloaded = new JobRegistry().reconcile([failed])
  assert.equal(relayDeleteState(reloaded.jobs, relay.id).phase, 'failed')
  assert.deepEqual(reloaded.notices, [], 'reload must not replay historical completion notifications')
})

test('legacy jobs without relay_id remain visible and can be tracked by exact ID', () => {
  const legacy = job('legacy', 'running', { relay_id: undefined })
  assert.equal(relayDeleteState([legacy], relay.id, legacy.id).phase, 'deleting')
  assert.equal(relayDeleteState([legacy], relay.id).phase, 'idle')
  assert.equal(relayDeleteState([{ ...legacy, status: 'failed', message: 'legacy failure' }], relay.id, legacy.id).error, 'legacy failure')
})

test('clearing the session removes registered tasks and their notification history', () => {
  const registry = new JobRegistry()
  registry.register(job())
  registry.clear()
  assert.deepEqual(registry.reconcile([]), { jobs: [], notices: [] })
  assert.deepEqual(registry.reconcile([job('delete-new', 'succeeded')]).notices, [])
})

test('automatic deletion applies the current node configuration for other relays too', () => {
  const remaining = { ...relay, id: 'relay-b' }
  const node = { id: 'entry-a', applied_revision: 'new-revision' }
  const state = { nodes: [node], upstreams: [{ id: 'exit-a', updated_at: time(10) }], jobs: [job('delete-new', 'running')] }
  assert.equal(relayApplyState(remaining, state).label, '正在应用')
  state.jobs = [job('delete-new', 'succeeded', { revision: node.applied_revision })]
  assert.equal(relayApplyState(remaining, state).label, '已应用')
  state.jobs = [job('delete-new', 'failed', { revision: node.applied_revision })]
  assert.equal(relayApplyState(remaining, state).label, '待应用')
})
