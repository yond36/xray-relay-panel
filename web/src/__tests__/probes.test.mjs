import assert from 'node:assert/strict'
import test from 'node:test'
import { latestProbeNode, probeKey, probeNodes, probeState } from '../utils.ts'

const time = second => `2026-11-08T00:00:${String(second).padStart(2, '0')}.000Z`
const upstream = { id: 'exit-a', owner_id: 'alice' }
const node = (id, owner_id = 'alice', kind = 'ssh') => ({ id, owner_id, kind })
const job = (id, status, second, extra = {}) => ({ id, node_id: 'entry-a', upstream_id: 'exit-a', action: 'probe', status, created_at: time(second), ...extra })
const result = (id, second, extra = {}) => ({ id, node_id: 'entry-a', upstream_id: 'exit-a', status: 'ok', ipv4: '198.51.100.10', checked_at: time(second), ...extra })
const state = (jobs = [], probes = []) => ({ jobs, probes })


test('probe candidates enforce ownership and local-node administrator access', () => {
  const nodes = [node('entry-a'), node('entry-b', 'bob'), node('local-a', 'alice', 'local')]
  assert.deepEqual(probeNodes({ nodes, current_user: { id: 'alice', role: 'user' } }, upstream).map(item => item.id), ['entry-a'])
  assert.deepEqual(probeNodes({ nodes, current_user: { id: 'root', role: 'admin' } }, upstream).map(item => item.id), ['entry-a', 'local-a'])
  assert.deepEqual(probeNodes({ nodes, current_user: { id: 'bob', role: 'user' } }, upstream), [])
})

test('an untested pair does not invent availability from another exit', () => {
  assert.equal(probeState(state([], [result('other', 10, { upstream_id: 'exit-b' })]), {}, 'entry-a', 'exit-a').phase, 'unchecked')
})

test('a persisted queued task restores checking state after a browser reload', () => {
  assert.equal(probeState(state([job('new', 'queued', 20)]), {}, 'entry-a', 'exit-a').phase, 'checking')
})

test('a running task takes precedence over an older successful result', () => {
  const view = probeState(state([job('new', 'running', 20)], [result('old', 30, { job_id: 'old-job' })]), {}, 'entry-a', 'exit-a')
  assert.equal(view.phase, 'checking')
})

test('a failed queued retry replaces a success that finished after the retry was queued', () => {
  const view = probeState(state([job('retry', 'failed', 20, { finished_at: time(40), error: 'proxy authentication failed' })], [result('old', 30, { job_id: 'old-job' })]), {}, 'entry-a', 'exit-a')
  assert.equal(view.phase, 'failed')
  assert.equal(view.error, 'proxy authentication failed')
})

test('an old failed task cannot override a newer successful result', () => {
  const view = probeState(state([job('old', 'failed', 10, { finished_at: time(12), error: 'old failure' })], [result('new', 30, { job_id: 'new-job' })]), {}, 'entry-a', 'exit-a')
  assert.equal(view.phase, 'available')
})

test('only-IPv6 success is partially available', () => {
  const view = probeState(state([job('ipv6', 'succeeded', 10, { finished_at: time(20) })], [result('ipv6-result', 20, { job_id: 'ipv6', status: 'partial', ipv4: '', ipv6: '2001:db8::10', error: 'IPv4 unavailable' })]), {}, 'entry-a', 'exit-a')
  assert.equal(view.phase, 'partial')
})

test('success without an address is never reported available', () => {
  assert.equal(probeState(state([], [result('empty', 10, { ipv4: '', ipv6: '' })]), {}, 'entry-a', 'exit-a').phase, 'failed')
})

test('an interrupted task is a failed detection rather than stale success', () => {
  const view = probeState(state([job('interrupted', 'interrupted', 20, { finished_at: time(30) })], [result('old', 10)]), {}, 'entry-a', 'exit-a')
  assert.equal(view.phase, 'failed')
})

test('a result belonging to a different task cannot masquerade as the current result', () => {
  const view = probeState(state([job('new', 'succeeded', 20, { finished_at: time(40) })], [result('old', 30, { job_id: 'old-job' })]), {}, 'entry-a', 'exit-a')
  assert.equal(view.phase, 'missing')
})

test('legacy results remain readable without task associations', () => {
  assert.equal(probeState(state([], [result('legacy', 10)]), {}, 'entry-a', 'exit-a').phase, 'available')
})

test('registered legacy tasks use the latest server status', () => {
  const pending = { [probeKey('entry-a', 'exit-a')]: { job: job('legacy', 'queued', 10, { upstream_id: undefined }), started_at: time(10) } }
  const view = probeState(state([job('legacy', 'failed', 10, { upstream_id: undefined, finished_at: time(20), error: 'SSH connection failed' })]), pending, 'entry-a', 'exit-a')
  assert.equal(view.phase, 'failed')
  assert.equal(view.error, 'SSH connection failed')
})

test('latest source selection follows submission time rather than an older task completion', () => {
  const jobs = [job('old', 'succeeded', 10), job('new', 'queued', 20, { node_id: 'entry-b' })]
  const probes = [result('old-result', 30, { job_id: 'old' })]
  assert.equal(latestProbeNode(state(jobs, probes), {}, 'exit-a', [node('entry-a'), node('entry-b')]), 'entry-b')
})

test('removed or differently owned sources are not restored as the selected entry', () => {
  const data = state([job('old', 'succeeded', 10, { node_id: 'removed' })], [result('old-result', 20, { node_id: 'removed' })])
  assert.equal(latestProbeNode(data, {}, 'exit-a', [node('entry-a')]), '')
})
