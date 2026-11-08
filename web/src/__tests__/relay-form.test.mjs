import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { newRelayDraft, relayRequest } from '../relay-form.ts'

const owner = 'fixture-admin'
const node = { kind: 'ssh', public_host: 'relay.example.test', host: 'entry.example.test' }
const newDraft = () => ({ ...newRelayDraft(owner, 'entry-default', 'exit-default'), name: ' Default relay ' })
const serialized = draft => JSON.parse(JSON.stringify(relayRequest(draft, node, owner)))


test('the actual default form serializes to the shared API contract', async () => {
  const contract = JSON.parse(await readFile(new URL('../../../tests/fixtures/default-relay-request.json', import.meta.url), 'utf8'))
  const draft = newDraft()
  assert.equal(draft.created_at, '')
  assert.equal(draft.updated_at, '')
  assert.deepEqual(serialized(draft), contract)
  assert.equal(draft.name, ' Default relay ')
  assert.equal(draft.public_host, '')
})

test('create and edit requests omit server timestamps, including malformed and saved values', () => {
  for (const [created_at, updated_at] of [['', ''], ['', '2026-11-08T00:00:00Z'], ['2026-11-08T00:00:00Z', ''], ['invalid-time', 'invalid-time'], ['2026-11-08T00:00:00Z', '2026-11-08T01:00:00Z']]) {
    const body = serialized({ ...newDraft(), created_at, updated_at })
    assert.equal(Object.hasOwn(body, 'created_at'), false)
    assert.equal(Object.hasOwn(body, 'updated_at'), false)
    assert.equal(body.port, 443)
    assert.equal(body.enabled, true)
  }
})

test('editing retains identity, owner, disabled state and connection credentials', () => {
  const body = serialized({ ...newDraft(), id: 'existing-relay', enabled: false, uuid: 'existing-client-id', reality_private_key: 'demo', reality_public_key: 'demo', short_id: 'ab' })
  assert.equal(body.id, 'existing-relay')
  assert.equal(body.owner_id, owner)
  assert.equal(body.enabled, false)
  assert.equal(body.uuid, 'existing-client-id')
  assert.equal(body.reality_private_key, 'demo')
  assert.equal(body.reality_public_key, 'demo')
  assert.equal(body.short_id, 'ab')
})

test('explicit public host overrides entry-node fallback without changing the form', () => {
  const draft = { ...newDraft(), public_host: ' relay-override.example.test ' }
  assert.equal(serialized(draft).public_host, 'relay-override.example.test')
  assert.equal(draft.public_host, ' relay-override.example.test ')
  assert.equal(relayRequest(newDraft(), { kind: 'ssh', public_host: '', host: 'entry.example.test' }, owner).public_host, 'entry.example.test')
  assert.equal(relayRequest(newDraft(), { kind: 'local', public_host: '', host: '127.0.0.1' }, owner).public_host, '')
})

test('non-TLS protocols do not submit stale TLS or REALITY fields', () => {
  for (const protocol of ['socks', 'http', 'shadowsocks']) {
    const body = serialized({ ...newDraft(), protocol, network: 'ws', security: 'tls', path: '/old', uuid: 'demo-user', password: 'demo', reality_private_key: 'demo', reality_public_key: 'demo', short_id: 'ab', certificate: 'demo', certificate_key: 'demo' })
    assert.equal(body.network, 'tcp')
    assert.equal(body.security, 'none')
    assert.equal(body.flow, '')
    assert.equal(body.path, '')
    assert.equal(body.target, '')
    assert.equal(body.reality_private_key, '')
    assert.equal(body.reality_public_key, '')
    assert.equal(body.certificate, '')
    assert.equal(body.certificate_key, '')
    assert.equal(body.password, 'demo')
    assert.equal(body.uuid, protocol === 'shadowsocks' ? '' : 'demo-user')
  }
})

test('TLS and WebSocket settings remain editable while REALITY fields are cleared', () => {
  const body = serialized({ ...newDraft(), network: 'ws', security: 'tls', path: '/relay', certificate: 'demo-cert', certificate_key: 'demo-key', reality_private_key: 'old', short_id: 'ab' })
  assert.equal(body.network, 'ws')
  assert.equal(body.security, 'tls')
  assert.equal(body.path, '/relay')
  assert.equal(body.flow, '')
  assert.equal(body.target, '')
  assert.equal(body.reality_private_key, '')
  assert.equal(body.short_id, '')
  assert.equal(body.certificate, 'demo-cert')
  assert.equal(body.certificate_key, 'demo-key')
})
