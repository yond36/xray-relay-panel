import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { changeRelayNode, newRelayDraft, randomRelayPort, relayRequest } from '../relay-form.ts'

const owner = 'fixture-admin'
const node = { kind: 'ssh', public_host: 'relay.example.test', host: 'entry.example.test' }
const fixedPort = 24443
const fixedRandom = () => fixedPort - 10000
const newDraft = () => ({ ...newRelayDraft(owner, 'entry-default', 'exit-default', [], fixedRandom), name: ' Default relay ' })
const serialized = draft => JSON.parse(JSON.stringify(relayRequest(draft, node, owner)))

test('automatic ports include both five-digit boundaries', () => {
  assert.equal(newRelayDraft(owner, 'entry-default', 'exit-default', [], () => 0).port, 10000)
  assert.equal(newRelayDraft(owner, 'entry-default', 'exit-default', [], () => 55535).port, 65535)
})

test('the browser default draws from getRandomValues once', t => {
  const random = t.mock.method(globalThis.crypto, 'getRandomValues', values => {
    assert.ok(values instanceof Uint32Array)
    values[0] = fixedRandom()
    return values
  })
  const draft = newRelayDraft(owner, 'entry-default', 'exit-default')
  assert.equal(draft.port, fixedPort)
  assert.equal(random.mock.callCount(), 1)
})

test('random ports skip every saved entry port and the current value, including disabled relays', () => {
  const saved = [
    { node_id: 'entry-default', port: 10000, enabled: true },
    { node_id: 'entry-default', port: 10001, enabled: false },
    { node_id: 'entry-default', port: 10001, enabled: false },
    { node_id: 'another-entry', port: 10003, enabled: true },
  ]
  assert.equal(newRelayDraft(owner, 'entry-default', 'exit-default', saved, () => 0).port, 10002)
  assert.equal(randomRelayPort('entry-default', saved, 10002, () => 0), 10003)
  assert.equal(randomRelayPort('entry-default', [{ node_id: 'entry-default', port: 65535 }], undefined, () => 55534), 65534)
  assert.equal(randomRelayPort('entry-default', [], 65535, () => 0), 10000)
})

test('random sampling rejects the incomplete final interval', () => {
  const words = [0xffffffff, fixedRandom()]
  assert.equal(randomRelayPort('entry-default', [], undefined, () => {
    assert.ok(words.length, 'random sampling must stop after the accepted word')
    return words.shift()
  }), fixedPort)
  assert.equal(words.length, 0)
})

test('nearly full and exhausted entries terminate without retrying occupied ports', () => {
  const saved = Array.from({ length: 55535 }, (_, index) => ({ node_id: 'entry-default', port: 10000 + index }))
  assert.equal(randomRelayPort('entry-default', saved, undefined, () => 0), 65535)
  assert.throws(() => randomRelayPort('entry-default', saved, 65535, () => assert.fail('no random draw when no ports remain')), /没有可用的五位数端口/)
})

test('switching an automatic new draft selects for the new entry without reusing its current port', () => {
  const draft = newDraft()
  const saved = [
    { node_id: 'next-entry', port: 10000, enabled: false },
    { node_id: 'entry-default', port: 10001, enabled: true },
  ]
  let draws = 0
  const switched = changeRelayNode(draft, 'next-entry', true, saved, () => { draws++; return 0 })
  assert.equal(switched.node_id, 'next-entry')
  assert.equal(switched.port, 10001)
  assert.equal(draws, 1)
  assert.equal(draft.node_id, 'entry-default')
  assert.equal(draft.port, fixedPort)
  assert.equal(changeRelayNode(switched, 'next-entry', true, saved, () => assert.fail('same entry must not redraw')), switched)
  const again = changeRelayNode(switched, 'entry-default', true, saved, () => 0)
  assert.equal(again.port, 10000)
  assert.equal(changeRelayNode({ ...draft, port: 10000 }, 'next-entry', true, [], () => 0).port, 10001)
})

test('switching entries preserves manual ports and every existing relay port', () => {
  for (const port of [1, 443, fixedPort, 65535]) {
    const saved = [{ node_id: 'next-entry', port }]
    const noRandom = () => assert.fail('manual and saved ports must not be randomized')
    const manual = changeRelayNode({ ...newDraft(), port }, 'next-entry', false, saved, noRandom)
    assert.equal(manual.node_id, 'next-entry')
    assert.equal(manual.port, port)
    assert.equal(serialized(manual).port, port)
    for (const automaticPort of [false, true]) {
      const edited = changeRelayNode({ ...newDraft(), id: 'existing-relay', port }, 'next-entry', automaticPort, saved, noRandom)
      assert.equal(edited.port, port)
      assert.equal(edited.id, 'existing-relay')
    }
  }
})

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
    assert.equal(body.port, fixedPort)
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
