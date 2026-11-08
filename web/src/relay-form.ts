import type { Node, Relay } from './types'

type SavedRelayPort = Pick<Relay, 'node_id' | 'port'>

function randomPortWord() {
  // getRandomValues is also available to panels served over plain HTTP.
  return globalThis.crypto.getRandomValues(new Uint32Array(1))[0]
}

export function randomRelayPort(nodeID: string, savedRelays: readonly SavedRelayPort[] = [], currentPort?: number, random = randomPortWord): number {
  const used = new Set(savedRelays.filter(relay => relay.node_id === nodeID).map(relay => relay.port))
  if (currentPort !== undefined) used.add(currentPort)
  const available: number[] = []
  for (let port = 10000; port <= 65535; port++) {
    if (!used.has(port)) available.push(port)
  }
  if (!available.length) throw new Error('当前入口节点没有可用的五位数端口，请手动输入其他端口。')
  // Reject the short final interval so every available port is equally likely.
  const limit = Math.floor(0x100000000 / available.length) * available.length
  let word: number
  do { word = random() } while (word >= limit)
  return available[word % available.length]
}

export function changeRelayNode(draft: Relay, nodeID: string, automaticPort: boolean, savedRelays: readonly SavedRelayPort[], random = randomPortWord): Relay {
  if (draft.node_id === nodeID) return draft
  return { ...draft, node_id: nodeID, port: automaticPort && !draft.id ? randomRelayPort(nodeID, savedRelays, draft.port, random) : draft.port }
}

export function newRelayDraft(ownerID: string, nodeID = '', upstreamID = '', savedRelays: readonly SavedRelayPort[] = [], random = randomPortWord): Relay {
  return {
    id: '', owner_id: ownerID, name: '', node_id: nodeID, upstream_id: upstreamID, enabled: true,
    protocol: 'vless', listen: '0.0.0.0', public_host: '', port: randomRelayPort(nodeID, savedRelays, undefined, random), network: 'tcp', security: 'reality',
    uuid: '', password: '', cipher: 'chacha20-ietf-poly1305', flow: 'xtls-rprx-vision',
    server_name: 'www.cloudflare.com', target: 'www.cloudflare.com:443', reality_private_key: '', reality_public_key: '', short_id: '', path: '', certificate: '', certificate_key: '', created_at: '', updated_at: '',
  }
}

export function relayRequest(draft: Relay, node: Pick<Node, 'public_host' | 'kind' | 'host'>, ownerID: string) {
  // Record timestamps belong to the server, not the editable form payload.
  const { created_at, updated_at, ...values } = draft
  const supportsTLS = ['vless', 'vmess', 'trojan'].includes(draft.protocol)
  const needsUUID = ['vless', 'vmess'].includes(draft.protocol)
  const needsPassword = ['trojan', 'shadowsocks', 'socks', 'http'].includes(draft.protocol)
  const security = supportsTLS ? draft.security : 'none'
  const network = supportsTLS ? draft.network : 'tcp'
  return {
    ...values, owner_id: ownerID, name: draft.name.trim(),
    public_host: draft.public_host.trim() || node.public_host || (node.kind === 'ssh' ? node.host : ''),
    flow: draft.protocol === 'vless' && network === 'tcp' && security !== 'none' ? draft.flow : '',
    security, network,
    cipher: draft.protocol === 'shadowsocks' ? draft.cipher : '',
    password: needsPassword ? draft.password : '',
    uuid: needsUUID || ['socks', 'http'].includes(draft.protocol) ? draft.uuid : '',
    path: network === 'tcp' ? '' : draft.path,
    target: security === 'reality' ? draft.target : '',
    reality_private_key: security === 'reality' ? draft.reality_private_key : '',
    reality_public_key: security === 'reality' ? draft.reality_public_key : '',
    short_id: security === 'reality' ? draft.short_id : '',
    certificate: security === 'tls' ? draft.certificate : '',
    certificate_key: security === 'tls' ? draft.certificate_key : '',
  }
}
