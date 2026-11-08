import type { Node, Relay } from './types'

export function newRelayDraft(ownerID: string, nodeID = '', upstreamID = ''): Relay {
  return {
    id: '', owner_id: ownerID, name: '', node_id: nodeID, upstream_id: upstreamID, enabled: true,
    protocol: 'vless', listen: '0.0.0.0', public_host: '', port: 443, network: 'tcp', security: 'reality',
    uuid: '', password: '', cipher: 'chacha20-ietf-poly1305', flow: 'xtls-rprx-vision',
    server_name: 'www.microsoft.com', target: 'www.microsoft.com:443', reality_private_key: '', reality_public_key: '', short_id: '', path: '', certificate: '', certificate_key: '', created_at: '', updated_at: '',
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
