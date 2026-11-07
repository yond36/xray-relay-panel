import { Activity, ArrowRight, Check, ChevronRight, GitBranch, Layers3, Network, Plus, Server, Settings2 } from 'lucide-react'
import { useApp } from '../context'
import { isFailure, isRunning, sortedJobs } from '../utils'
import { Badge, Button, Card, Empty, JobsTable, OwnerLabel, PageHeader, StatusBadge } from '../components/ui'

export default function DashboardPage() {
  const { state, navigate, isAdmin, user } = useApp()
  const ownNodes = state.nodes.filter(node => node.owner_id === user.id)
  const ownUpstreams = state.upstreams.filter(upstream => upstream.owner_id === user.id)
  const ownRelays = state.relays.filter(relay => relay.owner_id === user.id)
  const enabled = state.relays.filter(relay => relay.enabled).length
  const running = state.jobs.filter(isRunning).length
  const failed = state.jobs.filter(job => isFailure(job.status)).length
  const stats = [
    { label: '管理节点', value: state.nodes.length, detail: `${state.nodes.filter(node => node.kind === 'ssh').length} 个 SSH · ${state.nodes.filter(node => node.kind === 'local').length} 个本机`, icon: Server, color: 'teal' },
    { label: '上游资源', value: state.upstreams.length, detail: `${state.subscriptions.length} 个订阅源`, icon: GitBranch, color: 'blue' },
    { label: '转发入口', value: state.relays.length, detail: `${enabled} 个已启用 · ${state.relays.length - enabled} 个已停用`, icon: Network, color: 'violet' },
    { label: '执行任务', value: state.jobs.length, detail: `${running} 个进行中 · ${failed} 个失败记录`, icon: Activity, color: 'amber' },
  ]
  const steps = [
    { label: '添加我的管理节点', text: isAdmin ? '接入本机或远程 SSH 主机' : '接入你的远程 SSH 主机', done: ownNodes.length > 0, page: 'nodes' as const },
    { label: '导入我的上游资源', text: '支持多行链接和订阅地址', done: ownUpstreams.length > 0, page: 'upstreams' as const },
    { label: '创建我的转发入口', text: '关联同用户节点与上游，应用配置', done: ownRelays.length > 0, page: 'relays' as const },
  ]
  return <><PageHeader eyebrow="WORKSPACE OVERVIEW" title="工作空间概览" description={isAdmin ? '汇总全部用户的节点、上游与转发配置，统一管理转发网络。' : '连接你的节点、编排上游，掌握自己的转发网络。'} actions={<><Button onClick={() => navigate('upstreams')}><Plus size={16} />导入上游</Button><Button variant="primary" onClick={() => navigate('relays')}><Plus size={16} />创建转发</Button></>} /><div className="stats-grid">{stats.map(stat => <div className="stat-card" key={stat.label}><div className="stat-top"><span>{stat.label}</span><span className={`stat-icon stat-${stat.color}`}><stat.icon size={19} /></span></div><strong>{stat.value}<small>个</small></strong><p>{stat.detail}</p></div>)}</div>{steps.some(step => !step.done) && <Card className="getting-started"><div className="getting-started-intro"><span className="section-symbol"><Layers3 size={22} /></span><div><h2>搭建你的第一条转发线路</h2><p>完成以下步骤，开启统一管理。</p></div><Badge tone="info">{steps.filter(step => step.done).length} / 3 已完成</Badge></div><div className="steps-grid">{steps.map((step, index) => <button key={step.label} className={`setup-step ${step.done ? 'setup-complete' : ''}`} onClick={() => navigate(step.page)}><span className="step-number">{step.done ? <Check size={17} /> : `0${index + 1}`}</span><div><strong>{step.label}</strong><p>{step.text}</p></div><ChevronRight size={17} /></button>)}</div></Card>}<div className="dashboard-grid"><Card title="节点概况" description="各节点最近记录的部署与服务状态" action={<Button size="sm" variant="ghost" onClick={() => navigate('nodes')}>管理节点<ArrowRight size={14} /></Button>}>{state.nodes.length === 0 ? <Empty compact icon={Server} title="还没有管理节点" description="添加一台主机，作为转发入口的运行节点。" action={<Button size="sm" onClick={() => navigate('nodes')}><Plus size={14} />添加节点</Button>} /> : <div className="node-overview-list">{state.nodes.slice(0, 5).map(node => <div className="node-overview" key={node.id}><span className="node-icon"><Server size={19} /></span><div className="node-overview-name"><strong>{node.name}</strong><span>{node.kind === 'local' ? '本机节点' : node.host} · {state.relays.filter(relay => relay.node_id === node.id).length} 个入口</span><OwnerLabel ownerID={node.owner_id} /></div><StatusBadge status={node.status} /></div>)}</div>}</Card><Card title="配置与出口" description="保存与部署分开，探测结果按实际返回展示"><div className="overview-notes"><div><span className="note-icon"><Network size={19} /></span><div><strong>配置应用状态</strong><p>{state.nodes.filter(node => node.applied_revision).length} 个节点记录了已应用版本。修改入口或上游后，请重新应用节点配置。</p></div></div><div><span className="note-icon"><Activity size={19} /></span><div><strong>出口探测记录</strong><p>已记录 {state.probes.length} 次探测结果。出口 IP 由管理节点通过对应上游异步查询，不代表入口公网可达。</p></div></div><button className="overview-settings" onClick={() => navigate('settings')}><Settings2 size={16} /><span>{isAdmin ? '管理系统设置与个人订阅' : '管理我的账户与订阅'}</span><ArrowRight size={15} /></button></div></Card></div><Card title="最近任务" description="部署、服务操作与出口探测的实际执行记录" action={<Button size="sm" variant="ghost" onClick={() => navigate('jobs')}>全部任务<ArrowRight size={14} /></Button>}>{state.jobs.length ? <JobsTable jobs={sortedJobs(state.jobs).slice(0, 6)} compact /> : <Empty compact icon={Activity} title="暂无执行记录" description="部署节点或发起出口探测后，任务进度会出现在这里。" />}</Card></>
}
