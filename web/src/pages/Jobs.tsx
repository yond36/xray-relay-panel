import { useState } from 'react'
import { Activity, Download, Search } from 'lucide-react'
import { useApp } from '../context'
import { isFailure, isRunning, isSuccess, ownerName } from '../utils'
import { Badge, Button, Card, Empty, JobsTable, PageHeader, SubscriptionExport } from '../components/ui'

export default function JobsPage() {
  const { state, isAdmin } = useApp()
  const [filter, setFilter] = useState('all')
  const [nodeID, setNodeID] = useState('')
  const [search, setSearch] = useState('')
  const [exportOpen, setExportOpen] = useState(false)
  const jobs = state.jobs.filter(job => (!nodeID || job.node_id === nodeID) && (filter === 'all' || filter === 'running' && isRunning(job) || filter === 'success' && isSuccess(job.status) && !isRunning(job) || filter === 'failed' && isFailure(job.status)) && `${job.id} ${job.action} ${job.message} ${job.error || ''} ${isAdmin ? ownerName(state, job.owner_id) : ''}`.toLowerCase().includes(search.toLowerCase()))
  return <><PageHeader eyebrow="ACTIVITY LOG" title="任务记录" description="查看异步执行进度、错误信息与配置版本。运行中的任务会自动更新。" actions={<Button onClick={() => setExportOpen(true)}><Download size={16} />导出转发订阅</Button>} /><div className="summary-strip"><span><i className="summary-dot dot-info" /><strong>{state.jobs.filter(isRunning).length}</strong>进行中</span><span><i className="summary-dot dot-success" /><strong>{state.jobs.filter(job => isSuccess(job.status) && !isRunning(job)).length}</strong>已完成</span><span><i className="summary-dot dot-danger" /><strong>{state.jobs.filter(job => isFailure(job.status)).length}</strong>失败记录</span><span className="summary-hint">保存配置不会自动触发部署</span></div><Card><div className="table-toolbar"><div className="tabs" aria-label="任务状态筛选">{[{ value: 'all', label: '全部任务' }, { value: 'running', label: '进行中' }, { value: 'success', label: '已完成' }, { value: 'failed', label: '失败' }].map(tab => <button key={tab.value} className={filter === tab.value ? 'tab-active' : ''} onClick={() => setFilter(tab.value)}>{tab.label}{tab.value === 'all' && <Badge>{state.jobs.length}</Badge>}</button>)}</div><div className="toolbar-filters"><select aria-label="按节点筛选" value={nodeID} onChange={event => setNodeID(event.target.value)}><option value="">全部节点</option>{state.nodes.map(node => <option key={node.id} value={node.id}>{node.name}{isAdmin ? ` · ${ownerName(state, node.owner_id)}` : ''}</option>)}</select><div className="search-field"><Search size={16} /><input aria-label="搜索任务" placeholder="搜索任务或执行信息" value={search} onChange={event => setSearch(event.target.value)} /></div></div></div>{jobs.length ? <JobsTable jobs={jobs} /> : <Empty icon={Activity} title={state.jobs.length ? '没有匹配的任务' : '还没有执行任务'} description={state.jobs.length ? '调整筛选条件，查看其他任务记录。' : '从节点页面部署配置，或在转发页面探测出口。执行结果会保留在这里。'} />}</Card>{exportOpen && <SubscriptionExport onClose={() => setExportOpen(false)} />}</>
}
