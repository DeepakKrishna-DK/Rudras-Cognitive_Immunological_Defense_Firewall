'use client'
import Head from 'next/head'
import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { format } from 'date-fns'
import { Shield, AlertTriangle, Filter, Search, Download } from 'lucide-react'
import { INITIAL_EVENTS } from '@/services/mockData'
import { rudraSocket } from '@/services/websocket'
import type { AttackEvent, ThreatLevel } from '@/types'

const SEV_BADGE: Record<ThreatLevel, string> = {
  critical: 'badge badge-danger',
  high:     'bg-orange-500/20 text-orange-400 border border-orange-500/30',
  medium:   'badge badge-warn',
  low:      'badge badge-info',
  info:     'badge',
}

export default function AlertsPage() {
  const [events, setEvents]       = useState<AttackEvent[]>([...INITIAL_EVENTS].reverse())
  const [search, setSearch]       = useState('')
  const [sevFilter, setSev]       = useState<ThreatLevel | 'all'>('all')
  const [statusFilter, setStatus] = useState<string>('all')
  const [selected, setSelected]   = useState<AttackEvent | null>(null)

  useEffect(() => {
    rudraSocket.connect()
    rudraSocket.onEvent(ev => setEvents(prev => [ev, ...prev].slice(0, 500)))
    return () => rudraSocket.disconnect()
  }, [])

  const filtered = events.filter(e => {
    if (sevFilter !== 'all' && e.severity !== sevFilter) return false
    if (statusFilter !== 'all' && e.status?.toLowerCase() !== statusFilter) return false
    if (search && !JSON.stringify(e).toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  return (
    <>
      <Head><title>Alerts — Rudras SOC</title></Head>
      <div className="flex flex-col h-full gap-3">
        {/* Header */}
        <div className="flex items-center gap-3 shrink-0">
          <AlertTriangle size={18} className="text-danger" />
          <h1 className="text-lg font-bold text-text">Security Alerts</h1>
          <span className="badge badge-danger ml-1">{filtered.length}</span>
          <div className="ml-auto flex items-center gap-2">
            <div className="relative">
              <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
              <input
                value={search} onChange={e => setSearch(e.target.value)}
                placeholder="Search alerts..."
                className="bg-panel border border-border rounded-lg pl-7 pr-3 py-1.5 text-xs text-text focus:outline-none focus:border-accent w-48"
              />
            </div>
            <select value={sevFilter} onChange={e => setSev(e.target.value as ThreatLevel|'all')}
              className="bg-panel border border-border rounded-lg px-2 py-1.5 text-xs text-text focus:outline-none">
              <option value="all">All Severity</option>
              {(['critical','high','medium','low','info'] as ThreatLevel[]).map(s =>
                <option key={s} value={s}>{s}</option>)}
            </select>
            <select value={statusFilter} onChange={e => setStatus(e.target.value)}
              className="bg-panel border border-border rounded-lg px-2 py-1.5 text-xs text-text focus:outline-none">
              <option value="all">All Status</option>
              <option value="blocked">Blocked</option>
              <option value="detected">Detected</option>
              <option value="mitigated">Mitigated</option>
            </select>
            <button className="flex items-center gap-1.5 text-xs border border-border px-3 py-1.5 rounded-lg text-muted hover:border-accent hover:text-accent">
              <Download size={12} /> Export
            </button>
          </div>
        </div>

        {/* Table */}
        <div className="flex-1 soc-panel rounded-xl border border-border overflow-hidden flex flex-col min-h-0">
          <div className="overflow-x-auto overflow-y-auto flex-1">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-panel border-b border-border">
                <tr>
                  {['Time','Type','Severity','Source IP','Destination','Port','Status','MITRE','Confidence'].map(h => (
                    <th key={h} className="px-3 py-2.5 text-left text-[10px] text-muted uppercase tracking-wider font-medium whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                <AnimatePresence>
                  {filtered.map(ev => (
                    <motion.tr
                      key={ev.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      onClick={() => setSelected(ev)}
                      className={`border-b border-border/50 cursor-pointer transition-colors hover:bg-white/[0.03] ${selected?.id === ev.id ? 'bg-accent/5' : ''}`}
                    >
                      <td className="px-3 py-2 font-mono text-muted whitespace-nowrap">
                        {format(new Date(ev.timestamp), 'HH:mm:ss')}
                      </td>
                      <td className="px-3 py-2 font-semibold text-text whitespace-nowrap">{ev.attackType}</td>
                      <td className="px-3 py-2">
                        <span className={`${SEV_BADGE[ev.severity]} text-[9px]`}>{ev.severity}</span>
                      </td>
                      <td className="px-3 py-2 font-mono text-danger">{ev.srcIp}</td>
                      <td className="px-3 py-2 font-mono text-safe whitespace-nowrap">{ev.dstIp}</td>
                      <td className="px-3 py-2 font-mono text-muted">{ev.port || '—'}</td>
                      <td className="px-3 py-2">
                        <span className={`badge text-[9px] ${ev.status==='BLOCKED' ? 'badge-danger' : ev.status==='MITIGATED' ? 'badge-warn' : 'badge-info'}`}>
                          {ev.status || 'DETECTED'}
                        </span>
                      </td>
                      <td className="px-3 py-2 font-mono text-accent text-[10px]">{ev.mitre || '—'}</td>
                      <td className="px-3 py-2 font-mono text-muted">
                        {ev.mlConfidence !== undefined ? `${(ev.mlConfidence*100).toFixed(0)}%` : '—'}
                      </td>
                    </motion.tr>
                  ))}
                </AnimatePresence>
              </tbody>
            </table>
          </div>
        </div>

        {/* Detail panel */}
        <AnimatePresence>
          {selected && (
            <motion.div
              initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="soc-panel rounded-xl border border-accent/30 p-4 shrink-0 overflow-hidden"
            >
              <div className="flex items-center gap-2 mb-3">
                <Shield size={14} className="text-accent" />
                <span className="text-xs font-semibold text-accent">Event Detail — {selected.id}</span>
                <button onClick={() => setSelected(null)} className="ml-auto text-muted hover:text-text text-xs">✕ Close</button>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {[
                  ['Attack Type', selected.attackType],
                  ['Source', `${selected.srcIp} (${selected.srcCountry})`],
                  ['Destination', selected.dstIp],
                  ['Protocol', selected.protocol || 'TCP'],
                  ['MITRE', selected.mitre || 'N/A'],
                  ['ML Confidence', selected.mlConfidence !== undefined ? `${(selected.mlConfidence*100).toFixed(1)}%` : 'N/A'],
                  ['Rule ID', selected.ruleId || 'N/A'],
                  ['Payload', selected.payload || '—'],
                ].map(([k, v]) => (
                  <div key={k}>
                    <p className="text-[9px] text-muted uppercase tracking-wider">{k}</p>
                    <p className="text-xs font-mono text-text-dim truncate">{v}</p>
                  </div>
                ))}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </>
  )
}
