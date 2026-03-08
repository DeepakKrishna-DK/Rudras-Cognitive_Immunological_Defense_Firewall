'use client'
import Head from 'next/head'
import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Target, Search, Plus, ChevronDown, ChevronRight, CheckCircle, Clock, AlertTriangle } from 'lucide-react'
import { INITIAL_EVENTS } from '@/services/mockData'

const HYPOTHESES = [
  {
    id: 'H1',
    title: 'Lateral Movement via SMB — APT29',
    technique: 'T1021.002',
    status: 'active',
    confidence: 87,
    evidence: ['Multiple SMB sessions from client2 to db1', 'Pass-the-hash likely', 'Admin shares accessed 14:03 UTC'],
    iocs: ['192.168.1.52', '10.0.0.22', 'hash:fc3c7d5aa2f8e7a36'],
  },
  {
    id: 'H2',
    title: 'DNS Tunneling for C2 Exfiltration',
    technique: 'T1071.004',
    status: 'confirmed',
    confidence: 94,
    evidence: ['High-entropy subdomain queries detected', 'Query rate 120/min — anomalous', 'Destination: evildomain.ru'],
    iocs: ['evildomain.ru', '185.234.218.44'],
  },
  {
    id: 'H3',
    title: 'Credential Stuffing Campaign',
    technique: 'T1110.004',
    status: 'investigating',
    confidence: 72,
    evidence: ['3200 failed auth in 10 min', 'Source: 47 different IPs', 'Targeting /api/login endpoint'],
    iocs: ['47.0.0.0/8 range', 'User-Agent: python-requests'],
  },
]

const STATUS_BADGE: Record<string, string> = {
  active:       'badge badge-danger',
  confirmed:    'badge badge-safe',
  investigating:'badge badge-warn',
  closed:       'badge',
}

export default function HuntPage() {
  const [expanded, setExpanded] = useState<string | null>('H1')
  const [pivotIp, setPivotIp]   = useState('')

  const pivotEvents = pivotIp
    ? INITIAL_EVENTS.filter(e => e.srcIp === pivotIp || e.dstIp === pivotIp)
    : []

  return (
    <>
      <Head><title>Threat Hunt — Rudras SOC</title></Head>
      <div className="flex flex-col gap-4 h-full overflow-y-auto">
        <div className="flex items-center gap-2 shrink-0">
          <Target size={18} className="text-danger" />
          <h1 className="text-lg font-bold text-text">Threat Hunt</h1>
          <button className="ml-auto flex items-center gap-1.5 text-xs bg-danger/15 text-danger border border-danger/30 hover:bg-danger/25 px-3 py-1.5 rounded-lg transition-colors">
            <Plus size={12} /> New Hypothesis
          </button>
        </div>

        {/* Hypotheses */}
        <div className="space-y-3">
          {HYPOTHESES.map((h, i) => (
            <motion.div
              key={h.id}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.08 }}
              className="soc-panel border border-border rounded-xl overflow-hidden"
            >
              <button
                onClick={() => setExpanded(expanded === h.id ? null : h.id)}
                className="w-full flex items-center gap-3 px-4 py-3.5 hover:bg-white/[0.02] transition-colors"
              >
                <span className="font-mono text-[10px] text-muted border border-border px-1.5 py-0.5 rounded">{h.id}</span>
                <span className="text-sm font-semibold text-text text-left flex-1">{h.title}</span>
                <span className="font-mono text-[10px] text-accent">{h.technique}</span>
                <span className={`${STATUS_BADGE[h.status]} text-[9px]`}>{h.status}</span>
                <span className={`font-mono text-sm font-bold ml-2 ${h.confidence>=90?'text-danger':h.confidence>=70?'text-warn':'text-safe'}`}>
                  {h.confidence}%
                </span>
                {expanded === h.id ? <ChevronDown size={14} className="text-muted" /> : <ChevronRight size={14} className="text-muted" />}
              </button>

              <AnimatePresence>
                {expanded === h.id && (
                  <motion.div
                    initial={{ height: 0 }} animate={{ height: 'auto' }} exit={{ height: 0 }}
                    className="overflow-hidden border-t border-border"
                  >
                    <div className="px-4 py-3 grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <p className="text-[10px] font-semibold text-muted uppercase tracking-wider mb-2">Evidence</p>
                        <ul className="space-y-1.5">
                          {h.evidence.map((e, ei) => (
                            <li key={ei} className="flex items-start gap-2 text-[11px] text-text-dim">
                              <CheckCircle size={11} className="text-safe mt-0.5 shrink-0" /> {e}
                            </li>
                          ))}
                        </ul>
                      </div>
                      <div>
                        <p className="text-[10px] font-semibold text-muted uppercase tracking-wider mb-2">IOCs</p>
                        <div className="flex flex-wrap gap-1.5">
                          {h.iocs.map(ioc => (
                            <button
                              key={ioc}
                              onClick={() => setPivotIp(ioc)}
                              className="badge badge-danger text-[9px] hover:bg-danger/30 cursor-pointer"
                            >
                              {ioc}
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          ))}
        </div>

        {/* IOC Pivot */}
        <div className="soc-panel border border-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <Search size={13} className="text-accent" />
            <span className="text-xs font-semibold text-text">IOC Pivot</span>
          </div>
          <div className="flex gap-2 mb-3">
            <input
              value={pivotIp} onChange={e => setPivotIp(e.target.value)}
              placeholder="Enter IP / domain / hash to pivot..."
              className="flex-1 bg-bg border border-border rounded-lg px-3 py-2 text-xs font-mono text-text focus:outline-none focus:border-accent"
            />
            <button onClick={() => setPivotIp('')} className="text-xs border border-border px-3 py-2 rounded-lg text-muted hover:border-accent hover:text-accent">Clear</button>
          </div>
          {pivotIp && (
            <div>
              <p className="text-[10px] text-muted mb-2">
                Found <span className="text-accent font-mono">{pivotEvents.length}</span> events matching <span className="font-mono text-danger">{pivotIp}</span>
              </p>
              <div className="space-y-1 max-h-40 overflow-y-auto">
                {pivotEvents.map(ev => (
                  <div key={ev.id} className="flex items-center gap-3 text-[10px] font-mono bg-bg rounded px-2 py-1.5 border border-border/50">
                    <span className="text-muted">{ev.timestamp.slice(11,19)}</span>
                    <span className="text-text">{ev.attackType}</span>
                    <span className="text-danger">{ev.srcIp}</span>
                    <span className="text-border">→</span>
                    <span className="text-safe">{ev.dstIp}</span>
                  </div>
                ))}
                {pivotEvents.length === 0 && (
                  <p className="text-xs text-muted">No events found for this indicator</p>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  )
}
