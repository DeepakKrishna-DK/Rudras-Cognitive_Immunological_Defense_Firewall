'use client'
import Head from 'next/head'
import { useState } from 'react'
import { motion } from 'framer-motion'
import { Search, AlertTriangle } from 'lucide-react'
import { FORENSIC_PACKETS } from '@/services/mockData'
import type { ForensicPacket } from '@/types'

export default function ForensicsPage() {
  const [selected, setSelected] = useState<ForensicPacket | null>(null)
  const [search, setSearch]     = useState('')

  const filtered = FORENSIC_PACKETS.filter(p =>
    !search || JSON.stringify(p).toLowerCase().includes(search.toLowerCase())
  )

  return (
    <>
      <Head><title>Forensics — Rudras SOC</title></Head>
      <div className="flex flex-col gap-3 h-full">
        <div className="flex items-center gap-2 shrink-0">
          <Search size={18} className="text-accent" />
          <h1 className="text-lg font-bold text-text">Forensic Packet Inspector</h1>
          <div className="ml-auto relative">
            <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search packets..."
              className="bg-panel border border-border rounded-lg pl-8 pr-3 py-1.5 text-xs text-text focus:outline-none focus:border-accent w-44" />
          </div>
        </div>

        <div className="flex flex-1 gap-3 min-h-0">
          {/* Packet list */}
          <div className="w-1/2 soc-panel border border-border rounded-xl overflow-hidden flex flex-col min-h-0">
            <div className="border-b border-border px-3 py-2.5 shrink-0">
              <span className="text-[10px] font-semibold text-muted uppercase tracking-wider">Captured Packets — {filtered.length}</span>
            </div>
            <div className="overflow-y-auto flex-1">
              <table className="w-full text-xs">
                <thead className="bg-panel sticky top-0 border-b border-border">
                  <tr>
                    {['#','Time','Src → Dst','Proto','Flags'].map(h => (
                      <th key={h} className="px-2 py-2 text-left text-[9px] text-muted uppercase">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((p, i) => (
                    <motion.tr
                      key={p.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: Math.min(i * 0.02, 0.3) }}
                      onClick={() => setSelected(p)}
                      className={`border-t border-border/30 cursor-pointer transition-colors ${
                        selected?.id === p.id ? 'bg-accent/10' : 'hover:bg-white/[0.02]'
                      } ${p.flagged ? 'border-l-2 border-l-danger' : ''}`}
                    >
                      <td className="px-2 py-2 font-mono text-muted">{i+1}</td>
                      <td className="px-2 py-2 font-mono text-[10px] text-muted whitespace-nowrap">{new Date(p.timestamp).toISOString().slice(11,19)}</td>
                      <td className="px-2 py-2 font-mono text-[10px] whitespace-nowrap">
                        <span className="text-danger">{p.srcIp}</span>
                        <span className="text-border mx-1">→</span>
                        <span className="text-safe">{p.dstIp}</span>
                      </td>
                      <td className="px-2 py-2 text-muted">{p.protocol}</td>
                      <td className="px-2 py-2">
                        {p.flagged && <span className="badge badge-danger text-[8px]">⚠</span>}
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Packet detail / hex view */}
          <div className="w-1/2 flex flex-col gap-3 min-h-0">
            {selected ? (
              <motion.div
                key={selected.id}
                initial={{ opacity: 0, x: 10 }}
                animate={{ opacity: 1, x: 0 }}
                className="soc-panel border border-accent/30 rounded-xl p-4 flex flex-col gap-3 overflow-y-auto flex-1"
              >
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-accent">Packet {selected.id}</span>
                  {selected.flagged && <span className="badge badge-danger text-[9px]">FLAGGED</span>}
                  {selected.threat && <span className="badge badge-warn text-[9px]">{selected.threat}</span>}
                </div>

                {/* Metadata */}
                <div className="grid grid-cols-2 gap-2">
                  {[
                    ['Source IP', selected.srcIp],
                    ['Destination', selected.dstIp],
                    ['Protocol', selected.protocol],
                    ['Length', `${selected.length} bytes`],
                    ['Timestamp', new Date(selected.timestamp).toISOString().slice(0,19).replace('T',' ')],
                    ['TTL', selected.ttl ?? 'N/A'],
                  ].map(([k,v]) => (
                    <div key={k} className="bg-bg rounded p-2">
                      <p className="text-[9px] text-muted uppercase tracking-wider">{k}</p>
                      <p className="text-xs font-mono text-text-dim">{v ?? '—'}</p>
                    </div>
                  ))}
                </div>

                {/* Payload */}
                {selected.payload && (
                  <div>
                    <p className="text-[10px] text-muted uppercase tracking-wider mb-1.5">Payload (ASCII)</p>
                    <pre className="bg-bg border border-border rounded-lg p-3 font-mono text-[10px] text-safe whitespace-pre-wrap break-all overflow-auto max-h-40">
                      {selected.payload}
                    </pre>
                  </div>
                )}
              </motion.div>
            ) : (
              <div className="flex-1 soc-panel border border-border rounded-xl flex items-center justify-center">
                <div className="text-center text-muted">
                  <Search size={32} className="mx-auto mb-2 opacity-30" />
                  <p className="text-sm">Select a packet to inspect</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  )
}
