'use client'
import Head from 'next/head'
import NetworkGraph from '@/components/NetworkGraph/NetworkGraph'
import { NETWORK_NODES, NETWORK_EDGES, SYSTEM_STATS } from '@/services/mockData'

export default function NetworkPage() {
  return (
    <>
      <Head><title>Network Topology — Rudras SOC</title></Head>
      <div className="flex flex-col h-full gap-4">
        <div className="flex items-center justify-between shrink-0">
          <h1 className="text-lg font-bold text-text">Network Topology</h1>
          <div className="flex gap-2 text-xs">
            <span className="badge badge-safe">Rudras Engine: ONLINE</span>
            <span className="badge badge-info">{NETWORK_NODES.length} Nodes</span>
            <span className="badge badge-info">{NETWORK_EDGES.length} Edges</span>
            <span className="badge badge-danger">1 Under Attack</span>
          </div>
        </div>

        {/* Main graph */}
        <div className="flex-1 min-h-0">
          <NetworkGraph nodes={NETWORK_NODES} edges={NETWORK_EDGES} />
        </div>

        {/* Node inventory table */}
        <div className="soc-panel rounded-xl border border-border overflow-hidden shrink-0" style={{ maxHeight: 220 }}>
          <div className="px-4 py-2.5 border-b border-border">
            <span className="text-xs font-semibold text-text uppercase tracking-wider">Node Inventory</span>
          </div>
          <div className="overflow-y-auto" style={{ maxHeight: 170 }}>
            <table className="w-full text-xs">
              <thead className="bg-panel sticky top-0">
                <tr>
                  {['Node','Type','IP','Status','Last Seen'].map(h => (
                    <th key={h} className="px-3 py-2 text-left text-[10px] text-muted uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {NETWORK_NODES.map(n => (
                  <tr key={n.id} className="border-t border-border/50 hover:bg-white/[0.02]">
                    <td className="px-3 py-2 font-semibold text-text">{n.label}</td>
                    <td className="px-3 py-2 text-muted capitalize">{n.type}</td>
                    <td className="px-3 py-2 font-mono text-accent">{n.ip || '—'}</td>
                    <td className="px-3 py-2">
                      <span className={`badge text-[9px] ${
                        n.status==='danger' ? 'badge-danger' :
                        n.status==='warning' ? 'badge-warn' :
                        n.status==='isolated' ? 'badge-info' : 'badge-safe'}`}>
                        {n.status}
                      </span>
                    </td>
                    <td className="px-3 py-2 font-mono text-muted">just now</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  )
}
