'use client'
import Head from 'next/head'
import { motion } from 'framer-motion'
import { Globe, AlertTriangle, TrendingUp } from 'lucide-react'
import { THREAT_INTEL_ITEMS } from '@/services/mockData'

const RISK_COLOR: Record<string, string> = {
  critical: 'text-danger border-danger/30 bg-danger/10',
  high:     'text-orange-400 border-orange-500/30 bg-orange-500/10',
  medium:   'text-warn border-warn/30 bg-warn/10',
  low:      'text-info border-info/30 bg-info/10',
}

export default function IntelligencePage() {
  return (
    <>
      <Head><title>Threat Intelligence — Rudras SOC</title></Head>
      <div className="flex flex-col gap-4 h-full">
        <div className="flex items-center gap-2 shrink-0">
          <Globe size={18} className="text-accent" />
          <h1 className="text-lg font-bold text-text">Threat Intelligence</h1>
          <span className="badge badge-info ml-2">{THREAT_INTEL_ITEMS.length} IOCs</span>
        </div>

        {/* Summary cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 shrink-0">
          {[
            { label: 'Total IOCs',    value: THREAT_INTEL_ITEMS.length,  color: 'text-accent' },
            { label: 'Critical',      value: THREAT_INTEL_ITEMS.filter(t=>t.risk==='critical').length, color: 'text-danger' },
            { label: 'Active Campaigns', value: new Set(THREAT_INTEL_ITEMS.map(t=>t.campaign)).size, color: 'text-warn' },
            { label: 'Feed Sources',  value: 4, color: 'text-safe' },
          ].map(({ label, value, color }) => (
            <div key={label} className="soc-panel border border-border rounded-xl px-4 py-3">
              <p className="text-[10px] text-muted uppercase tracking-wider mb-1">{label}</p>
              <p className={`font-mono text-2xl font-bold ${color}`}>{value}</p>
            </div>
          ))}
        </div>

        {/* IOC Table */}
        <div className="flex-1 soc-panel border border-border rounded-xl overflow-hidden flex flex-col min-h-0">
          <div className="px-4 py-2.5 border-b border-border shrink-0 flex items-center gap-2">
            <AlertTriangle size={13} className="text-warn" />
            <span className="text-xs font-semibold text-text">Indicators of Compromise</span>
          </div>
          <div className="overflow-y-auto flex-1">
            <table className="w-full text-xs">
              <thead className="bg-panel sticky top-0">
                <tr>
                  {['Indicator','Type','Campaign','Last Seen','Hits','Risk'].map(h => (
                    <th key={h} className="px-3 py-2.5 text-left text-[10px] text-muted uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {THREAT_INTEL_ITEMS.map((item, i) => (
                  <motion.tr
                    key={item.id}
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.04 }}
                    className="border-t border-border/50 hover:bg-white/[0.02]"
                  >
                    <td className="px-3 py-2.5 font-mono text-danger">{item.indicator}</td>
                    <td className="px-3 py-2.5 text-muted capitalize">{item.type}</td>
                    <td className="px-3 py-2.5">
                      <span className="badge badge-accent text-[9px]">{item.campaign}</span>
                    </td>
                    <td className="px-3 py-2.5 font-mono text-muted text-[10px]">{item.lastSeen}</td>
                    <td className="px-3 py-2.5 font-mono text-warn">{item.hits}</td>
                    <td className="px-3 py-2.5">
                      <span className={`text-[9px] px-2 py-0.5 rounded-full border font-semibold ${RISK_COLOR[item.risk] || ''}`}>
                        {item.risk}
                      </span>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  )
}
