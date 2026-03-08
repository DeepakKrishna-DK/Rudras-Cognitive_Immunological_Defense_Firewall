'use client'
import Head from 'next/head'
import { useState } from 'react'
import { motion } from 'framer-motion'
import { Zap, ToggleLeft, ToggleRight, Plus, Trash2 } from 'lucide-react'
import { AUTO_RULES } from '@/services/mockData'
import type { AutoRule } from '@/types'

export default function AutomationPage() {
  const [rules, setRules] = useState<AutoRule[]>(AUTO_RULES)

  const toggle = (id: string) =>
    setRules(rs => rs.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r))

  const remove = (id: string) =>
    setRules(rs => rs.filter(r => r.id !== id))

  return (
    <>
      <Head><title>Automation — Rudras SOC</title></Head>
      <div className="flex flex-col gap-4 h-full">
        <div className="flex items-center gap-2 shrink-0">
          <Zap size={18} className="text-warn" />
          <h1 className="text-lg font-bold text-text">Automation Engine</h1>
          <span className="badge badge-safe ml-2">{rules.filter(r => r.enabled).length} Active</span>
          <button className="ml-auto flex items-center gap-1.5 text-xs bg-accent/20 text-accent border border-accent/30 hover:bg-accent/30 px-3 py-1.5 rounded-lg transition-colors">
            <Plus size={12} /> New Rule
          </button>
        </div>

        {/* Rule cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 flex-1 overflow-y-auto content-start">
          {rules.map((rule, i) => (
            <motion.div
              key={rule.id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.07 }}
              className={`soc-panel border rounded-xl p-4 ${rule.enabled ? 'border-accent/30' : 'border-border'}`}
            >
              <div className="flex items-start justify-between mb-3">
                <div>
                  <p className="text-sm font-semibold text-text">{rule.name}</p>
                  <p className="text-[10px] text-muted mt-0.5">{rule.description}</p>
                </div>
                <div className="flex items-center gap-2 ml-3 shrink-0">
                  <button onClick={() => remove(rule.id)} className="text-muted hover:text-danger">
                    <Trash2 size={12} />
                  </button>
                  <button onClick={() => toggle(rule.id)}>
                    {rule.enabled
                      ? <ToggleRight size={22} className="text-safe" />
                      : <ToggleLeft size={22} className="text-muted" />}
                  </button>
                </div>
              </div>

              {/* IF → THEN */}
              <div className="space-y-1.5">
                <div className="flex items-start gap-2 bg-bg rounded-lg px-3 py-2">
                  <span className="text-[9px] font-bold border border-info/40 text-info px-1.5 py-0.5 rounded shrink-0 mt-0.5">IF</span>
                  <p className="text-[11px] text-text-dim">{rule.condition}</p>
                </div>
                <div className="flex items-start gap-2 bg-bg rounded-lg px-3 py-2">
                  <span className="text-[9px] font-bold border border-safe/40 text-safe px-1.5 py-0.5 rounded shrink-0 mt-0.5">THEN</span>
                  <p className="text-[11px] text-text-dim">{rule.action}</p>
                </div>
              </div>

              <div className="flex items-center justify-between mt-3 text-[9px] text-muted">
                <span>Triggered: <span className="font-mono text-accent">{rule.triggerCount}</span>×</span>
                <span>Priority: <span className={`font-mono ${rule.priority === 'high' ? 'text-danger' : 'text-warn'}`}>{rule.priority}</span></span>
                <span className={rule.enabled ? 'text-safe' : 'text-muted'}>{rule.enabled ? '● ENABLED' : '○ DISABLED'}</span>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </>
  )
}
