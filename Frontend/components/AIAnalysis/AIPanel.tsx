'use client'
import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Brain, ChevronRight, CheckCircle, AlertTriangle, Target, Layers } from 'lucide-react'
import type { AiAnalysis } from '@/types'

interface AIPanelProps {
  analysis: AiAnalysis
}

export default function AIPanel({ analysis }: AIPanelProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'mitre' | 'recommendations'>('overview')
  const [lastAnalyzed, setLastAnalyzed] = useState<string | null>(null)

  useEffect(() => {
    setLastAnalyzed(new Date().toLocaleTimeString())
  }, [])

  const conf = analysis.confidence
  const confColor = conf >= 90 ? 'text-danger' : conf >= 70 ? 'text-warn' : 'text-safe'
  const confBg   = conf >= 90 ? 'bg-danger' : conf >= 70 ? 'bg-warn' : 'bg-safe'

  return (
    <div className="flex flex-col h-full soc-panel rounded-xl border border-border overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-border shrink-0">
        <Brain size={15} className="text-accent" />
        <span className="text-sm font-semibold text-text">AI Threat Analysis</span>
        <span className="ml-auto text-[10px] bg-accent/15 text-accent border border-accent/30 px-2 py-0.5 rounded-full font-mono">
          GPT-Security Engine v4
        </span>
      </div>

      {/* Threat name + confidence */}
      <div className="px-4 pt-4 pb-2 shrink-0">
        <div className="flex items-start justify-between gap-2 mb-3">
          <div>
            <p className="text-xs text-muted uppercase tracking-widest mb-1">Identified Threat Pattern</p>
            <h3 className="text-base font-bold text-text leading-tight">{analysis.threatName}</h3>
          </div>
          <div className="text-right shrink-0">
            <p className="text-xs text-muted mb-1">Confidence</p>
            <p className={`font-mono text-2xl font-bold ${confColor}`}>{conf}%</p>
          </div>
        </div>

        {/* Confidence bar */}
        <div className="h-1.5 bg-bg rounded-full overflow-hidden mb-1">
          <motion.div
            className={`h-full rounded-full ${confBg}`}
            initial={{ width: 0 }}
            animate={{ width: `${conf}%` }}
            transition={{ duration: 1, ease: 'easeOut' }}
          />
        </div>
        <div className="flex justify-between text-[9px] text-muted font-mono">
          <span>0%</span><span>50%</span><span>100%</span>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-border shrink-0">
        {(['overview', 'mitre', 'recommendations'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`flex-1 text-[11px] py-2 capitalize transition-colors ${
              activeTab === tab
                ? 'text-accent border-b-2 border-accent bg-accent/5'
                : 'text-muted hover:text-text-dim'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-y-auto min-h-0 px-4 py-3">
        {activeTab === 'overview' && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-3">
            {/* Key metrics */}
            <div className="grid grid-cols-2 gap-2">
              {[
                { label: 'IOC Matches', value: analysis.iocMatches, color: 'text-danger' },
                { label: 'Behavior Score', value: analysis.behaviorScore + '%', color: 'text-warn' },
                { label: 'Affected Hosts', value: analysis.affectedHosts ?? 3, color: 'text-accent' },
                { label: 'Campaign Age', value: analysis.campaignAge ?? '14d', color: 'text-muted' },
              ].map(({ label, value, color }) => (
                <div key={label} className="bg-bg rounded-lg p-2.5 border border-border/50">
                  <p className="text-[9px] text-muted uppercase tracking-wider">{label}</p>
                  <p className={`font-mono text-base font-bold ${color}`}>{value}</p>
                </div>
              ))}
            </div>

            {analysis.summary && (
              <div className="bg-bg rounded-lg p-3 border border-border/50">
                <p className="text-[11px] text-text-dim leading-relaxed">{analysis.summary}</p>
              </div>
            )}

            {/* Threat actors if present */}
            {analysis.actors && analysis.actors.length > 0 && (
              <div>
                <p className="text-[10px] text-muted uppercase tracking-wider mb-1.5 flex items-center gap-1">
                  <Target size={10} /> Attributed Actors
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {analysis.actors.map(a => (
                    <span key={a} className="badge badge-danger text-[10px]">{a}</span>
                  ))}
                </div>
              </div>
            )}
          </motion.div>
        )}

        {activeTab === 'mitre' && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-2">
            <p className="text-[10px] text-muted uppercase tracking-wider mb-2 flex items-center gap-1">
              <Layers size={10} /> MITRE ATT&amp;CK Techniques
            </p>
            {(analysis.mitreTechniques ?? []).map((t, i) => (
              <div key={i} className="flex items-center gap-2 bg-bg rounded-lg p-2.5 border border-border/50">
                <span className="font-mono text-[10px] text-accent border border-accent/30 px-1.5 py-0.5 rounded">
                  {t.id}
                </span>
                <span className="text-xs text-text-dim truncate">{t.name}</span>
                <span className="ml-auto text-[10px] font-mono text-muted">{t.tactic}</span>
              </div>
            ))}
            {(!analysis.mitreTechniques || analysis.mitreTechniques.length === 0) && (
              <p className="text-xs text-muted">No MITRE techniques mapped</p>
            )}
          </motion.div>
        )}

        {activeTab === 'recommendations' && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-2">
            <p className="text-[10px] text-muted uppercase tracking-wider mb-2 flex items-center gap-1">
              <CheckCircle size={10} className="text-safe" /> AI Recommendations
            </p>
            {analysis.recommendations.map((r, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: 10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.08 }}
                className="flex items-start gap-2.5 bg-bg rounded-lg p-3 border border-border/50"
              >
                <CheckCircle size={13} className="text-safe mt-0.5 shrink-0" />
                <p className="text-xs text-text-dim leading-relaxed">{r}</p>
                <ChevronRight size={11} className="text-muted mt-0.5 shrink-0 ml-auto" />
              </motion.div>
            ))}
          </motion.div>
        )}
      </div>

      {/* Footer */}
      <div className="px-4 py-2 border-t border-border flex justify-between text-[10px] text-muted shrink-0">
        <span className="flex items-center gap-1" suppressHydrationWarning>
          <AlertTriangle size={9} className="text-warn" />
          Last analyzed: {lastAnalyzed ?? ''}
        </span>
        <button className="text-accent hover:text-accent/80 transition-colors">Run Full Analysis</button>
      </div>
    </div>
  )
}
