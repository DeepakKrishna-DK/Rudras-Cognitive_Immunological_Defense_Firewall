'use client'
import Head from 'next/head'
import AIPanel from '@/components/AIAnalysis/AIPanel'
import { AI_ANALYSIS } from '@/services/mockData'

export default function AIPage() {
  return (
    <>
      <Head><title>AI Analysis — Rudras SOC</title></Head>
      <div className="flex flex-col gap-4 h-full">
        <h1 className="text-lg font-bold text-text shrink-0">AI Threat Analysis Engine</h1>
        <div className="flex flex-1 gap-4 min-h-0">
          {/* Main AI panel */}
          <div className="flex-1 min-h-0">
            <AIPanel analysis={AI_ANALYSIS} />
          </div>
          {/* Engine status sidebar */}
          <div className="w-64 space-y-3 shrink-0">
            {[
              { name: 'Anomaly Detector',        status: 'online',   score: 98 },
              { name: 'Behavior Classifier',      status: 'online',   score: 94 },
              { name: 'NLP Payload Analyzer',     status: 'online',   score: 91 },
              { name: 'Graph Neural Net',         status: 'learning', score: 82 },
              { name: 'Zero-Day Predictor',       status: 'online',   score: 77 },
              { name: 'Campaign Correlator',      status: 'online',   score: 88 },
            ].map(({ name, status, score }) => (
              <div key={name} className="soc-panel border border-border rounded-xl p-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-text-dim">{name}</span>
                  <span className={`text-[9px] font-mono ${status==='online'?'text-safe':status==='learning'?'text-warn':'text-muted'}`}>
                    {status.toUpperCase()}
                  </span>
                </div>
                <div className="h-1.5 bg-bg rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${score>=90?'bg-safe':score>=75?'bg-accent':'bg-warn'}`}
                    style={{ width: `${score}%` }}
                  />
                </div>
                <p className={`text-right text-[9px] font-mono mt-0.5 ${score>=90?'text-safe':score>=75?'text-accent':'text-warn'}`}>
                  {score}%
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </>
  )
}
