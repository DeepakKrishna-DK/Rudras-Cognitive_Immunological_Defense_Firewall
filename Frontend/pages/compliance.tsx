'use client'
import Head from 'next/head'
import { motion } from 'framer-motion'
import { CheckCircle, AlertTriangle, Clock } from 'lucide-react'

const FRAMEWORKS = [
  {
    id: 'nist',
    name: 'NIST CSF 2.0',
    score: 91,
    status: 'compliant',
    controls: 23,
    passed: 21,
    failed: 2,
    color: '#10b981',
  },
  {
    id: 'pci',
    name: 'PCI DSS 4.0',
    score: 88,
    status: 'compliant',
    controls: 12,
    passed: 11,
    failed: 1,
    color: '#06b6d4',
  },
  {
    id: 'hipaa',
    name: 'HIPAA Security Rule',
    score: 94,
    status: 'compliant',
    controls: 18,
    passed: 17,
    failed: 1,
    color: '#6366f1',
  },
  {
    id: 'gdpr',
    name: 'GDPR Art. 32',
    score: 79,
    status: 'partial',
    controls: 10,
    passed: 8,
    failed: 2,
    color: '#f59e0b',
  },
  {
    id: 'iso27001',
    name: 'ISO 27001:2022',
    score: 85,
    status: 'compliant',
    controls: 20,
    passed: 17,
    failed: 3,
    color: '#3b82f6',
  },
]

function ScoreRing({ score, color, size = 80 }: { score: number; color: string; size?: number }) {
  const r = size / 2 - 8
  const circ = 2 * Math.PI * r
  const dash = (score / 100) * circ
  return (
    <svg width={size} height={size}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#1e293b" strokeWidth={7} />
      <motion.circle
        cx={size/2} cy={size/2} r={r}
        fill="none"
        stroke={color}
        strokeWidth={7}
        strokeLinecap="round"
        strokeDasharray={circ}
        initial={{ strokeDashoffset: circ }}
        animate={{ strokeDashoffset: circ - dash }}
        transition={{ duration: 1.2, ease: 'easeOut' }}
        transform={`rotate(-90 ${size/2} ${size/2})`}
        style={{ filter: `drop-shadow(0 0 4px ${color})` }}
      />
      <text x={size/2} y={size/2 + 5} textAnchor="middle" fontSize={16} fontWeight="700"
        fill={color} fontFamily="monospace">{score}</text>
    </svg>
  )
}

export default function CompliancePage() {
  return (
    <>
      <Head><title>Compliance — Rudras SOC</title></Head>
      <div className="flex flex-col gap-4 h-full overflow-y-auto">
        <div className="flex items-center gap-2 shrink-0">
          <CheckCircle size={18} className="text-safe" />
          <h1 className="text-lg font-bold text-text">Compliance Dashboard</h1>
          <span className="badge badge-safe ml-2">4/5 Frameworks Compliant</span>
        </div>

        {/* Framework cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {FRAMEWORKS.map((fw, i) => (
            <motion.div
              key={fw.id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.08 }}
              className="soc-panel border border-border rounded-xl p-4"
            >
              <div className="flex items-start justify-between mb-3">
                <div>
                  <p className="text-sm font-bold text-text">{fw.name}</p>
                  <span className={`text-[9px] font-semibold mt-1 inline-block px-2 py-0.5 rounded-full border ${
                    fw.status === 'compliant'
                      ? 'text-safe border-safe/30 bg-safe/10'
                      : 'text-warn border-warn/30 bg-warn/10'
                  }`}>
                    {fw.status === 'compliant' ? '✓ COMPLIANT' : '△ PARTIAL'}
                  </span>
                </div>
                <ScoreRing score={fw.score} color={fw.color} size={72} />
              </div>

              <div className="grid grid-cols-3 gap-2 text-center">
                <div className="bg-bg rounded-lg py-2">
                  <p className="font-mono text-base font-bold text-text">{fw.controls}</p>
                  <p className="text-[9px] text-muted">Total</p>
                </div>
                <div className="bg-bg rounded-lg py-2">
                  <p className="font-mono text-base font-bold text-safe">{fw.passed}</p>
                  <p className="text-[9px] text-muted">Passed</p>
                </div>
                <div className="bg-bg rounded-lg py-2">
                  <p className="font-mono text-base font-bold text-danger">{fw.failed}</p>
                  <p className="text-[9px] text-muted">Failed</p>
                </div>
              </div>

              {/* Progress bar */}
              <div className="mt-3 h-1.5 bg-bg rounded-full overflow-hidden">
                <motion.div
                  className="h-full rounded-full"
                  style={{ background: fw.color }}
                  initial={{ width: 0 }}
                  animate={{ width: `${fw.score}%` }}
                  transition={{ duration: 1.2, ease: 'easeOut', delay: i * 0.08 }}
                />
              </div>
            </motion.div>
          ))}
        </div>

        {/* Pending items */}
        <div className="soc-panel border border-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <Clock size={13} className="text-warn" />
            <span className="text-xs font-semibold text-text">Pending Remediations</span>
          </div>
          <div className="space-y-2">
            {[
              { fw: 'GDPR', control: 'Art 32 – Encryption at rest', severity: 'high', due: '7 days' },
              { fw: 'PCI DSS', control: 'Req 6.4 – WAF rule updates', severity: 'medium', due: '14 days' },
              { fw: 'NIST', control: 'PR.AC-4 – MFA enforcement', severity: 'high', due: '3 days' },
              { fw: 'ISO 27001', control: 'A.9.1.2 – Access review', severity: 'low', due: '30 days' },
            ].map(({ fw, control, severity, due }, i) => (
              <div key={i} className="flex items-center gap-3 bg-bg rounded-lg px-3 py-2.5 border border-border/50">
                <span className="badge badge-info text-[9px] w-20 text-center shrink-0">{fw}</span>
                <span className="text-xs text-text-dim flex-1">{control}</span>
                <span className={`text-[9px] font-mono ${severity==='high'?'text-danger':severity==='medium'?'text-warn':'text-muted'}`}>
                  {severity}
                </span>
                <span className="text-[9px] text-muted font-mono">Due: {due}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </>
  )
}
