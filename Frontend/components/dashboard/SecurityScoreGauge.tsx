'use client'
import { useEffect, useRef } from 'react'
import { motion } from 'framer-motion'
import type { SecurityScore } from '@/types'

interface SecurityScoreGaugeProps {
  score: SecurityScore
  compact?: boolean
}

function Arc({ cx, cy, r, startAngle, endAngle, stroke, strokeWidth, glow }: {
  cx: number; cy: number; r: number
  startAngle: number; endAngle: number
  stroke: string; strokeWidth: number; glow?: boolean
}) {
  const toRad = (d: number) => (d - 90) * (Math.PI / 180)
  const x1 = cx + r * Math.cos(toRad(startAngle))
  const y1 = cy + r * Math.sin(toRad(startAngle))
  const x2 = cx + r * Math.cos(toRad(endAngle))
  const y2 = cy + r * Math.sin(toRad(endAngle))
  const large = endAngle - startAngle > 180 ? 1 : 0
  return (
    <path
      d={`M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`}
      fill="none"
      stroke={stroke}
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      style={glow ? { filter: `drop-shadow(0 0 6px ${stroke})` } : undefined}
    />
  )
}

const SUB_SCORES = [
  { key: 'idsScore',         label: 'IDS',           color: '#06b6d4' },
  { key: 'ipsScore',         label: 'IPS',           color: '#10b981' },
  { key: 'mlScore',          label: 'ML Engine',     color: '#6366f1' },
  { key: 'complianceScore',  label: 'Compliance',    color: '#f59e0b' },
  { key: 'threatIntelScore', label: 'Threat Intel',  color: '#f97316' },
] as const

export default function SecurityScoreGauge({ score, compact = false }: SecurityScoreGaugeProps) {
  const s = score.overall
  const arcStart = -135
  const arcEnd = arcStart + (s / 100) * 270

  const getScoreColor = (v: number) =>
    v >= 90 ? '#10b981' : v >= 70 ? '#f59e0b' : '#ef4444'

  return (
    <div className="flex flex-col h-full soc-panel rounded-xl border border-border p-4">
      {/* Title */}
      <p className="text-xs font-semibold text-muted uppercase tracking-widest mb-3">Security Score</p>

      {/* Central gauge */}
      <div className="flex justify-center mb-3">
        <svg width={160} height={110} viewBox="0 0 160 110">
          {/* Track */}
          <Arc cx={80} cy={90} r={65} startAngle={-135} endAngle={135}
            stroke="#1e293b" strokeWidth={10} />
          {/* Value arc */}
          <Arc cx={80} cy={90} r={65} startAngle={-135} endAngle={arcEnd}
            stroke={getScoreColor(s)} strokeWidth={10} glow />

          {/* Score value */}
          <text x={80} y={88} textAnchor="middle" fontSize={28} fontWeight="700"
            fill={getScoreColor(s)} fontFamily="'JetBrains Mono', monospace">
            {s}
          </text>
          <text x={80} y={102} textAnchor="middle" fontSize={9} fill="#64748b" fontFamily="sans-serif">
            OVERALL
          </text>

          {/* Min/Max labels */}
          <text x={14} y={105} textAnchor="middle" fontSize={9} fill="#334155" fontFamily="monospace">0</text>
          <text x={146} y={105} textAnchor="middle" fontSize={9} fill="#334155" fontFamily="monospace">100</text>
        </svg>
      </div>

      {/* Sub-scores */}
      <div className="space-y-2 flex-1">
        {SUB_SCORES.map(({ key, label, color }) => {
          const val = score[key]
          return (
            <div key={key} className="flex items-center gap-2">
              <span className="text-[10px] text-muted w-20 shrink-0">{label}</span>
              <div className="flex-1 h-1.5 bg-bg rounded-full overflow-hidden">
                <motion.div
                  className="h-full rounded-full"
                  style={{ background: color, boxShadow: `0 0 6px ${color}60` }}
                  initial={{ width: 0 }}
                  animate={{ width: `${val}%` }}
                  transition={{ duration: 1, ease: 'easeOut' }}
                />
              </div>
              <span className="font-mono text-[10px] w-7 text-right" style={{ color }}>
                {val}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
