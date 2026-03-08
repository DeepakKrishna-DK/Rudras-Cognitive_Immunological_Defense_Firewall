'use client'
import { useEffect, useRef } from 'react'
import { motion } from 'framer-motion'
import type { ReactNode } from 'react'

type ColorKey = 'accent' | 'danger' | 'safe' | 'warn' | 'info'

interface StatCardProps {
  title: string
  value: number
  suffix?: string
  delta?: number          // percent change, positive = up
  icon: ReactNode
  color?: ColorKey
  formatValue?: (v: number) => string
  subtitle?: string
}

const COLOR_MAP: Record<ColorKey, { text: string; border: string; glow: string; bg: string }> = {
  accent: { text: 'text-accent',  border: 'border-accent/30',  glow: 'shadow-[0_0_16px_rgba(6,182,212,0.25)]',  bg: 'bg-accent/10' },
  danger: { text: 'text-danger',  border: 'border-danger/30',  glow: 'shadow-[0_0_16px_rgba(239,68,68,0.25)]',  bg: 'bg-danger/10' },
  safe:   { text: 'text-safe',    border: 'border-safe/30',    glow: 'shadow-[0_0_16px_rgba(16,185,129,0.25)]', bg: 'bg-safe/10'   },
  warn:   { text: 'text-warn',    border: 'border-warn/30',    glow: 'shadow-[0_0_16px_rgba(245,158,11,0.25)]', bg: 'bg-warn/10'   },
  info:   { text: 'text-info',    border: 'border-info/30',    glow: 'shadow-[0_0_16px_rgba(59,130,246,0.25)]', bg: 'bg-info/10'   },
}

export default function StatCard({
  title, value, suffix = '', delta, icon, color = 'accent', formatValue, subtitle
}: StatCardProps) {
  const displayRef = useRef<HTMLSpanElement>(null)
  const prevRef = useRef(0)

  // Animated counter
  useEffect(() => {
    const el = displayRef.current
    if (!el) return
    const from = prevRef.current
    const to = value
    prevRef.current = to
    const duration = 800
    const start = performance.now()
    const tick = (now: number) => {
      const t = Math.min((now - start) / duration, 1)
      const ease = 1 - Math.pow(1 - t, 3)
      const cur = Math.round(from + (to - from) * ease)
      el.textContent = formatValue ? formatValue(cur) : cur.toLocaleString()
      if (t < 1) requestAnimationFrame(tick)
    }
    requestAnimationFrame(tick)
  }, [value, formatValue])

  const colors = COLOR_MAP[color]
  const isPositiveDelta = delta !== undefined && delta > 0
  const isNegativeDelta = delta !== undefined && delta < 0

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className={`soc-panel border ${colors.border} ${colors.glow} rounded-xl p-5 flex flex-col gap-3 relative overflow-hidden`}
    >
      {/* Subtle corner glow */}
      <div className={`absolute -top-6 -right-6 w-20 h-20 rounded-full ${colors.bg} blur-2xl opacity-60 pointer-events-none`} />

      {/* Header */}
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-muted uppercase tracking-widest">{title}</span>
        <div className={`p-2 rounded-lg ${colors.bg} ${colors.text}`}>
          {icon}
        </div>
      </div>

      {/* Value */}
      <div className="flex items-end gap-2">
        <span
          ref={displayRef}
          className={`font-mono text-3xl font-bold tracking-tight ${colors.text}`}
        >
          {formatValue ? formatValue(value) : value.toLocaleString()}
        </span>
        {suffix && <span className="text-muted text-sm mb-1">{suffix}</span>}
      </div>

      {/* Delta + subtitle */}
      <div className="flex items-center gap-2 text-xs">
        {delta !== undefined && (
          <span className={`font-mono font-semibold ${isPositiveDelta ? 'text-danger' : isNegativeDelta ? 'text-safe' : 'text-muted'}`}>
            {isPositiveDelta ? '▲' : isNegativeDelta ? '▼' : '—'}
            {' '}{Math.abs(delta).toFixed(1)}%
          </span>
        )}
        {subtitle && <span className="text-muted">{subtitle}</span>}
      </div>

      {/* Bottom accent bar */}
      <div className={`absolute bottom-0 left-0 right-0 h-0.5 ${colors.bg}`}>
        <motion.div
          className={`h-full ${colors.text.replace('text-', 'bg-')}`}
          initial={{ width: 0 }}
          animate={{ width: '100%' }}
          transition={{ duration: 1.2, ease: 'easeOut' }}
        />
      </div>
    </motion.div>
  )
}
