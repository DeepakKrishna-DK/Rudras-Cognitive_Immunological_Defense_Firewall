'use client'
import { useEffect, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { format } from 'date-fns'
import { Shield, AlertTriangle, Info } from 'lucide-react'
import type { AttackEvent, ThreatLevel } from '@/types'

const SEV_STYLES: Record<ThreatLevel, { border: string; badge: string; icon: React.ReactNode }> = {
  critical: { border: 'border-l-danger',  badge: 'badge badge-danger', icon: <AlertTriangle size={12} className="text-danger" /> },
  high:     { border: 'border-l-[#f97316]', badge: 'bg-orange-500/20 text-orange-400 border border-orange-500/30', icon: <AlertTriangle size={12} className="text-orange-400" /> },
  medium:   { border: 'border-l-warn',    badge: 'badge badge-warn',   icon: <AlertTriangle size={12} className="text-warn" /> },
  low:      { border: 'border-l-info',    badge: 'badge badge-info',   icon: <Info size={12} className="text-info" /> },
  info:     { border: 'border-l-muted',   badge: 'badge',              icon: <Info size={12} className="text-muted" /> },
}

const STATUS_STYLES: Record<string, string> = {
  blocked:   'badge badge-danger',
  mitigated: 'badge badge-warn',
  detected:  'badge badge-info',
  allowed:   'badge badge-safe',
}

interface AttackFeedProps {
  initialEvents: AttackEvent[]
  liveEvents: AttackEvent[]
  maxItems?: number
  compact?: boolean
}

export default function AttackFeed({ initialEvents, liveEvents, maxItems = 50, compact = false }: AttackFeedProps) {
  // Start empty on server to avoid SSR/client mismatch from Math.random() generated data
  const [events, setEvents] = useState<AttackEvent[]>([])
  const listRef = useRef<HTMLDivElement>(null)
  const [paused, setPaused] = useState(false)
  const [filter, setFilter] = useState<ThreatLevel | 'all'>('all')

  // Populate initial events only after client mount (data is random, differs server vs client)
  const initializedRef = useRef(false)
  useEffect(() => {
    if (initializedRef.current) return
    initializedRef.current = true
    setEvents(initialEvents.slice(-maxItems).reverse())
  }, [initialEvents, maxItems])

  // Append live events
  useEffect(() => {
    if (!liveEvents.length || paused) return
    setEvents(prev => {
      const combined = [liveEvents[liveEvents.length - 1], ...prev]
      return combined.slice(0, maxItems)
    })
  }, [liveEvents, paused, maxItems])

  const visible = filter === 'all' ? events : events.filter(e => e.severity === filter)

  return (
    <div className="flex flex-col h-full soc-panel rounded-xl border border-border overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border shrink-0">
        <div className="flex items-center gap-2">
          <Shield size={15} className="text-accent" />
          <span className="text-sm font-semibold text-text">Live Attack Feed</span>
          {!paused && (
            <span className="flex items-center gap-1 text-[10px] text-safe">
              <span className="w-2 h-2 rounded-full bg-safe animate-pulse inline-block" />
              LIVE
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {/* Severity filter */}
          <select
            value={filter}
            onChange={e => setFilter(e.target.value as ThreatLevel | 'all')}
            className="text-xs bg-bg border border-border rounded px-2 py-1 text-text-dim focus:outline-none focus:border-accent"
          >
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <button
            onClick={() => setPaused(p => !p)}
            className={`text-xs px-2 py-1 rounded border transition-colors ${paused ? 'border-warn text-warn' : 'border-border text-muted hover:border-accent hover:text-accent'}`}
          >
            {paused ? '▶ Resume' : '⏸ Pause'}
          </button>
        </div>
      </div>

      {/* Feed */}
      <div ref={listRef} className="flex-1 overflow-y-auto min-h-0">
        <AnimatePresence initial={false} mode="popLayout">
          {visible.map(ev => {
            const sev = SEV_STYLES[ev.severity] || SEV_STYLES.info
            const status = ev.status?.toLowerCase() || 'detected'
            return (
              <motion.div
                key={ev.id}
                initial={{ opacity: 0, x: -20, height: 0 }}
                animate={{ opacity: 1, x: 0, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.2 }}
                className={`border-l-2 ${sev.border} px-3 py-2.5 border-b border-border/50 hover:bg-white/[0.02] transition-colors cursor-default`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-1.5 min-w-0">
                    {sev.icon}
                    <span className="font-mono text-[11px] text-text truncate font-semibold">
                      {ev.attackType}
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded ${STATUS_STYLES[status] || 'badge'}`}>
                      {status.toUpperCase()}
                    </span>
                    <span className="font-mono text-[10px] text-muted" suppressHydrationWarning>
                      {format(new Date(ev.timestamp), 'HH:mm:ss')}
                    </span>
                  </div>
                </div>
                {!compact && (
                  <div className="mt-1 flex items-center gap-2 text-[10px] font-mono text-muted">
                    <span className="text-danger">{ev.srcIp}</span>
                    <span className="text-border">→</span>
                    <span className="text-safe">{ev.dstIp}</span>
                    {ev.port && <span className="text-border">:{ev.port}</span>}
                    {ev.srcCountry && (
                      <span className="ml-auto text-[9px] text-muted/60">{ev.srcCountry}</span>
                    )}
                  </div>
                )}
                {!compact && ev.mitre && (
                  <div className="mt-0.5">
                    <span className="text-[9px] font-mono text-accent/70">{ev.mitre}</span>
                    {ev.mlConfidence !== undefined && (
                      <span className="ml-2 text-[9px] text-muted">ML: {(ev.mlConfidence * 100).toFixed(0)}%</span>
                    )}
                  </div>
                )}
              </motion.div>
            )
          })}
        </AnimatePresence>
        {visible.length === 0 && (
          <div className="flex items-center justify-center h-32 text-muted text-sm">
            No events matching filter
          </div>
        )}
      </div>

      {/* Footer count */}
      <div className="px-4 py-2 border-t border-border text-[10px] text-muted flex justify-between shrink-0">
        <span>Showing {visible.length} events</span>
        <span className="font-mono">{events.length} total buffered</span>
      </div>
    </div>
  )
}
