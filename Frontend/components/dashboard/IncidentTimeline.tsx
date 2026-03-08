'use client'
import { motion } from 'framer-motion'
import { format } from 'date-fns'
import { Shield, AlertTriangle, Ban, Eye, Zap, Info } from 'lucide-react'
import type { IncidentTimelineEvent } from '@/types'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const EVENT_ICONS: Record<string, React.FC<any>> = {
  detection:  Eye,
  block:      Ban,
  alert:      AlertTriangle,
  mitigation: Shield,
  escalation: Zap,
  info:       Info,
}

const EVENT_COLORS: Record<string, { dot: string; line: string; text: string }> = {
  detection:  { dot: 'bg-info border-info',     line: 'bg-info/30',     text: 'text-info' },
  block:      { dot: 'bg-danger border-danger',  line: 'bg-danger/30',   text: 'text-danger' },
  alert:      { dot: 'bg-warn border-warn',      line: 'bg-warn/30',     text: 'text-warn' },
  mitigation: { dot: 'bg-safe border-safe',      line: 'bg-safe/30',     text: 'text-safe' },
  escalation: { dot: 'bg-accent border-accent',  line: 'bg-accent/30',   text: 'text-accent' },
  info:       { dot: 'bg-muted border-muted',    line: 'bg-muted/30',    text: 'text-muted' },
}

interface IncidentTimelineProps {
  events: IncidentTimelineEvent[]
  horizontal?: boolean
}

export default function IncidentTimeline({ events, horizontal = true }: IncidentTimelineProps) {
  if (horizontal) {
    return (
      <div className="soc-panel rounded-xl border border-border p-4">
        <div className="flex items-center gap-2 mb-4">
          <Zap size={14} className="text-warn" />
          <span className="text-xs font-semibold text-text uppercase tracking-wider">Incident Timeline</span>
          <span className="ml-auto text-[10px] text-muted">{events.length} events</span>
        </div>

        <div className="relative overflow-x-auto">
          {/* Horizontal connector line */}
          <div className="absolute left-0 right-0 top-[22px] h-px bg-border" />

          <div className="flex gap-6 pb-2">
            {events.map((ev, i) => {
              const colors = EVENT_COLORS[ev.type] || EVENT_COLORS.info
              const IconComp = EVENT_ICONS[ev.type] || Info
              return (
                <motion.div
                  key={ev.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.06 }}
                  className="flex flex-col items-center gap-2 min-w-[120px]"
                >
                  {/* Dot */}
                  <div className={`w-11 h-11 rounded-full border-2 ${colors.dot} flex items-center justify-center z-10 bg-panel`}>
                    <IconComp size={16} className={colors.text} />
                  </div>
                  {/* Content */}
                  <div className="text-center">
                    <p className="text-[10px] font-semibold text-text leading-tight mb-0.5">{ev.title}</p>
                    <p className="text-[9px] text-muted font-mono mb-1">
                      {format(new Date(ev.timestamp), 'HH:mm:ss')}
                    </p>
                    {ev.description && (
                      <p className="text-[9px] text-muted/70 leading-tight max-w-[110px]">{ev.description}</p>
                    )}
                    {ev.severity && (
                      <span className={`text-[9px] font-mono ${colors.text} bg-current/10 px-1 py-0.5 rounded mt-1 inline-block`}>
                        {ev.severity.toUpperCase()}
                      </span>
                    )}
                  </div>
                </motion.div>
              )
            })}
          </div>
        </div>
      </div>
    )
  }

  // Vertical layout
  return (
    <div className="soc-panel rounded-xl border border-border p-4 flex flex-col h-full">
      <div className="flex items-center gap-2 mb-4">
        <Zap size={14} className="text-warn" />
        <span className="text-xs font-semibold text-text uppercase tracking-wider">Incident Timeline</span>
      </div>
      <div className="flex-1 overflow-y-auto space-y-0 min-h-0">
        {events.map((ev, i) => {
          const colors = EVENT_COLORS[ev.type] || EVENT_COLORS.info
          const IconComp = EVENT_ICONS[ev.type] || Info
          return (
            <motion.div
              key={ev.id}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.06 }}
              className="flex gap-3 relative"
            >
              {/* Line */}
              {i < events.length - 1 && (
                <div className={`absolute left-[19px] top-[40px] bottom-0 w-0.5 ${colors.line}`} />
              )}
              {/* Dot */}
              <div className={`w-10 h-10 rounded-full border-2 ${colors.dot} flex items-center justify-center shrink-0 bg-panel z-10`}>
                <IconComp size={14} className={colors.text} />
              </div>
              {/* Content */}
              <div className="pb-4 pt-1.5 flex-1">
                <div className="flex items-center gap-2 mb-0.5">
                  <p className="text-xs font-semibold text-text">{ev.title}</p>
                  <span className="ml-auto font-mono text-[10px] text-muted">
                    {format(new Date(ev.timestamp), 'HH:mm:ss')}
                  </span>
                </div>
                {ev.description && (
                  <p className="text-[11px] text-text-dim leading-relaxed">{ev.description}</p>
                )}
              </div>
            </motion.div>
          )
        })}
      </div>
    </div>
  )
}
