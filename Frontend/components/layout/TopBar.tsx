'use client'
import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Bell, Search, ChevronDown, Wifi, WifiOff, User, Moon, RefreshCw } from 'lucide-react'
import type { SystemStats } from '@/types'
import { SYSTEM_STATS } from '@/services/mockData'

function formatUptime(secs: number) {
  const d = Math.floor(secs / 86400)
  const h = Math.floor((secs % 86400) / 3600)
  const m = Math.floor((secs % 3600) / 60)
  return `${d}d ${h}h ${m}m`
}

export default function TopBar({ alertCount = 0 }: { alertCount?: number }) {
  const [stats, setStats] = useState<SystemStats>(SYSTEM_STATS)
  const [time, setTime] = useState<Date | null>(null)
  const [showAlerts, setShowAlerts] = useState(false)

  useEffect(() => {
    setTime(new Date())
    const t = setInterval(() => setTime(new Date()), 1000)
    const s = setInterval(() => {
      setStats(prev => ({
        ...prev,
        packetsPerSec:    Math.max(0, prev.packetsPerSec + Math.floor((Math.random() - 0.5) * 1200)),
        cpuUsage:         Math.min(100, Math.max(5, prev.cpuUsage + Math.floor((Math.random() - 0.5) * 4))),
        activeConnections:Math.max(0, prev.activeConnections + Math.floor((Math.random() - 0.5) * 40)),
      }))
    }, 2000)
    return () => { clearInterval(t); clearInterval(s) }
  }, [])

  return (
    <header className="h-14 flex items-center gap-4 px-6 border-b border-border bg-panel/80 backdrop-blur-sm sticky top-0 z-10">
      {/* Search */}
      <div className="flex items-center gap-2 bg-bg border border-border rounded-lg px-3 py-1.5 w-64">
        <Search className="w-3.5 h-3.5 text-muted" />
        <input
          placeholder="Search IPs, rules, events..."
          className="bg-transparent text-sm text-text-dim placeholder:text-muted outline-none w-full"
        />
        <kbd className="text-[10px] text-muted border border-border rounded px-1 py-0.5">⌘K</kbd>
      </div>

      {/* Live metrics strip */}
      <div className="flex items-center gap-5 ml-4">
        {[
          { label: 'Pkts/s', value: stats.packetsPerSec.toLocaleString(), color: 'text-accent' },
          { label: 'Blocked', value: stats.blockedToday.toLocaleString(), color: 'text-danger' },
          { label: 'Connections', value: stats.activeConnections.toLocaleString(), color: 'text-safe' },
          { label: 'CPU', value: `${stats.cpuUsage}%`, color: stats.cpuUsage > 70 ? 'text-warn' : 'text-text-dim' },
        ].map(({ label, value, color }) => (
          <div key={label} className="hidden lg:flex flex-col items-center -space-y-0.5">
            <span className={`text-xs font-mono font-semibold ${color}`}>{value}</span>
            <span className="text-[10px] text-muted">{label}</span>
          </div>
        ))}
      </div>

      <div className="flex-1" />

      {/* Uptime */}
      <div className="hidden xl:flex items-center gap-1.5 text-[11px] text-text-dim">
        <RefreshCw className="w-3 h-3 text-safe" />
        <span>Uptime: {formatUptime(stats.uptime)}</span>
      </div>

      {/* Connection status */}
      <div className="flex items-center gap-1.5 text-[11px] px-2 py-1 rounded bg-safe/10 border border-safe/20">
        <Wifi className="w-3 h-3 text-safe" />
        <span className="text-safe font-medium">LIVE</span>
      </div>

      {/* Clock — client-only to avoid SSR hydration mismatch */}
      <div className="font-mono text-xs text-text-dim w-24 text-center" suppressHydrationWarning>
        {time ? time.toLocaleTimeString() : ''}
      </div>

      {/* Alerts bell */}
      <button
        onClick={() => setShowAlerts(!showAlerts)}
        className="relative p-2 rounded-lg hover:bg-white/5 transition"
      >
        <Bell className="w-4 h-4 text-text-dim" />
        {alertCount > 0 && (
          <motion.span
            initial={{ scale: 0 }} animate={{ scale: 1 }}
            className="absolute -top-0.5 -right-0.5 w-4 h-4 bg-danger rounded-full flex items-center justify-center text-[9px] font-bold text-white"
          >
            {alertCount > 9 ? '9+' : alertCount}
          </motion.span>
        )}
      </button>

      {/* Profile */}
      <button className="flex items-center gap-2 px-3 py-1.5 rounded-lg hover:bg-white/5 transition">
        <div className="w-7 h-7 rounded-full bg-accent/20 border border-accent/40 flex items-center justify-center">
          <User className="w-3.5 h-3.5 text-accent" />
        </div>
        <span className="text-sm text-text hidden sm:block">Analyst</span>
        <ChevronDown className="w-3 h-3 text-muted" />
      </button>
    </header>
  )
}
