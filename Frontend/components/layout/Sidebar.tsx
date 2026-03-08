'use client'
import { useState } from 'react'
import Link from 'next/link'
import Image from 'next/image'
import { useRouter } from 'next/router'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Activity, AlertTriangle, BarChart2, Terminal, Network,
  Settings, Globe, Zap, ChevronLeft, ChevronRight,
  Bot, Search, Lock
} from 'lucide-react'
import appIcon from '@/icons/appicon.png'
import monoIcon from '@/icons/monochrome.png'

const NAV_ITEMS = [
  { href: '/',            icon: Activity,      label: 'Dashboard' },
  { href: '/threatmap',   icon: Globe,         label: 'Threat Map' },
  { href: '/alerts',      icon: AlertTriangle, label: 'Alerts' },
  { href: '/network',     icon: Network,       label: 'Network' },
  { href: '/analytics',   icon: BarChart2,     label: 'Analytics' },
  { href: '/intelligence',icon: Globe,         label: 'Threat Intel' },
  { href: '/automation',  icon: Zap,           label: 'Automation' },
  { href: '/forensics',   icon: Terminal,      label: 'Forensics' },
  { href: '/hunt',        icon: Search,        label: 'Threat Hunt' },
  { href: '/ai',          icon: Bot,           label: 'AI Analysis' },
  { href: '/compliance',  icon: Lock,          label: 'Compliance' },
  { href: '/settings',    icon: Settings,      label: 'Settings' },
]

export default function Sidebar() {
  const [collapsed, setCollapsed] = useState(false)
  const router = useRouter()

  return (
    <motion.aside
      animate={{ width: collapsed ? 64 : 220 }}
      transition={{ duration: 0.25, ease: 'easeInOut' }}
      className="relative flex flex-col h-screen flex-shrink-0 z-20"
      style={{
        background: 'linear-gradient(180deg, rgba(15,23,42,0.97) 0%, rgba(2,6,23,0.99) 100%)',
        borderRight: '1px solid rgba(6,182,212,0.15)',
        boxShadow: '4px 0 24px rgba(6,182,212,0.06), inset -1px 0 0 rgba(6,182,212,0.08)',
      }}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 py-5 border-b border-border"
           style={{ background: 'linear-gradient(135deg, rgba(6,182,212,0.06) 0%, transparent 80%)' }}>
        <div className="relative flex-shrink-0 w-9 h-9">
          {/* Show full-colour icon when expanded, monochrome when collapsed */}
          <Image
            src={collapsed ? monoIcon : appIcon}
            alt="Rudras"
            width={36}
            height={36}
            className="rounded-xl object-contain"
            style={{
              filter: 'drop-shadow(0 0 10px rgba(6,182,212,0.7)) brightness(1.05)',
            }}
          />
          <span
            className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 bg-safe rounded-full"
            style={{ boxShadow: '0 0 8px #10b981, 0 0 16px rgba(16,185,129,0.4)', animation: 'pulse 2s cubic-bezier(0.4,0,0.6,1) infinite' }}
          />
        </div>
        <AnimatePresence>
          {!collapsed && (
            <motion.div initial={{ opacity:0, x:-6 }} animate={{ opacity:1, x:0 }} exit={{ opacity:0, x:-6 }}>
              <p className="text-text font-bold text-base leading-tight tracking-wide"
                 style={{ textShadow: '0 0 12px rgba(6,182,212,0.5)' }}>
                RUDRAS
              </p>
              <p className="text-accent text-[9px] uppercase tracking-[0.2em] font-medium">SOC Command Center</p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-0.5">
        {NAV_ITEMS.map(({ href, icon: Icon, label }) => {
          const active = router.pathname === href || (href !== '/' && router.pathname.startsWith(href))
          return (
            <Link key={href} href={href}>
              <motion.div
                whileHover={{ x: 2 }}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg cursor-pointer transition-colors
                  ${active
                    ? 'bg-accent/10 text-accent border border-accent/20'
                    : 'text-text-dim hover:text-text hover:bg-white/5'
                  }`}
              >
                <Icon className="w-4 h-4 flex-shrink-0" />
                <AnimatePresence>
                  {!collapsed && (
                    <motion.span
                      initial={{ opacity:0 }} animate={{ opacity:1 }} exit={{ opacity:0 }}
                      className="text-sm font-medium whitespace-nowrap"
                    >
                      {label}
                    </motion.span>
                  )}
                </AnimatePresence>
                {active && !collapsed && (
                  <motion.div layoutId="nav-indicator"
                    className="ml-auto w-1.5 h-1.5 rounded-full bg-accent"
                    style={{ boxShadow: '0 0 6px #06b6d4' }}
                  />
                )}
              </motion.div>
            </Link>
          )
        })}
      </nav>

      {/* Engine status mini panel */}
      <AnimatePresence>
        {!collapsed && (
          <motion.div
            initial={{ opacity:0 }} animate={{ opacity:1 }} exit={{ opacity:0 }}
            className="mx-2 mb-3 p-3 rounded-lg bg-bg border border-border"
          >
            <p className="text-[10px] text-text-dim uppercase tracking-wider mb-2">Engine Status</p>
            {[
              { label:'IDS/IPS', color:'safe' },
              { label:'ML Engine', color:'safe' },
              { label:'Threat Intel', color:'safe' },
              { label:'RASP', color:'warn' },
            ].map(({ label, color }) => (
              <div key={label} className="flex items-center justify-between py-0.5">
                <span className="text-[11px] text-text-dim">{label}</span>
                <span className={`status-dot ${color === 'safe' ? 'online' : 'warning'}`} />
              </div>
            ))}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Collapse toggle */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="absolute -right-3 top-1/2 -mt-4 w-6 h-6 rounded-full bg-panel border border-border
          flex items-center justify-center text-text-dim hover:text-accent transition z-30"
      >
        {collapsed ? <ChevronRight className="w-3 h-3" /> : <ChevronLeft className="w-3 h-3" />}
      </button>
    </motion.aside>
  )
}
