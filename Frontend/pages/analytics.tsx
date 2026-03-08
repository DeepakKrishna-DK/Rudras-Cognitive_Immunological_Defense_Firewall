'use client'
import Head from 'next/head'
import { BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend, AreaChart, Area } from 'recharts'
import { HOURLY_STATS, INITIAL_EVENTS } from '@/services/mockData'

const TACTIC_MAP = INITIAL_EVENTS.reduce((acc, e) => {
  acc[e.attackType] = (acc[e.attackType] || 0) + 1
  return acc
}, {} as Record<string, number>)

const topAttacks = Object.entries(TACTIC_MAP)
  .sort((a, b) => b[1] - a[1])
  .slice(0, 8)
  .map(([name, count]) => ({ name, count }))

export default function AnalyticsPage() {
  return (
    <>
      <Head><title>Analytics — Rudras SOC</title></Head>
      <div className="flex flex-col gap-4 h-full overflow-y-auto">
        <h1 className="text-lg font-bold text-text shrink-0">Security Analytics</h1>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* 24h traffic area */}
          <div className="soc-panel border border-border rounded-xl p-4">
            <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-4">24h Traffic Breakdown</p>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={HOURLY_STATS} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="gBlocked" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gAllowed" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="hour" tick={{ fontSize: 9, fill: '#475569' }} />
                <YAxis tick={{ fontSize: 9, fill: '#475569' }} />
                <Tooltip
                  contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8, fontSize: 11 }}
                />
                <Area type="monotone" dataKey="blocked" stroke="#ef4444" fill="url(#gBlocked)" strokeWidth={2} />
                <Area type="monotone" dataKey="allowed" stroke="#10b981" fill="url(#gAllowed)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Top attack types bar */}
          <div className="soc-panel border border-border rounded-xl p-4">
            <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-4">Top Attack Types</p>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={topAttacks} layout="vertical" margin={{ top: 0, right: 10, left: 60, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis type="number" tick={{ fontSize: 9, fill: '#475569' }} />
                <YAxis dataKey="name" type="category" tick={{ fontSize: 9, fill: '#94a3b8' }} width={80} />
                <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8, fontSize: 11 }} />
                <Bar dataKey="count" fill="#06b6d4" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Threats per hour line */}
          <div className="soc-panel border border-border rounded-xl p-4 lg:col-span-2">
            <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-4">Threat Events — 24h Trend</p>
            <ResponsiveContainer width="100%" height={180}>
              <LineChart data={HOURLY_STATS} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="hour" tick={{ fontSize: 9, fill: '#475569' }} />
                <YAxis tick={{ fontSize: 9, fill: '#475569' }} />
                <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8, fontSize: 11 }} />
                <Legend wrapperStyle={{ fontSize: 10 }} />
                <Line type="monotone" dataKey="threats"  stroke="#f59e0b" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="blocked"  stroke="#ef4444" strokeWidth={1.5} dot={false} strokeDasharray="4 2" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </>
  )
}
