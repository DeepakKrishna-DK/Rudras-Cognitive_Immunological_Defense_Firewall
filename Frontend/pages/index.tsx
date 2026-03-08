'use client'
import { useEffect, useState, useCallback } from 'react'
import Head from 'next/head'
import { Activity, Shield, Zap, Cpu, Globe, Brain } from 'lucide-react'
import StatCard from '@/components/dashboard/StatCard'
import AttackFeed from '@/components/dashboard/AttackFeed'
import SecurityScoreGauge from '@/components/dashboard/SecurityScoreGauge'
import IncidentTimeline from '@/components/dashboard/IncidentTimeline'
import ThreatMap from '@/components/ThreatMap/ThreatMap'
import NetworkGraph from '@/components/NetworkGraph/NetworkGraph'
import AIPanel from '@/components/AIAnalysis/AIPanel'
import { rudraSocket } from '@/services/websocket'
import {
  INITIAL_EVENTS, SYSTEM_STATS, SECURITY_SCORE,
  AI_ANALYSIS, INCIDENT_TIMELINE, NETWORK_NODES, NETWORK_EDGES
} from '@/services/mockData'
import type { AttackEvent, SystemStats } from '@/types'

export default function DashboardPage() {
  const [liveEvents, setLiveEvents]   = useState<AttackEvent[]>([])
  const [stats, setStats]             = useState<SystemStats>(SYSTEM_STATS)

  const handleEvent = useCallback((ev: AttackEvent) => {
    setLiveEvents(prev => [...prev.slice(-200), ev])
    setStats(prev => ({
      ...prev,
      packetsPerSec:    prev.packetsPerSec + Math.floor(Math.random() * 400 - 180),
      blockedToday:     ev.status === 'BLOCKED' ? prev.blockedToday + 1 : prev.blockedToday,
      threatsDetected:  prev.threatsDetected + 1,
      activeConnections: prev.activeConnections + Math.floor(Math.random() * 6 - 2),
    }))
  }, [])

  useEffect(() => {
    rudraSocket.connect()
    rudraSocket.onEvent(handleEvent)
    return () => rudraSocket.disconnect()
  }, [handleEvent])

  return (
    <>
      <Head>
        <title>Rudras SOC — Command Center</title>
      </Head>

      <div className="flex flex-col gap-4 h-full min-h-0">

        {/* Row 1 — KPI stat cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 shrink-0">
          <StatCard
            title="Packets / sec"
            value={Math.max(0, stats.packetsPerSec)}
            icon={<Activity size={16} />}
            color="accent"
            formatValue={v => v.toLocaleString()}
            subtitle="network throughput"
          />
          <StatCard
            title="Blocked Today"
            value={stats.blockedToday}
            icon={<Shield size={16} />}
            color="danger"
            delta={+12.4}
            subtitle="vs yesterday"
          />
          <StatCard
            title="Threats Detected"
            value={stats.threatsDetected}
            icon={<Zap size={16} />}
            color="warn"
            delta={+3.1}
            subtitle="last 24 h"
          />
          <StatCard
            title="CPU Usage"
            value={stats.cpuUsage}
            suffix="%"
            icon={<Cpu size={16} />}
            color={stats.cpuUsage > 80 ? 'danger' : stats.cpuUsage > 60 ? 'warn' : 'safe'}
            subtitle="Rudras engine"
          />
        </div>

        {/* Row 2 — Threat Map + Attack Feed */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-4" style={{ height: 340 }}>
          <div className="lg:col-span-3 min-h-0 h-full">
            <ThreatMap events={[...INITIAL_EVENTS, ...liveEvents]} />
          </div>
          <div className="lg:col-span-2 min-h-0 h-full">
            <AttackFeed initialEvents={INITIAL_EVENTS} liveEvents={liveEvents} />
          </div>
        </div>

        {/* Row 3 — Network Graph + AI Panel + Score Gauge */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-4" style={{ height: 320 }}>
          <div className="lg:col-span-2 min-h-0 h-full">
            <NetworkGraph nodes={NETWORK_NODES} edges={NETWORK_EDGES} />
          </div>
          <div className="lg:col-span-2 min-h-0 h-full">
            <AIPanel analysis={AI_ANALYSIS} />
          </div>
          <div className="lg:col-span-1 min-h-0 h-full">
            <SecurityScoreGauge score={SECURITY_SCORE} />
          </div>
        </div>

        {/* Row 4 — Incident Timeline */}
        <div className="shrink-0">
          <IncidentTimeline events={INCIDENT_TIMELINE} horizontal />
        </div>

      </div>
    </>
  )
}
