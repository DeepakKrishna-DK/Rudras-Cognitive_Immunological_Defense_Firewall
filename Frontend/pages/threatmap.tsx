'use client'
import Head from 'next/head'
import { useState, useEffect } from 'react'
import ThreatMap from '@/components/ThreatMap/ThreatMap'
import { rudraSocket } from '@/services/websocket'
import { INITIAL_EVENTS } from '@/services/mockData'
import type { AttackEvent } from '@/types'

export default function ThreatMapPage() {
  const [events, setEvents] = useState<AttackEvent[]>(INITIAL_EVENTS)

  useEffect(() => {
    rudraSocket.connect()
    rudraSocket.onEvent(ev => setEvents(prev => [...prev.slice(-300), ev]))
    return () => rudraSocket.disconnect()
  }, [])

  return (
    <>
      <Head><title>Threat Map — Rudras SOC</title></Head>
      <div className="flex flex-col h-full gap-3">
        <div className="flex items-center justify-between shrink-0">
          <h1 className="text-lg font-bold text-text">Global Threat Intelligence Map</h1>
          <div className="flex gap-3 text-xs text-muted">
            {(['critical','high','medium','low'] as const).map(s => (
              <span key={s} className={`flex items-center gap-1`}>
                <span className={`w-2 h-2 rounded-full ${
                  s==='critical'?'bg-danger':s==='high'?'bg-orange-500':s==='medium'?'bg-warn':'bg-info'}`} />
                {s}
              </span>
            ))}
          </div>
        </div>
        <div className="flex-1 min-h-0">
          <ThreatMap events={events} />
        </div>
        <div className="grid grid-cols-4 gap-3 shrink-0">
          {[
            { label:'Total Attacks',  value: events.length },
            { label:'Critical',       value: events.filter(e=>e.severity==='critical').length, cls:'text-danger' },
            { label:'Countries',      value: new Set(events.map(e=>e.srcCountry)).size, cls:'text-warn' },
            { label:'Blocked',        value: events.filter(e=>e.status==='BLOCKED').length, cls:'text-safe' },
          ].map(({label,value,cls}) => (
            <div key={label} className="soc-panel border border-border rounded-xl px-4 py-3">
              <p className="text-[10px] text-muted uppercase tracking-wider mb-1">{label}</p>
              <p className={`font-mono text-2xl font-bold ${cls||'text-accent'}`}>{value}</p>
            </div>
          ))}
        </div>
      </div>
    </>
  )
}
