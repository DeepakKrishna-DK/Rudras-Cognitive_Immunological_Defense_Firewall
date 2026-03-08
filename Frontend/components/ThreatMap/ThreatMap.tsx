'use client'
import { useEffect, useRef, useState } from 'react'
import { motion } from 'framer-motion'
import type { AttackEvent } from '@/types'

interface Beam {
  id: string
  x1: number; y1: number
  x2: number; y2: number
  color: string
  progress: number
  type: string
}

function geoToCanvas(lat: number, lng: number, w: number, h: number) {
  const x = (lng + 180) * (w / 360)
  const y = (90 - lat) * (h / 180)
  return { x, y }
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#f59e0b',
  low:      '#3b82f6',
  info:     '#06b6d4',
}

// Simple equirectangular world map paths (SVG outline)
const WORLD_PATHS = [
  // Simplified continent outlines — enough to be recognizable
  "M150,95 L160,90 L175,88 L185,92 L180,100 L165,105 L150,100 Z", // Greenland
  "M55,70 L90,65 L120,68 L140,80 L150,95 L130,110 L105,115 L80,105 L60,90 Z", // Europe/western
  "M160,70 L200,65 L230,75 L255,68 L270,80 L260,95 L240,105 L210,100 L185,92 L165,88 Z", // Asia north
  "M185,100 L215,100 L240,115 L235,135 L210,145 L195,130 L180,115 Z", // SE Asia
  "M95,100 L130,95 L155,105 L160,125 L145,140 L120,145 L100,135 L90,118 Z", // Middle East + S Asia
  "M70,105 L95,100 L100,118 L90,135 L75,140 L65,128 L65,112 Z", // Africa north
  "M65,130 L80,125 L92,140 L88,158 L75,165 L63,155 L60,140 Z", // Africa south
  "M20,90 L42,85 L50,95 L45,112 L28,120 L15,108 Z", // North America east
  "M5,80 L25,75 L42,85 L35,98 L18,105 L4,95 Z", // North America west
  "M25,140 L40,130 L48,145 L42,162 L28,168 L20,155 Z", // South America
  "M235,158 L255,152 L265,160 L255,170 L240,170 Z", // Australia
]

export default function ThreatMap({ events }: { events: AttackEvent[] }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const beamsRef = useRef<Beam[]>([])
  const animRef = useRef<number>(0)
  const [stats, setStats] = useState({ total: 0, critical: 0, countries: new Set<string>() })

  // Add new beams from events
  useEffect(() => {
    if (!events.length) return
    const latest = events.slice(-5)
    if (!canvasRef.current) return
    const { clientWidth: w, clientHeight: h } = canvasRef.current
    latest.forEach(ev => {
      const src = geoToCanvas(ev.srcLat, ev.srcLng, w, h)
      const dst = geoToCanvas(ev.dstLat, ev.dstLng, w, h)
      beamsRef.current.push({
        id: ev.id,
        x1: src.x, y1: src.y,
        x2: dst.x, y2: dst.y,
        color: SEVERITY_COLOR[ev.severity] || '#06b6d4',
        progress: 0,
        type: ev.attackType,
      })
    })
    if (beamsRef.current.length > 80) beamsRef.current = beamsRef.current.slice(-80)
    setStats({
      total: events.length,
      critical: events.filter(e => e.severity === 'critical').length,
      countries: new Set(events.map(e => e.srcCountry)),
    })
  }, [events])

  // Animation loop
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const resize = () => {
      canvas.width  = canvas.clientWidth
      canvas.height = canvas.clientHeight
    }
    resize()
    window.addEventListener('resize', resize)

    const draw = () => {
      const w = canvas.width, h = canvas.height
      ctx.clearRect(0, 0, w, h)

      // Ocean background
      ctx.fillStyle = '#020617'
      ctx.fillRect(0, 0, w, h)

      // Grid lines (lat/lng)
      ctx.strokeStyle = 'rgba(6,182,212,0.05)'
      ctx.lineWidth = 0.5
      for (let lat = -90; lat <= 90; lat += 30) {
        const y = (90 - lat) * (h / 180)
        ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(w,y); ctx.stroke()
      }
      for (let lng = -180; lng <= 180; lng += 30) {
        const x = (lng+180) * (w/360)
        ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,h); ctx.stroke()
      }

      // Land masses — draw filled polygons scaled to canvas
      ctx.fillStyle = 'rgba(15,23,42,1)'
      ctx.strokeStyle = 'rgba(30,41,59,0.8)'
      ctx.lineWidth = 0.5
      // Draw simplified rectangle continents
      const continents = [
        { x: 0.04, y: 0.25, w: 0.13, h: 0.50 }, // Americas
        { x: 0.30, y: 0.15, w: 0.18, h: 0.55 }, // Europe+Africa
        { x: 0.50, y: 0.12, w: 0.35, h: 0.55 }, // Asia
        { x: 0.73, y: 0.60, w: 0.12, h: 0.20 }, // Oceania
      ]
      continents.forEach(c => {
        ctx.beginPath()
        ctx.roundRect(c.x*w, c.y*h, c.w*w, c.h*h, 4)
        ctx.fill(); ctx.stroke()
      })

      // Glowing dots for active attack countries
      const attackers = new Map<string, {x:number,y:number,color:string}>()
      beamsRef.current.forEach(b => {
        const key = `${Math.round(b.x1)}-${Math.round(b.y1)}`
        attackers.set(key, { x:b.x1, y:b.y1, color:b.color })
      })
      attackers.forEach(({ x, y, color }) => {
        ctx.beginPath()
        const r = ctx.createRadialGradient(x,y,0,x,y,10)
        r.addColorStop(0, color)
        r.addColorStop(1, 'transparent')
        ctx.fillStyle = r
        ctx.arc(x, y, 10, 0, Math.PI*2)
        ctx.fill()
        ctx.beginPath()
        ctx.arc(x, y, 3, 0, Math.PI*2)
        ctx.fillStyle = color
        ctx.fill()
      })

      // Draw/animate beams
      beamsRef.current = beamsRef.current.filter(beam => beam.progress <= 1.2)
      beamsRef.current.forEach(beam => {
        beam.progress += 0.015
        const p = Math.min(beam.progress, 1)
        const cx = beam.x1 + (beam.x2 - beam.x1) * p
        const cy = beam.y1 + (beam.y2 - beam.y1) * p
        // Trail
        ctx.beginPath()
        ctx.moveTo(beam.x1, beam.y1)
        ctx.lineTo(cx, cy)
        const alpha = Math.max(0, 1 - beam.progress * 0.7)
        ctx.strokeStyle = beam.color.replace(')', `, ${alpha})`).replace('rgb', 'rgba')
        ctx.lineWidth = 1.5
        ctx.shadowColor = beam.color
        ctx.shadowBlur = 8
        ctx.stroke()
        ctx.shadowBlur = 0
        // Arrow head
        if (p >= 1) {
          ctx.beginPath()
          ctx.arc(beam.x2, beam.y2, 4, 0, Math.PI*2)
          ctx.fillStyle = beam.color
          ctx.fill()
          // Ripple
          const rp = (beam.progress - 1) * 3
          if (rp < 1) {
            ctx.beginPath()
            ctx.arc(beam.x2, beam.y2, 4 + rp*12, 0, Math.PI*2)
            ctx.strokeStyle = beam.color.replace(')', `, ${0.5*(1-rp)})`).replace('rgb','rgba')
            ctx.lineWidth = 1
            ctx.stroke()
          }
        }
      })

      // Target node — fixed center-right (our "defended" system)
      const tx = w*0.75, ty = h*0.45
      ctx.beginPath()
      ctx.arc(tx, ty, 6, 0, Math.PI*2)
      ctx.fillStyle = '#10b981'
      ctx.fill()
      const tg = ctx.createRadialGradient(tx, ty, 0, tx, ty, 20)
      tg.addColorStop(0, 'rgba(16,185,129,0.3)')
      tg.addColorStop(1, 'transparent')
      ctx.fillStyle = tg
      ctx.beginPath()
      ctx.arc(tx, ty, 20, 0, Math.PI*2)
      ctx.fill()
      ctx.strokeStyle = 'rgba(16,185,129,0.5)'
      ctx.lineWidth = 1
      ctx.beginPath()
      ctx.arc(tx, ty, 14 + Math.sin(Date.now()/800)*4, 0, Math.PI*2)
      ctx.stroke()

      animRef.current = requestAnimationFrame(draw)
    }
    draw()
    return () => {
      cancelAnimationFrame(animRef.current)
      window.removeEventListener('resize', resize)
    }
  }, [])

  return (
    <div className="relative w-full h-full rounded-xl overflow-hidden bg-bg border border-border">
      <canvas ref={canvasRef} className="w-full h-full" />
      {/* Overlay stats */}
      <div className="absolute top-3 left-3 flex gap-2">
        {[
          { label: 'Attacks', value: stats.total, color: 'danger' },
          { label: 'Critical', value: stats.critical, color: 'danger' },
          { label: 'Countries', value: stats.countries.size, color: 'warn' },
        ].map(({ label, value, color }) => (
          <div key={label} className="soc-panel px-3 py-1.5 text-xs">
            <span className="text-muted">{label}: </span>
            <span className={`font-mono font-bold ${color === 'danger' ? 'text-danger' : 'text-warn'}`}>{value}</span>
          </div>
        ))}
      </div>
      <div className="absolute bottom-2 right-3 text-[10px] text-muted">
        🌐 Global Threat Intelligence — Live
      </div>
    </div>
  )
}
