'use client'
import { useEffect, useRef, useState } from 'react'
import { motion } from 'framer-motion'
import { Globe, Server, Shield, Monitor, Cpu, Wifi } from 'lucide-react'
import type { NetworkNode, NetworkEdge } from '@/types'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const NODE_ICONS: Record<string, React.FC<any>> = {
  internet:  Globe,
  router:    Wifi,
  firewall:  Shield,
  server:    Server,
  client:    Monitor,
  iot:       Cpu,
  attacker:  Globe,
}

const STATUS_COLORS: Record<string, { fill: string; glow: string; ring: string }> = {
  normal:   { fill: '#0f172a', glow: 'rgba(6,182,212,0.3)',   ring: '#334155' },
  warning:  { fill: '#1c1308', glow: 'rgba(245,158,11,0.4)',  ring: '#f59e0b' },
  danger:   { fill: '#1a0808', glow: 'rgba(239,68,68,0.5)',   ring: '#ef4444' },
  isolated: { fill: '#0d0d0d', glow: 'rgba(99,102,241,0.4)',  ring: '#6366f1' },
}

// Pre-computed layout positions (percentage of container)
const NODE_POSITIONS: Record<string, { px: number; py: number }> = {
  internet: { px: 0.10, py: 0.50 },
  router:   { px: 0.28, py: 0.50 },
  firewall: { px: 0.46, py: 0.50 },
  web1:     { px: 0.65, py: 0.25 },
  db1:      { px: 0.65, py: 0.75 },
  ad:       { px: 0.82, py: 0.50 },
  client1:  { px: 0.82, py: 0.20 },
  client2:  { px: 0.82, py: 0.80 },
  iot1:     { px: 0.65, py: 0.50 },
}

interface NetworkGraphProps {
  nodes: NetworkNode[]
  edges: NetworkEdge[]
}

export default function NetworkGraph({ nodes, edges }: NetworkGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null)
  const [dim, setDim] = useState({ w: 800, h: 400 })
  const [tooltip, setTooltip] = useState<{ node: NetworkNode; x: number; y: number } | null>(null)
  const [animTick, setAnimTick] = useState(0)

  useEffect(() => {
    const el = svgRef.current?.parentElement
    if (!el) return
    const ro = new ResizeObserver(entries => {
      const { width, height } = entries[0].contentRect
      setDim({ w: width, h: height })
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  // Pulse animation tick
  useEffect(() => {
    const id = setInterval(() => setAnimTick(t => t + 1), 50)
    return () => clearInterval(id)
  }, [])

  const getPos = (nodeId: string) => {
    const p = NODE_POSITIONS[nodeId] || { px: 0.5, py: 0.5 }
    return { x: p.px * dim.w, y: p.py * dim.h }
  }

  return (
    <div className="relative w-full h-full soc-panel rounded-xl border border-border overflow-hidden">
      <div className="absolute top-3 left-3 z-10 flex items-center gap-2">
        <Shield size={14} className="text-accent" />
        <span className="text-xs font-semibold text-text">Network Topology</span>
      </div>

      <svg ref={svgRef} width="100%" height="100%" className="w-full h-full">
        <defs>
          {/* Arrow markers */}
          <marker id="arrow-normal" markerWidth="6" markerHeight="6" refX="3" refY="3" orient="auto">
            <path d="M0,0 L6,3 L0,6 Z" fill="#1e293b" />
          </marker>
          <marker id="arrow-attack" markerWidth="6" markerHeight="6" refX="3" refY="3" orient="auto">
            <path d="M0,0 L6,3 L0,6 Z" fill="#ef4444" />
          </marker>
          {/* Glow filter */}
          <filter id="glow-red" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <filter id="glow-cyan" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>

        {/* Edges */}
        {edges.map((edge, i) => {
          const src = getPos(edge.source)
          const tgt = getPos(edge.target)
          const isAttack = edge.attack
          const dashOffset = isAttack ? -(animTick * 0.5) % 20 : 0
          return (
            <g key={i}>
              {/* Glow for attack edges */}
              {isAttack && (
                <line
                  x1={src.x} y1={src.y} x2={tgt.x} y2={tgt.y}
                  stroke="#ef4444" strokeWidth={4} strokeOpacity={0.3}
                  filter="url(#glow-red)"
                />
              )}
              <line
                x1={src.x} y1={src.y} x2={tgt.x} y2={tgt.y}
                stroke={isAttack ? '#ef4444' : edge.active ? '#334155' : '#1e293b'}
                strokeWidth={isAttack ? 2 : 1.5}
                strokeDasharray={isAttack ? '8 4' : '0'}
                strokeDashoffset={dashOffset}
                strokeOpacity={isAttack ? 0.9 : 0.6}
                markerEnd={`url(#arrow-${isAttack ? 'attack' : 'normal'})`}
              />
            </g>
          )
        })}

        {/* Nodes */}
        {nodes.map(node => {
          const { x, y } = getPos(node.id)
          const sc = STATUS_COLORS[node.status] || STATUS_COLORS.normal
          const isAttackNode = node.status === 'danger'
          const pulseR = 20 + (isAttackNode ? Math.sin(animTick * 0.12) * 4 : Math.sin(animTick * 0.06) * 2)
          const IconComp = NODE_ICONS[node.type] || Server
          const isFirewall = node.type === 'firewall'

          return (
            <g key={node.id} style={{ cursor: 'pointer' }}
              onMouseEnter={e => setTooltip({ node, x: e.clientX, y: e.clientY })}
              onMouseLeave={() => setTooltip(null)}>
              {/* Outer pulse ring */}
              <circle
                cx={x} cy={y} r={pulseR}
                fill="none"
                stroke={sc.ring}
                strokeWidth={1}
                strokeOpacity={isAttackNode ? 0.6 : 0.25}
                filter={isAttackNode ? 'url(#glow-red)' : undefined}
              />
              {/* Background circle */}
              <circle
                cx={x} cy={y} r={18}
                fill={sc.fill}
                stroke={sc.ring}
                strokeWidth={isFirewall ? 2.5 : 1.5}
                filter={isFirewall ? 'url(#glow-cyan)' : undefined}
              />
              {/* Icon as foreignObject */}
              <foreignObject x={x - 9} y={y - 9} width={18} height={18} style={{ pointerEvents: 'none' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 18, height: 18 }}>
                  <IconComp
                    size={12}
                    className={
                      node.status === 'danger'   ? 'text-danger' :
                      node.status === 'warning'  ? 'text-warn' :
                      node.status === 'isolated' ? 'text-info' :
                      node.type === 'firewall'   ? 'text-accent' :
                      node.type === 'attacker'   ? 'text-danger' :
                      'text-text-dim'
                    }
                  />
                </div>
              </foreignObject>
              {/* Label */}
              <text
                x={x} y={y + 30}
                textAnchor="middle"
                fontSize={9}
                fill="#64748b"
                fontFamily="'JetBrains Mono', monospace"
              >
                {node.label}
              </text>
            </g>
          )
        })}
      </svg>

      {/* Tooltip */}
      {tooltip && (
        <div
          className="absolute z-20 soc-panel border border-border rounded-lg p-3 text-xs pointer-events-none shadow-xl"
          style={{ left: tooltip.x + 10, top: tooltip.y - 60, maxWidth: 180 }}
        >
          <p className="text-text font-semibold mb-1">{tooltip.node.label}</p>
          <p className="text-muted">Type: <span className="text-text-dim">{tooltip.node.type}</span></p>
          <p className="text-muted">Status: <span className={
            tooltip.node.status === 'danger' ? 'text-danger' :
            tooltip.node.status === 'warning' ? 'text-warn' : 'text-safe'
          }>{tooltip.node.status}</span></p>
          {tooltip.node.ip && <p className="text-muted font-mono mt-1">{tooltip.node.ip}</p>}
        </div>
      )}

      {/* Legend */}
      <div className="absolute bottom-3 right-3 flex gap-3 text-[10px]">
        {[
          { color: 'bg-accent', label: 'Firewall' },
          { color: 'bg-warn', label: 'Warning' },
          { color: 'bg-danger', label: 'Under Attack' },
        ].map(({ color, label }) => (
          <div key={label} className="flex items-center gap-1">
            <span className={`w-2 h-2 rounded-full ${color}`} />
            <span className="text-muted">{label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
