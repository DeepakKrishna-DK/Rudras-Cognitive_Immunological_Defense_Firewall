'use client'
import React from 'react'
import Image from 'next/image'
import Sidebar from './Sidebar'
import TopBar from './TopBar'
import mainBg from '@/main.jpeg'

interface Props {
  children: React.ReactNode
  alertCount?: number
}

export default function Layout({ children, alertCount = 0 }: Props) {
  return (
    <div className="flex h-screen overflow-hidden relative" style={{ backgroundColor: '#020617' }}>

      {/* ── Futuristic layered background ────────────────────── */}
      <div className="fixed inset-0 z-0 pointer-events-none select-none" aria-hidden="true">

        {/* Layer 1 — main.jpeg full image, centered, complete view */}
        <Image
          src={mainBg}
          alt=""
          fill
          priority
          className="object-contain object-center"
          style={{
            opacity: 0.50,
            mixBlendMode: 'normal',
            filter: 'brightness(0.80)',
          }}
        />

        {/* Layer 2 — very light vignette only at the far edges */}
        <div
          className="absolute inset-0"
          style={{
            background:
              'radial-gradient(ellipse 130% 130% at 50% 50%, transparent 40%, rgba(2,6,23,0.55) 75%, rgba(2,6,23,0.85) 100%)',
          }}
        />

        {/* Layer 3 — radial cyan aurora at top + violet accent bottom-right */}
        <div
          className="absolute inset-0"
          style={{
            background:
              'radial-gradient(ellipse 80% 40% at 50% 0%, rgba(6,182,212,0.14) 0%, transparent 65%), ' +
              'radial-gradient(ellipse 50% 35% at 95% 95%, rgba(99,102,241,0.10) 0%, transparent 60%)',
          }}
        />

        {/* Layer 4 — cyan dot grid */}
        <div className="absolute inset-0 soc-grid-bg" style={{ opacity: 0.6 }} />

        {/* Layer 5 — animated horizontal scan line */}
        <div className="scanline" />

        {/* Layer 6 — top edge neon line */}
        <div
          className="absolute top-0 left-0 right-0 h-px"
          style={{
            background:
              'linear-gradient(90deg, transparent 0%, rgba(6,182,212,0.6) 30%, rgba(6,182,212,0.9) 50%, rgba(6,182,212,0.6) 70%, transparent 100%)',
            boxShadow: '0 0 12px rgba(6,182,212,0.5)',
          }}
        />

        {/* Layer 7 — bottom edge subtle glow */}
        <div
          className="absolute bottom-0 left-0 right-0 h-px"
          style={{
            background:
              'linear-gradient(90deg, transparent, rgba(99,102,241,0.4) 50%, transparent)',
          }}
        />
      </div>

      {/* ── App content above background layers ─────────────── */}
      <div className="relative z-10 flex h-full w-full overflow-hidden">
        <Sidebar />
        <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
          <TopBar alertCount={alertCount} />
          <main className="flex-1 overflow-auto">
            {children}
          </main>
        </div>
      </div>
    </div>
  )
}
