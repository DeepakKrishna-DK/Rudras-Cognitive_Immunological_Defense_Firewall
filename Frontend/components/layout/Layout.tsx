'use client'
import React from 'react'
import Sidebar from './Sidebar'
import TopBar from './TopBar'

interface Props {
  children: React.ReactNode
  alertCount?: number
}

export default function Layout({ children, alertCount = 0 }: Props) {
  return (
    <div className="flex h-screen overflow-hidden bg-bg soc-grid-bg">
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <TopBar alertCount={alertCount} />
        <main className="flex-1 overflow-auto">
          {children}
        </main>
      </div>
    </div>
  )
}
