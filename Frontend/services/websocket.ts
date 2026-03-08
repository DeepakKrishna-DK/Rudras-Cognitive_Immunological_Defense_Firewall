// ============================================================
// Rudra SOC — WebSocket service (connects to Rust backend)
// Falls back to mock data simulation when server is offline
// ============================================================

import { generateAttackEvent } from './mockData'
import type { AttackEvent } from '@/types'

type EventHandler = (event: AttackEvent) => void

class RudraSocketService {
  private handlers: EventHandler[] = []
  private interval: ReturnType<typeof setInterval> | null = null
  private connected = false

  connect(url = 'ws://localhost:7443/ws/events') {
    if (typeof window === 'undefined') return
    // Try real WS first, fall back to simulation
    try {
      const ws = new WebSocket(url)
      ws.onopen = () => { this.connected = true }
      ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data) as AttackEvent
          data.timestamp = new Date(data.timestamp)
          this.handlers.forEach(h => h(data))
        } catch { /* ignore parse errors */ }
      }
      ws.onerror = () => { this.startSimulation() }
      ws.onclose = () => { this.connected = false; this.startSimulation() }
    } catch {
      this.startSimulation()
    }
  }

  private startSimulation() {
    if (this.interval) return
    // Emit a new attack event every 1.5–4 seconds
    const schedule = () => {
      this.interval = setTimeout(() => {
        const ev = generateAttackEvent()
        this.handlers.forEach(h => h(ev))
        schedule()
      }, 1500 + Math.random() * 2500)
    }
    schedule()
  }

  onEvent(handler: EventHandler) {
    this.handlers.push(handler)
    return () => { this.handlers = this.handlers.filter(h => h !== handler) }
  }

  disconnect() {
    if (this.interval) { clearTimeout(this.interval as unknown as number); this.interval = null }
    this.handlers = []
  }

  isConnected() { return this.connected }
}

export const rudraSocket = new RudraSocketService()
