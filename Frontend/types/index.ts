// ============================================================
// Rudra SOC — Shared type definitions
// ============================================================

export type ThreatLevel = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type AttackType =
  | 'SQL Injection'
  | 'XSS'
  | 'DDoS'
  | 'Port Scan'
  | 'Brute Force'
  | 'Malware C2'
  | 'Ransomware'
  | 'DNS Tunnel'
  | 'QUIC Abuse'
  | 'ARP Spoof'
  | 'Path Traversal'
  | 'RCE'
  | 'SSRF'
  | 'Botnet'
  | 'Zero-Day'

export interface AttackEvent {
  id: string
  timestamp: Date | string
  srcIp: string
  srcCountry: string
  srcLat: number
  srcLng: number
  dstIp: string
  dstCountry: string
  dstLat: number
  dstLng: number
  attackType: AttackType
  severity: ThreatLevel
  status: string
  protocol: string
  port: number
  payload?: string
  mlConfidence?: number
  ruleId?: string
  mitre?: string
}

export interface NetworkNode {
  id: string
  label: string
  type: 'internet' | 'router' | 'firewall' | 'server' | 'client' | 'iot' | 'attacker'
  ip?: string
  status: 'normal' | 'warning' | 'danger' | 'isolated'
  x?: number
  y?: number
}

export interface NetworkEdge {
  source: string
  target: string
  active: boolean
  attack?: boolean
}

export interface SecurityScore {
  overall: number
  idsScore: number
  ipsScore: number
  mlScore: number
  complianceScore: number
  threatIntelScore: number
}

export interface SystemStats {
  packetsPerSec: number
  blockedToday: number
  activeConnections: number
  threatsDetected: number
  engineStatus: 'online' | 'degraded' | 'offline'
  uptime: number
  cpuUsage: number
  memUsage: number
}

export interface ThreatIntelItem {
  id: string
  indicator: string
  type: string
  campaign: string
  lastSeen: string
  hits: number
  risk: ThreatLevel
}

export interface AutoRule {
  id: string
  name: string
  description: string
  condition: string
  action: string
  enabled: boolean
  triggerCount: number
  priority: 'high' | 'medium' | 'low'
}

export interface ForensicPacket {
  id: string
  timestamp: string
  srcIp: string
  dstIp: string
  protocol: string
  length: number
  payload?: string
  threat?: string
  flagged: boolean
  ttl?: number
}

export interface MitreTechnique {
  id: string
  name: string
  tactic: string
}

export interface AiAnalysis {
  threatName: string
  confidence: number
  iocMatches: number
  behaviorScore: number
  recommendations: string[]
  mitreTechniques?: MitreTechnique[]
  actors?: string[]
  summary?: string
  affectedHosts?: number
  campaignAge?: string
}

export interface IncidentTimelineEvent {
  id: string
  timestamp: string
  type: 'detection' | 'block' | 'alert' | 'mitigation' | 'escalation' | 'info'
  title: string
  description?: string
  severity?: ThreatLevel
}
