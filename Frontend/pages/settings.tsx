'use client'
import Head from 'next/head'
import { useState } from 'react'
import { motion } from 'framer-motion'
import { Settings, Save, RotateCcw, Shield, Cpu, Globe, Zap } from 'lucide-react'

const ENGINE_CONFIGS = [
  { id: 'ids', name: 'IDS Engine', icon: Shield, description: 'Intrusion Detection System rules and sensitivity' },
  { id: 'ips', name: 'IPS Engine', icon: Zap,    description: 'Active blocking thresholds and auto-response' },
  { id: 'ml',  name: 'ML Engine',  icon: Cpu,    description: 'AI detection models and training parameters' },
  { id: 'ti',  name: 'Threat Intel', icon: Globe, description: 'Feed sources and IOC update intervals' },
]

type ConfigKey = 'sensitivity' | 'blockThreshold' | 'mlConfidenceMin' | 'honeypotEnabled' | 'zeroTrustMode' | 'logLevel'

interface Cfg {
  sensitivity: number
  blockThreshold: number
  mlConfidenceMin: number
  honeypotEnabled: boolean
  zeroTrustMode: boolean
  logLevel: string
}

const DEFAULT_CFG: Cfg = {
  sensitivity: 75,
  blockThreshold: 85,
  mlConfidenceMin: 70,
  honeypotEnabled: true,
  zeroTrustMode: false,
  logLevel: 'info',
}

export default function SettingsPage() {
  const [cfg, setCfg] = useState<Cfg>(DEFAULT_CFG)
  const [saved, setSaved] = useState(false)

  const save = () => {
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <>
      <Head><title>Settings — Rudras SOC</title></Head>
      <div className="flex flex-col gap-4 h-full overflow-y-auto">
        <div className="flex items-center gap-2 shrink-0">
          <Settings size={18} className="text-muted" />
          <h1 className="text-lg font-bold text-text">System Settings</h1>
          <div className="ml-auto flex gap-2">
            <button
              onClick={() => setCfg(DEFAULT_CFG)}
              className="flex items-center gap-1.5 text-xs border border-border px-3 py-1.5 rounded-lg text-muted hover:border-accent hover:text-accent"
            >
              <RotateCcw size={11} /> Reset
            </button>
            <button
              onClick={save}
              className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg transition-all ${
                saved ? 'bg-safe/20 text-safe border border-safe/30' : 'bg-accent/20 text-accent border border-accent/30 hover:bg-accent/30'
              }`}
            >
              <Save size={11} /> {saved ? 'Saved!' : 'Save Changes'}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Engine toggles */}
          <div className="soc-panel border border-border rounded-xl p-4">
            <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-4">Engine Modules</p>
            <div className="space-y-3">
              {ENGINE_CONFIGS.map(({ id, name, icon: Icon, description }) => (
                <div key={id} className="flex items-center gap-3 p-3 bg-bg rounded-xl border border-border/50">
                  <Icon size={16} className="text-accent shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-semibold text-text">{name}</p>
                    <p className="text-[10px] text-muted truncate">{description}</p>
                  </div>
                  <div className="w-10 h-5 bg-safe/20 border border-safe/40 rounded-full flex items-center px-0.5 cursor-pointer shrink-0">
                    <div className="w-4 h-4 bg-safe rounded-full ml-auto" />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Detection tuning */}
          <div className="soc-panel border border-border rounded-xl p-4">
            <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-4">Detection Tuning</p>
            <div className="space-y-5">
              {[
                { key: 'sensitivity'    as ConfigKey, label: 'IDS Sensitivity',        unit: '%' },
                { key: 'blockThreshold' as ConfigKey, label: 'Auto-Block Threshold',   unit: '%' },
                { key: 'mlConfidenceMin'as ConfigKey, label: 'ML Confidence Min',      unit: '%' },
              ].map(({ key, label, unit }) => {
                const val = cfg[key] as number
                return (
                  <div key={key}>
                    <div className="flex justify-between text-[10px] mb-1.5">
                      <span className="text-muted">{label}</span>
                      <span className="font-mono text-accent">{val}{unit}</span>
                    </div>
                    <input
                      type="range" min={0} max={100} step={5}
                      value={val}
                      onChange={e => setCfg(c => ({ ...c, [key]: Number(e.target.value) }))}
                      className="w-full accent-cyan-500 cursor-pointer"
                    />
                  </div>
                )
              })}
            </div>
          </div>

          {/* Feature flags */}
          <div className="soc-panel border border-border rounded-xl p-4">
            <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-4">Feature Flags</p>
            <div className="space-y-3">
              {[
                { key: 'honeypotEnabled' as ConfigKey, label: 'Adaptive Honeypot', desc: 'Deploy dynamic decoys for attacker tracking' },
                { key: 'zeroTrustMode'   as ConfigKey, label: 'Zero Trust Mode',   desc: 'Enforce strict identity verification on all flows' },
              ].map(({ key, label, desc }) => {
                const val = cfg[key] as boolean
                return (
                  <div key={key} className="flex items-center gap-3 p-3 bg-bg rounded-xl border border-border/50">
                    <div className="flex-1">
                      <p className="text-xs font-semibold text-text">{label}</p>
                      <p className="text-[10px] text-muted">{desc}</p>
                    </div>
                    <button
                      onClick={() => setCfg(c => ({ ...c, [key]: !val }))}
                      className={`w-10 h-5 rounded-full flex items-center px-0.5 transition-colors border ${
                        val ? 'bg-safe/20 border-safe/40' : 'bg-bg border-border'
                      }`}
                    >
                      <motion.div
                        animate={{ x: val ? 20 : 0 }}
                        transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                        className={`w-4 h-4 rounded-full ${val ? 'bg-safe' : 'bg-muted'}`}
                      />
                    </button>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Log level */}
          <div className="soc-panel border border-border rounded-xl p-4">
            <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-4">Logging</p>
            <div className="space-y-3">
              <div>
                <p className="text-[10px] text-muted mb-2">Log Level</p>
                <div className="grid grid-cols-4 gap-2">
                  {['debug', 'info', 'warn', 'error'].map(lvl => (
                    <button
                      key={lvl}
                      onClick={() => setCfg(c => ({ ...c, logLevel: lvl }))}
                      className={`py-2 rounded-lg text-xs font-mono border transition-colors capitalize ${
                        cfg.logLevel === lvl
                          ? 'bg-accent/20 text-accent border-accent/40'
                          : 'bg-bg border-border text-muted hover:border-accent/40'
                      }`}
                    >
                      {lvl}
                    </button>
                  ))}
                </div>
              </div>
              <div className="p-3 bg-bg rounded-xl border border-border/50">
                <p className="text-[10px] text-muted mb-1">Log Path</p>
                <p className="font-mono text-xs text-text-dim">./logs/Rudras.log.&#123;date&#125;</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  )
}
