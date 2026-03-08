/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        bg: '#020617',
        panel: '#0f172a',
        border: '#1e293b',
        accent: '#06b6d4',
        danger: '#ef4444',
        warn: '#f59e0b',
        safe: '#10b981',
        info: '#3b82f6',
        muted: '#475569',
        text: '#e2e8f0',
        'text-dim': '#94a3b8',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'pulse-danger': 'pulse 1s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'spin-slow': 'spin 8s linear infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'scan': 'scan 3s linear infinite',
        'float': 'float 3s ease-in-out infinite',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px #06b6d4, 0 0 10px #06b6d4' },
          '100%': { boxShadow: '0 0 10px #06b6d4, 0 0 25px #06b6d4, 0 0 40px #06b6d4' },
        },
        scan: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-8px)' },
        },
      },
      backgroundImage: {
        'grid-pattern': "linear-gradient(rgba(6,182,212,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(6,182,212,0.03) 1px, transparent 1px)",
        'radial-glow': 'radial-gradient(ellipse at center, rgba(6,182,212,0.15), transparent 70%)',
      },
      backgroundSize: {
        'grid': '48px 48px',
      },
    },
  },
  plugins: [],
}
