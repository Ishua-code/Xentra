'use client'

import { useState } from 'react'
import {
  AlertTriangle,
  ArrowUpRight,
  Bell,
  CircleHelp,
  Filter,
  GitBranch,
  KeyRound,
  LayoutDashboard,
  Menu,
  Network,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  Ticket,
  UserRound,
  Users,
  X,
  Zap,
} from 'lucide-react'
import { Bar, BarChart, CartesianGrid, Cell, LabelList, Tooltip, XAxis, YAxis } from 'recharts'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { ChartContainer, ChartTooltipContent } from '@/components/ui/chart'
import { Input } from '@/components/ui/input'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'

const navItems = [
  { label: 'Overview', icon: LayoutDashboard },
  { label: 'Findings', icon: ShieldAlert },
  { label: 'Identities', icon: Users },
  { label: 'Attack Graph', icon: Network },
  { label: 'Incidents', icon: Ticket },
]

// TEMPORARY placeholder data — Branch 5 will replace this with real API calls
// to GET /api/v1/epss/{cve_id}, POST /api/v1/correlate, etc.
const findings = [
  { cve: 'CVE-2021-44228', score: 0.95, severity: 'Critical' },
  { cve: 'CVE-2017-0144', score: 0.91, severity: 'Critical' },
  { cve: 'CVE-2020-1472', score: 0.84, severity: 'High' },
  { cve: 'CVE-2018-7600', score: 0.72, severity: 'High' },
  { cve: 'CVE-2021-34527', score: 0.67, severity: 'High' },
  { cve: 'CVE-2019-0708', score: 0.55, severity: 'Medium' },
  { cve: 'CVE-2017-5638', score: 0.48, severity: 'Medium' },
  { cve: 'CVE-2015-4000', score: 0.41, severity: 'Low' },
]

const metrics = [
  { label: 'Vulnerabilities detected', value: '1,284', delta: '+12.5%', note: 'vs last 7 days', icon: ShieldAlert, tone: 'blue' },
  { label: 'Identities monitored', value: '8,492', delta: '+4.8%', note: 'vs last 7 days', icon: Users, tone: 'violet' },
  { label: 'Critical risk findings', value: '23', delta: '-8.2%', note: 'vs last 7 days', icon: AlertTriangle, tone: 'red' },
  { label: 'Open incidents', value: '07', delta: '+2', note: 'since yesterday', icon: Ticket, tone: 'amber' },
]

function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <div className="logo-mark">
        <GitBranch className="size-4" />
      </div>
      <span className="text-sm font-bold tracking-tight text-white">XENTRA</span>
    </div>
  )
}

function AttackPath() {
  return (
    <div className="attack-graph">
      <svg className="attack-lines" viewBox="0 0 360 190" preserveAspectRatio="none" aria-hidden="true">
        <defs>
          <marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
            <path d="M0,0 L0,6 L7,3 z" fill="#64748b" />
          </marker>
        </defs>
        <path d="M48 126 C98 78, 112 78, 158 109 S218 145, 254 92 S300 68, 325 74" markerEnd="url(#arrow)" />
      </svg>
      <div className="graph-node node-user" style={{ left: '8%', top: '57%' }}>
        <UserRound />
      </div>
      <div className="graph-node node-pivot" style={{ left: '40%', top: '48%' }}>
        <KeyRound />
      </div>
      <div className="graph-node node-domain" style={{ left: '83%', top: '38%' }}>
        <Shield />
      </div>
      <span className="graph-label" style={{ left: '3%', top: '76%' }}>weak_user</span>
      <span className="graph-label" style={{ left: '34%', top: '64%' }}>admin_pivot</span>
      <span className="graph-label label-domain" style={{ left: '73%', top: '57%' }}>DOMAIN_ADMIN</span>
    </div>
  )
}

export default function Page() {
  const [active, setActive] = useState('Overview')
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <div className="min-h-screen bg-[#0a0e17] text-slate-200">
      <aside className={`xentra-sidebar ${sidebarOpen ? 'is-open' : ''}`}>
        <div className="flex items-center justify-between px-6 py-6">
          <Logo />
          <button className="lg:hidden" onClick={() => setSidebarOpen(false)} aria-label="Close navigation">
            <X />
          </button>
        </div>
        <div className="px-3 pt-5">
          <p className="eyebrow px-3 pb-3">Workspace</p>
          {navItems.map(({ label, icon: Icon }) => (
            <button
              key={label}
              onClick={() => {
                setActive(label)
                setSidebarOpen(false)
              }}
              className={`nav-item ${active === label ? 'active' : ''}`}
            >
              <Icon />
              {label}
              {label === 'Incidents' && (
                <span className="ml-auto rounded bg-red-500/15 px-1.5 py-0.5 text-[10px] font-bold text-red-400">4</span>
              )}
            </button>
          ))}
          <p className="eyebrow px-3 pb-3 pt-7">System</p>
          <button className="nav-item">
            <Settings />
            Settings
          </button>
          <button className="nav-item">
            <CircleHelp />
            Help center
          </button>
        </div>
        <div className="sidebar-user">
          <Avatar className="size-9">
            <AvatarFallback className="bg-blue-500/20 text-blue-300">MP</AvatarFallback>
          </Avatar>
          <div className="min-w-0">
            <p className="truncate text-xs font-semibold text-white">Maya Patel</p>
            <p className="truncate text-[11px] text-slate-500">Security Analyst</p>
          </div>
          <div className="ml-auto size-2 rounded-full bg-emerald-400" />
        </div>
      </aside>

      <main className="lg:pl-[248px]">
        <header className="topbar">
          <button className="mr-3 lg:hidden" onClick={() => setSidebarOpen(true)} aria-label="Open navigation">
            <Menu />
          </button>
          <div className="min-w-0">
            <p className="eyebrow">Security operations / {active}</p>
            <h1>{active === 'Overview' ? 'Overview dashboard' : active}</h1>
          </div>
          <div className="ml-auto flex items-center gap-3">
            <div className="search-wrap hidden md:flex">
              <Search />
              <Input placeholder="Search findings, identities..." />
            </div>
            <button className="icon-btn relative" aria-label="Notifications">
              <Bell />
              <span className="notification-dot">4</span>
            </button>
            <Button className="hidden bg-blue-600 text-white shadow-lg shadow-blue-950/40 hover:bg-blue-500 sm:flex">
              <Zap className="mr-1.5 size-4" />
              Run new scan
            </Button>
          </div>
        </header>

        <div className="dashboard-content">
          <div className="mb-7 flex items-end justify-between">
            <div>
              <p className="eyebrow text-blue-400">Live environment · Production</p>
              <h2 className="mt-1 text-2xl font-semibold tracking-tight text-white">Good morning, Maya</h2>
              <p className="mt-1 text-sm text-slate-500">Here&apos;s what needs your attention today.</p>
            </div>
            <p className="hidden text-xs text-slate-500 sm:block">
              Last sync <span className="text-slate-300">2 min ago</span>
            </p>
          </div>

          <section className="metrics-grid">
            {metrics.map(({ label, value, delta, note, icon: Icon, tone }) => (
              <Card key={label} className="metric-card">
                <CardContent className="p-5">
                  <div className="flex items-start justify-between">
                    <div className={`metric-icon ${tone}`}>
                      <Icon />
                    </div>
                    <ArrowUpRight className={`size-4 ${tone === 'red' ? 'text-emerald-400' : 'text-blue-400'}`} />
                  </div>
                  <p className="mt-5 text-[11px] font-medium uppercase tracking-[0.12em] text-slate-500">{label}</p>
                  <div className="mt-1 flex items-baseline gap-2">
                    <span className="text-3xl font-semibold tracking-tight text-white">{value}</span>
                    <span className={`text-xs font-semibold ${tone === 'red' ? 'text-emerald-400' : 'text-blue-400'}`}>{delta}</span>
                  </div>
                  <p className="mt-1 text-[11px] text-slate-600">{note}</p>
                </CardContent>
              </Card>
            ))}
          </section>

          <section className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1.65fr)_minmax(320px,0.85fr)]">
            <Card className="dashboard-card">
              <CardHeader className="flex-row items-start justify-between space-y-0 pb-2">
                <div>
                  <CardTitle>
                    Unified risk score <span className="font-normal text-slate-500">· top findings</span>
                  </CardTitle>
                  <p className="mt-1 text-xs text-slate-500">Calculated from exploitability, identity privilege, and blast radius</p>
                </div>
                <button className="icon-btn">
                  <Filter />
                </button>
              </CardHeader>
              <CardContent>
                <ChartContainer config={{ score: { label: 'Risk score', color: 'var(--chart-1)' } }} className="h-[285px] w-full">
                  <BarChart data={findings} layout="vertical" margin={{ top: 8, right: 36, left: 4, bottom: 0 }} barCategoryGap={8}>
                    <CartesianGrid horizontal={false} stroke="#202a3b" />
                    <XAxis type="number" domain={[0, 1]} ticks={[0, 0.25, 0.5, 0.75, 1]} tickLine={false} axisLine={false} tick={{ fill: '#64748b', fontSize: 10 }} />
                    <YAxis dataKey="cve" type="category" width={108} tickLine={false} axisLine={false} tick={{ fill: '#cbd5e1', fontSize: 11, fontFamily: 'ui-monospace' }} />
                    <Tooltip cursor={{ fill: '#172033' }} content={<ChartTooltipContent hideLabel />} />
                    <Bar dataKey="score" radius={[0, 4, 4, 0]}>
                      <LabelList dataKey="score" position="right" formatter={(v: number) => v.toFixed(2)} fill="#94a3b8" fontSize={10} />
                      {findings.map((entry) => (
                        <Cell
                          key={entry.cve}
                          fill={entry.severity === 'Critical' ? '#ef4444' : entry.severity === 'High' ? '#f97316' : entry.severity === 'Medium' ? '#eab308' : '#22c55e'}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ChartContainer>
                <div className="mt-2 flex justify-end gap-4 text-[10px] text-slate-500">
                  <span><i className="legend-dot bg-red-500" /> Critical</span>
                  <span><i className="legend-dot bg-orange-500" /> High</span>
                  <span><i className="legend-dot bg-yellow-500" /> Medium</span>
                  <span><i className="legend-dot bg-emerald-500" /> Low</span>
                </div>
              </CardContent>
            </Card>

            <Card className="dashboard-card">
              <CardHeader className="pb-0">
                <div className="flex items-center justify-between">
                  <CardTitle>Live attack path</CardTitle>
                  <span className="live-pill">
                    <span />LIVE
                  </span>
                </div>
                <p className="mt-1 text-xs text-slate-500">Highest confidence route to privilege</p>
              </CardHeader>
              <CardContent>
                <AttackPath />
                <div className="mt-4 flex items-end justify-between border-t border-slate-800 pt-4">
                  <div>
                    <p className="text-2xl font-semibold text-white">3 hops</p>
                    <p className="text-xs text-slate-500">to domain admin</p>
                  </div>
                  <Button variant="outline" size="sm" className="border-slate-700 bg-transparent text-slate-300 hover:bg-slate-800">
                    View full graph <ArrowUpRight className="ml-1.5 size-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          </section>
        </div>
      </main>
    </div>
  )
}