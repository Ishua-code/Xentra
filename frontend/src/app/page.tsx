'use client'

import { useState } from 'react'
import {
  Bell,
  CircleHelp,
  GitBranch,
  LayoutDashboard,
  Menu,
  Network,
  Search,
  Settings,
  ShieldAlert,
  Ticket,
  Users,
  X,
  Zap,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'

const navItems = [
  { label: 'Overview', icon: LayoutDashboard },
  { label: 'Findings', icon: ShieldAlert },
  { label: 'Identities', icon: Users },
  { label: 'Attack Graph', icon: Network },
  { label: 'Incidents', icon: Ticket },
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
          <p className="text-slate-500">Dashboard content will go here next.</p>
        </div>
      </main>
    </div>
  )
}