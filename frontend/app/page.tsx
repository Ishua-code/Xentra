"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  Bell,
  CalendarDays,
  CircleHelp,
  Download,
  FileText,
  Filter,
  GitBranch,
  LayoutDashboard,
  LogOut,
  Menu,
  Network,
  Plus,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  UserRound,
  Users,
  X,
  Zap,
} from "lucide-react";
import {
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuth } from "@/lib/auth";
import api from "@/lib/api";

// ---------------------------------------------------------------------------
// Real API shapes (matching app/models/finding.py, ticket.py, identity.py)
// ---------------------------------------------------------------------------

interface ApiFinding {
  cve_id: string;
  host: string;
  owner: string;
  epss_score: number;
  identity_exposure_score: number;
  graph_proximity_score: number;
  betweenness_centrality: number;
  unified_risk_score: number;
  hops_to_domain_admin: number | null;
  attack_path: string[] | null;
}

interface ApiTicket {
  ticket_id: string;
  title: string;
  severity: string;
  cve_id: string;
  host: string;
  owner: string;
  status: string;
  recommended_actions: string[];
  created_at: string;
}

interface ApiIdentity {
  username: string;
  privilege_level: string;
  mfa_enabled: boolean;
  last_login_days_ago: number;
  owned_asset_ip: string;
}

interface DisplayFinding {
  cve: string;
  host: string;
  owner: string;
  epss: string;
  identity: number;
  severity: "Critical" | "High" | "Medium" | "Low";
  description: string;
  unifiedRiskScore: number;
  attackPath: string[] | null;
  hopsToDomainAdmin: number | null;
  ticket: ApiTicket | null;
}

const CVE_DESCRIPTIONS: Record<string, string> = {
  "CVE-2021-44228": "Remote code execution in Log4j allows unauthenticated attackers to execute arbitrary code on affected servers.",
  "CVE-2017-0144": "SMBv1 remote code execution vulnerability with known ransomware exploitation.",
  "CVE-2020-1472": "Zerologon elevation of privilege in Netlogon allows an attacker to impersonate a domain controller.",
  "CVE-2018-7600": "Drupalgeddon remote code execution affecting the public web tier.",
  "CVE-2021-34527": "PrintNightmare allows remote code execution through the Windows Print Spooler.",
  "CVE-2019-0708": "BlueKeep remote desktop services vulnerability.",
};

function severityFromScore(score: number): DisplayFinding["severity"] {
  if (score >= 0.7) return "Critical";
  if (score >= 0.5) return "High";
  if (score >= 0.3) return "Medium";
  return "Low";
}

function toDisplayFinding(f: ApiFinding, ticketsByCve: Map<string, ApiTicket>): DisplayFinding {
  return {
    cve: f.cve_id,
    host: f.host,
    owner: f.owner,
    epss: f.epss_score.toFixed(3),
    identity: Math.round(f.identity_exposure_score * 100),
    severity: severityFromScore(f.unified_risk_score),
    description: CVE_DESCRIPTIONS[f.cve_id] ?? "No description available for this CVE yet.",
    unifiedRiskScore: f.unified_risk_score,
    attackPath: f.attack_path,
    hopsToDomainAdmin: f.hops_to_domain_admin,
    ticket: ticketsByCve.get(f.cve_id) ?? null,
  };
}

const demoTrend = Array.from({ length: 30 }, (_, i) => ({
  day: i + 1,
  score: Math.round(82 - i * 0.34 + Math.sin(i / 2) * 2),
}));

const demoAssets = [
  { host: "dc-prod-01", criticality: "Critical", team: "Infrastructure", findings: 12 },
  { host: "payments-api-03", criticality: "Critical", team: "Payments", findings: 8 },
  { host: "finance-laptop-44", criticality: "High", team: "Finance IT", findings: 5 },
  { host: "legacy-web-02", criticality: "Medium", team: "Platform", findings: 3 },
  { host: "backup-node-07", criticality: "High", team: "Infrastructure", findings: 7 },
];

const alerts = [
  "Critical finding crossed EPSS threshold",
  "Scan completed on production-east",
  "Jira ticket XENTRA-241 created",
  "MFA policy drift detected in Finance",
  "Finding CVE-2019-0708 resolved",
  "New identity added to privileged group",
];

const navItems = [
  { label: "Overview", icon: LayoutDashboard },
  { label: "Vulnerabilities", icon: ShieldAlert },
  { label: "Identities", icon: Users },
  { label: "Attack Paths", icon: Network },
  { label: "Assets", icon: GitBranch },
  { label: "Reports", icon: FileText },
];

function severityClass(s: string) {
  return `severity-${s.toLowerCase()}`;
}

function useDashboardData() {
  const [findings, setFindings] = useState<DisplayFinding[]>([]);
  const [identityRisk, setIdentityRisk] = useState<{ name: string; risk: number }[]>([]);
  const [identityCount, setIdentityCount] = useState(0);
  const [openTickets, setOpenTickets] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const [findingsRes, ticketsRes, identitiesRes] = await Promise.all([
          api.get<ApiFinding[]>("/api/v1/findings"),
          api.get<ApiTicket[]>("/api/v1/tickets"),
          api.get<ApiIdentity[]>("/api/v1/identities"),
        ]);
        if (cancelled) return;

        const ticketsByCve = new Map(ticketsRes.data.map((t) => [t.cve_id, t]));
        const displayFindings = findingsRes.data
          .map((f) => toDisplayFinding(f, ticketsByCve))
          .sort((a, b) => b.unifiedRiskScore - a.unifiedRiskScore);

        const riskByOwner = new Map<string, number>();
        for (const f of findingsRes.data) {
          const current = riskByOwner.get(f.owner) ?? 0;
          riskByOwner.set(f.owner, Math.max(current, Math.round(f.identity_exposure_score * 100)));
        }
        const topIdentities = [...riskByOwner.entries()]
          .map(([name, risk]) => ({ name, risk }))
          .sort((a, b) => b.risk - a.risk)
          .slice(0, 3);

        setFindings(displayFindings);
        setIdentityRisk(topIdentities);
        setIdentityCount(identitiesRes.data.length);
        setOpenTickets(ticketsRes.data.filter((t) => t.status === "Open").length);
        setError(null);
      } catch {
        if (!cancelled) setError("Could not load live data from the backend.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, []);

  return { findings, identityRisk, identityCount, openTickets, loading, error };
}

function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <div className="logo-mark">
        <Shield className="size-4" />
      </div>
      <div>
        <p className="text-sm font-bold tracking-[.22em] text-white">XENTRA</p>
        <p className="text-[8px] tracking-[.18em] text-slate-500">THREAT FUSION</p>
      </div>
    </div>
  );
}

function Sparkline({
  color = "#60a5fa",
  points = [4, 7, 5, 9, 8, 12, 10],
}: {
  color?: string;
  points?: number[];
}) {
  return (
    <svg viewBox="0 0 80 24" className="sparkline" aria-hidden="true">
      <polyline
        points={points.map((p, i) => `${i * 13},${22 - p * 1.5}`).join(" ")}
        fill="none"
        stroke={color}
        strokeWidth="1.8"
      />
    </svg>
  );
}

function RiskRing({ score }: { score: number }) {
  const label = score >= 70 ? "HIGH RISK" : score >= 40 ? "MODERATE RISK" : "LOW RISK";
  return (
    <div className="risk-ring">
      <div>
        <strong>{score}</strong>
        <span>/100</span>
        <small>{label}</small>
      </div>
    </div>
  );
}

function AttackPath({ path }: { path: string[] | null }) {
  if (!path || path.length === 0) {
    return (
      <div className="attack-graph attack-graph-large flex items-center justify-center text-sm text-slate-500">
        No attack path recorded for this finding.
      </div>
    );
  }

  const nodeCount = path.length;
  const nodes = path.map((label, i) => {
    const left = `${8 + (i * 84) / Math.max(nodeCount - 1, 1)}%`;
    const top = i % 2 === 0 ? "45%" : "20%";
    const kind = i === 0 ? "node-user" : i === nodeCount - 1 ? "node-domain" : "node-pivot";
    return [kind, label, left, top] as const;
  });

  return (
    <div className="attack-graph attack-graph-large">
      <svg className="attack-lines" viewBox="0 0 760 300" preserveAspectRatio="none">
        <path d="M80 170 C180 60 220 80 310 145 S430 240 520 130 S630 70 700 115" />
      </svg>
      {nodes.map(([kind, label, left, top]) => (
        <div key={label}>
          <div className={`graph-node ${kind}`} style={{ left, top }}>
            {kind === "node-pivot" ? <Zap /> : kind === "node-domain" ? <Shield /> : <UserRound />}
          </div>
          <span className="graph-label" style={{ left, top: `calc(${top} + 12%)` }}>
            {label}
          </span>
        </div>
      ))}
    </div>
  );
}

function AppButton({
  children,
  onClick,
  variant = "outline",
}: {
  children: React.ReactNode;
  onClick?: () => void;
  variant?: "outline" | "default";
}) {
  return (
    <Button
      onClick={onClick}
      variant={variant}
      size="sm"
      className={
        variant === "default"
          ? "bg-blue-600 text-white hover:bg-blue-500"
          : "border-slate-700 bg-transparent text-slate-300 hover:bg-slate-800"
      }
    >
      {children}
    </Button>
  );
}

function Sidebar({
  active,
  setActive,
  sidebarOpen,
  setSidebarOpen,
  findingsCount,
}: {
  active: string;
  setActive: (label: string) => void;
  sidebarOpen: boolean;
  setSidebarOpen: (open: boolean) => void;
  findingsCount: number;
}) {
  const { username, logout } = useAuth();
  const initials = username ? username.slice(0, 2).toUpperCase() : "??";

  return (
    <aside className={`xentra-sidebar ${sidebarOpen ? "is-open" : ""}`}>
      <div className="px-5 py-5">
        <div className="flex items-center justify-between">
          <Logo />
          <button className="lg:hidden" onClick={() => setSidebarOpen(false)} aria-label="Close navigation">
            <X />
          </button>
        </div>
      </div>
      <div className="px-3 pt-2">
        <p className="eyebrow px-3 pb-2">Workspace</p>
        {navItems.map(({ label, icon: Icon }) => (
          <button
            key={label}
            onClick={() => {
              setActive(label);
              setSidebarOpen(false);
            }}
            className={`nav-item ${active === label ? "active" : ""}`}
          >
            <Icon />
            {label}
            {label === "Vulnerabilities" && (
              <span className="ml-auto text-[9px] text-slate-600">{findingsCount}</span>
            )}
          </button>
        ))}
        <p className="eyebrow px-3 pb-2 pt-6">System</p>
        <button onClick={() => setActive("Settings")} className={`nav-item ${active === "Settings" ? "active" : ""}`}>
          <Settings />
          Settings
        </button>
        <button className="nav-item">
          <CircleHelp />
          Help center
        </button>
      </div>
      <div className="sidebar-user">
        <Avatar className="size-8">
          <AvatarFallback className="bg-blue-500/20 text-xs text-blue-300">{initials}</AvatarFallback>
        </Avatar>
        <div className="min-w-0">
          <p className="truncate text-xs font-semibold text-white">{username ?? "Unknown user"}</p>
          <p className="truncate text-[10px] text-slate-500">Security Analyst</p>
        </div>
        <button className="icon-btn ml-auto" onClick={logout} aria-label="Log out" title="Log out">
          <LogOut className="size-4" />
        </button>
      </div>
    </aside>
  );
}

function TopBar({
  active,
  alertsOpen,
  setAlertsOpen,
  setSidebarOpen,
}: {
  active: string;
  alertsOpen: boolean;
  setAlertsOpen: (open: boolean) => void;
  setSidebarOpen: (open: boolean) => void;
}) {
  return (
    <header className="topbar">
      <button className="mr-1 lg:hidden" onClick={() => setSidebarOpen(true)} aria-label="Open navigation">
        <Menu />
      </button>
      <div className="min-w-0">
        <p className="eyebrow">Security operations / {active}</p>
        <h1>{active === "Overview" ? "Overview dashboard" : active}</h1>
      </div>
      <div className="ml-auto flex items-center gap-2">
        <div className="search-wrap hidden md:flex">
          <Search />
          <Input placeholder="Search workspace" />
        </div>
        <div className="relative">
          <button className="icon-btn" onClick={() => setAlertsOpen(!alertsOpen)} aria-label="Notifications">
            <Bell />
            <span className="notification-dot">4</span>
          </button>
          {alertsOpen && (
            <div className="alerts-dropdown">
              <p className="mb-3 text-xs font-semibold text-white">
                Notifications <span className="float-right text-[10px] text-blue-400">Mark all read</span>
              </p>
              {alerts.map((a, i) => (
                <div className="alert-item" key={a}>
                  <span className={`incident-dot severity-${i < 2 ? "critical" : "medium"}`} />
                  <div>
                    <p>{a}</p>
                    <small>{i + 2} min ago</small>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
        <AppButton variant="default">
          <Zap data-icon="inline-start" />
          Run new scan
        </AppButton>
      </div>
    </header>
  );
}

function PageIntro({ title, subtitle }: { title: string; subtitle: string }) {
  return (
    <div className="mb-5">
      <p className="eyebrow text-blue-400">Workspace</p>
      <h2 className="mt-1 text-xl font-semibold text-white">{title}</h2>
      <p className="mt-1 text-sm text-slate-500">{subtitle}</p>
    </div>
  );
}

function DemoBadge({ label = "DEMO DATA" }: { label?: string }) {
  return <span className="ml-2 rounded bg-slate-800 px-1.5 py-0.5 text-[9px] tracking-wide text-slate-400">{label}</span>;
}

function AssetTable() {
  return (
    <Card className="dashboard-card">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>
            Asset inventory
            <DemoBadge />
          </CardTitle>
          <AppButton variant="default">
            <Plus data-icon="inline-start" />
            Add asset
          </AppButton>
        </div>
        <p className="mt-1 text-[11px] text-slate-500">
          There is no /api/v1/assets endpoint yet -- this table shows placeholder data until one exists.
        </p>
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Host</TableHead>
              <TableHead>Criticality</TableHead>
              <TableHead>Owner team</TableHead>
              <TableHead>Open findings</TableHead>
              <TableHead>Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {demoAssets.map((a) => (
              <TableRow key={a.host}>
                <TableCell className="font-mono text-xs text-blue-300">{a.host}</TableCell>
                <TableCell>
                  <Badge className={severityClass(a.criticality)}>{a.criticality}</Badge>
                </TableCell>
                <TableCell>{a.team}</TableCell>
                <TableCell>{a.findings}</TableCell>
                <TableCell>
                  <span className="text-emerald-400">● Online</span>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

function Reports() {
  return (
    <div className="dashboard-content">
      <PageIntro title="Reports" subtitle="Generate analyst-ready security reports from your workspace data." />
      <div className="report-grid">
        {["Executive risk brief", "Vulnerability register", "Identity exposure report", "Compliance evidence"].map((r) => (
          <Card className="dashboard-card" key={r}>
            <CardContent className="p-5">
              <div className="report-icon">
                <FileText />
              </div>
              <h3 className="mt-4 text-sm font-semibold text-white">
                {r}
                <DemoBadge label="COMING SOON" />
              </h3>
              <p className="mt-1 text-xs text-slate-500">PDF · Report generation not built yet</p>
              <Button
                disabled
                size="sm"
                title="Report generation isn't built yet -- there's no backend endpoint for this."
                className="cursor-not-allowed border-slate-800 bg-transparent text-slate-600 opacity-60"
              >
                <Download data-icon="inline-start" />
                Generate report
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

function SettingsPage() {
  return (
    <div className="dashboard-content">
      <PageIntro title="Settings" subtitle="Manage workspace connections and notification routing." />
      <Card className="dashboard-card">
        <CardHeader>
          <CardTitle>Integrations</CardTitle>
        </CardHeader>
        <CardContent className="integration-grid">
          {["Slack", "Jira", "ServiceNow", "PagerDuty"].map((x) => (
            <div className="integration-card" key={x}>
              <div className="flex items-center gap-3">
                <div className="integration-logo">{x[0]}</div>
                <div>
                  <p className="text-sm font-semibold text-white">
                    {x}
                    <DemoBadge label="NOT CONNECTED" />
                  </p>
                  <p className="text-[10px] text-slate-500">Incident routing and alerts</p>
                </div>
              </div>
              <Button
                disabled
                size="sm"
                title="Integrations aren't wired up yet -- there's no backend endpoint for this."
                className="cursor-not-allowed border-slate-700 bg-transparent text-slate-600 opacity-60"
              >
                Connect
              </Button>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

function DetailPanel({ finding, onClose }: { finding: DisplayFinding; onClose: () => void }) {
  return (
    <div className="detail-overlay" onClick={onClose}>
      <aside className="detail-panel" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between border-b border-slate-800 pb-4">
          <div>
            <p className="eyebrow text-blue-400">Finding detail</p>
            <h2 className="mt-1 font-mono text-lg text-white">{finding.cve}</h2>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close detail">
            <X />
          </button>
        </div>
        <Badge className={`mt-4 ${severityClass(finding.severity)}`}>{finding.severity} severity</Badge>
        <p className="mt-4 text-sm leading-6 text-slate-300">{finding.description}</p>
        <div className="detail-stats">
          <div>
            <span>Unified risk</span>
            <strong>{Math.round(finding.unifiedRiskScore * 100)}</strong>
          </div>
          <div>
            <span>EPSS</span>
            <strong>{finding.epss}</strong>
          </div>
          <div>
            <span>Identity risk</span>
            <strong>{finding.identity}</strong>
          </div>
        </div>
        <h3 className="detail-heading">Attack path chain</h3>
        {finding.attackPath && finding.attackPath.length > 0 ? (
          <div className="chain">
            {finding.attackPath.map((step, i) => (
              <span key={step} style={{ display: "contents" }}>
                <span>{step}</span>
                {i < finding.attackPath!.length - 1 && <b>-&gt;</b>}
              </span>
            ))}
          </div>
        ) : (
          <p className="text-xs text-slate-500">No attack path recorded for this finding.</p>
        )}
        <h3 className="detail-heading">Ticket status</h3>
        {finding.ticket ? (
          <p className="text-sm text-slate-300">
            <span className="font-mono text-blue-300">{finding.ticket.ticket_id}</span> -- {finding.ticket.status}
          </p>
        ) : (
          <p className="text-xs text-slate-500">
            No ticket exists for this finding yet. Tickets are currently only created in bulk by
            <code className="mx-1 rounded bg-slate-800 px-1">POST /api/v1/correlate</code>
            -- there is no endpoint yet to create one for a single finding.
          </p>
        )}
        <h3 className="detail-heading">Remediation</h3>
        <label>
          Assign owner
          <Select defaultValue={finding.owner}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={finding.owner}>{finding.owner}</SelectItem>
            </SelectContent>
          </Select>
        </label>
        <label>
          Status
          <Select defaultValue={finding.ticket?.status ?? "none"}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="none">No ticket</SelectItem>
              <SelectItem value="Open">Open</SelectItem>
              <SelectItem value="In Progress">In Progress</SelectItem>
              <SelectItem value="Resolved">Resolved</SelectItem>
            </SelectContent>
          </Select>
        </label>
        <AppButton variant="default">Save remediation</AppButton>
      </aside>
    </div>
  );
}

// ---------------------------------------------------------------------------
// NEW: real Vulnerabilities page, wired to /api/v1/findings (via `findings`
// already fetched by useDashboardData -- no new API call needed)
// ---------------------------------------------------------------------------

function VulnerabilitiesContent({
  findings,
  setSelected,
}: {
  findings: DisplayFinding[];
  setSelected: (f: DisplayFinding | null) => void;
}) {
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");

  const filtered = useMemo(
    () =>
      findings
        .filter((f) => (severityFilter === "all" ? true : f.severity === severityFilter))
        .filter((f) =>
          [f.cve, f.host, f.owner].join(" ").toLowerCase().includes(query.toLowerCase())
        ),
    [findings, query, severityFilter]
  );

  const counts = useMemo(() => {
    const c = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    for (const f of findings) c[f.severity]++;
    return c;
  }, [findings]);

  return (
    <div className="dashboard-content">
      <PageIntro
        title="Vulnerabilities"
        subtitle="Every CVE correlated with exploitability (EPSS) and identity exposure, from live backend data."
      />

      <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
        {(["Critical", "High", "Medium", "Low"] as const).map((sev) => (
          <Card key={sev} className="dashboard-card">
            <CardContent className="p-4">
              <p className="text-[10px] uppercase tracking-wider text-slate-500">{sev}</p>
              <strong className="text-xl text-white">{counts[sev]}</strong>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card className="dashboard-card overflow-hidden">
        <CardHeader className="border-b border-slate-800/80 pb-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <CardTitle>All findings</CardTitle>
              <p className="mt-1 text-[11px] text-slate-500">Click a row to inspect the full attack chain.</p>
            </div>
            <div className="flex items-center gap-2">
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger className="w-[140px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All severities</SelectItem>
                  <SelectItem value="Critical">Critical</SelectItem>
                  <SelectItem value="High">High</SelectItem>
                  <SelectItem value="Medium">Medium</SelectItem>
                  <SelectItem value="Low">Low</SelectItem>
                </SelectContent>
              </Select>
              <div className="search-wrap table-search">
                <Search />
                <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search CVE, host, owner" />
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>CVE ID</TableHead>
                  <TableHead>Host</TableHead>
                  <TableHead>Owner</TableHead>
                  <TableHead>EPSS</TableHead>
                  <TableHead>Unified risk</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Ticket</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.length === 0 ? (
                  <TableRow>
                    <TableCell className="p-6 text-center text-sm text-slate-500">
                      No vulnerabilities match your filters.
                    </TableCell>
                  </TableRow>
                ) : (
                  filtered.map((f) => (
                    <TableRow key={f.cve} className="cursor-pointer" onClick={() => setSelected(f)}>
                      <TableCell className="font-mono text-xs text-blue-300">{f.cve}</TableCell>
                      <TableCell className="font-mono text-xs text-slate-400">{f.host}</TableCell>
                      <TableCell className="text-xs">{f.owner}</TableCell>
                      <TableCell className="font-mono text-xs">{f.epss}</TableCell>
                      <TableCell className="font-mono text-xs">{Math.round(f.unifiedRiskScore * 100)}</TableCell>
                      <TableCell>
                        <Badge className={severityClass(f.severity)}>{f.severity}</Badge>
                      </TableCell>
                      <TableCell className="text-xs">
                        {f.ticket ? (
                          <span className="text-blue-300">{f.ticket.ticket_id}</span>
                        ) : (
                          <span className="text-slate-500">No ticket</span>
                        )}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function OverviewContent({
  tab,
  setTab,
  query,
  setQuery,
  filterOpen,
  setFilterOpen,
  filtered,
  setSelected,
  identityRisk,
  identityCount,
  openTickets,
  riskScore,
}: {
  tab: string;
  setTab: (t: string) => void;
  query: string;
  setQuery: (q: string) => void;
  filterOpen: boolean;
  setFilterOpen: (o: boolean) => void;
  filtered: DisplayFinding[];
  setSelected: (f: DisplayFinding | null) => void;
  identityRisk: { name: string; risk: number }[];
  identityCount: number;
  openTickets: number;
  riskScore: number;
}) {
  return (
    <div className="dashboard-content">
      <div className="mb-5 flex items-end justify-between">
        <div>
          <p className="eyebrow text-blue-400">Live environment · Production</p>
          <h2 className="mt-1 text-xl font-semibold text-white">Good morning</h2>
        </div>
        <p className="hidden text-[11px] text-slate-500 sm:block">
          Last sync <span className="text-slate-300">just now</span>
        </p>
      </div>

      <div className="workspace-grid">
        <aside className="pulse-rail">
          <Card className="dashboard-card pulse-main">
            <CardContent className="flex flex-col items-center p-4">
              <p className="eyebrow self-start">Risk pulse</p>
              <RiskRing score={riskScore} />
              <p className="mt-1 text-center text-[10px] leading-4 text-slate-500">
                Based on {filtered.length} correlated finding{filtered.length === 1 ? "" : "s"}.
              </p>
            </CardContent>
          </Card>
          {(
            [
              ["Vulnerabilities", String(filtered.length), "#60a5fa"],
              ["Identities", String(identityCount), "#a78bfa"],
              ["Open incidents", String(openTickets).padStart(2, "0"), "#fbbf24"],
            ] as const
          ).map(([label, value, color], i) => (
            <div className="pulse-row" key={label}>
              <div>
                <p className="text-[10px] uppercase tracking-wider text-slate-500">{label}</p>
                <strong>{value}</strong>
                <span className={i === 0 ? "text-red-400" : "text-emerald-400"}>
                  {i === 0 ? <ArrowUpRight /> : <ArrowDownRight />}
                  live
                </span>
              </div>
              <Sparkline color={color} />
            </div>
          ))}
        </aside>

        <section className="workspace-center">
          <div className="tab-bar">
            {["Findings", "Attack Paths", "Assets", "Trends"].map((t) => (
              <button key={t} onClick={() => setTab(t)} className={tab === t ? "active" : ""}>
                {t}
              </button>
            ))}
            <button className="filter-trigger" onClick={() => setFilterOpen(!filterOpen)} aria-label="Open filters">
              <Filter />
            </button>
          </div>

          {filterOpen && (
            <div className="filter-panel">
              <p className="text-xs font-semibold text-white">Filter findings</p>
              <label>
                <input type="checkbox" defaultChecked /> Critical
              </label>
              <label>
                <input type="checkbox" defaultChecked /> High
              </label>
              <label>
                <input type="checkbox" /> Medium / Low
              </label>
              <div className="filter-fields">
                <Input placeholder="Owner search" />
                <Select defaultValue="all">
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All asset criticality</SelectItem>
                    <SelectItem value="critical">Critical only</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <p className="text-[10px] text-slate-500">
                <CalendarDays /> Last 30 days
              </p>
            </div>
          )}

          {tab === "Findings" && (
            <Card className="dashboard-card tab-panel overflow-hidden">
              <CardHeader className="border-b border-slate-800/80 pb-3">
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle>Prioritized findings</CardTitle>
                    <p className="mt-1 text-[11px] text-slate-500">Click any row to inspect the full attack chain.</p>
                  </div>
                  <div className="search-wrap table-search">
                    <Search />
                    <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter findings" />
                  </div>
                </div>
              </CardHeader>
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>CVE ID</TableHead>
                        <TableHead>Host</TableHead>
                        <TableHead>Owner</TableHead>
                        <TableHead>EPSS</TableHead>
                        <TableHead>Identity risk</TableHead>
                        <TableHead>Severity</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {filtered.length === 0 ? (
                        <TableRow>
                          <TableCell className="p-6 text-center text-sm text-slate-500">
                            No findings match. Run a correlation to populate this table.
                          </TableCell>
                        </TableRow>
                      ) : (
                        filtered.map((f) => (
                          <TableRow key={f.cve} className="cursor-pointer" onClick={() => setSelected(f)}>
                            <TableCell className="font-mono text-xs text-blue-300">{f.cve}</TableCell>
                            <TableCell className="font-mono text-xs text-slate-400">{f.host}</TableCell>
                            <TableCell className="text-xs">{f.owner}</TableCell>
                            <TableCell className="font-mono text-xs">{f.epss}</TableCell>
                            <TableCell>
                              <div className="flex items-center gap-2">
                                <div className="risk-track">
                                  <span style={{ width: `${f.identity}%` }} />
                                </div>
                                <span className="text-xs">{f.identity}</span>
                              </div>
                            </TableCell>
                            <TableCell>
                              <Badge className={severityClass(f.severity)}>{f.severity}</Badge>
                            </TableCell>
                          </TableRow>
                        ))
                      )}
                    </TableBody>
                  </Table>
                </div>
              </CardContent>
            </Card>
          )}

          {tab === "Attack Paths" && (
            <Card className="dashboard-card tab-panel">
              <CardHeader>
                <CardTitle>Privilege escalation graph</CardTitle>
                <p className="text-xs text-slate-500">
                  {filtered[0]
                    ? `Highest risk finding · ${filtered[0].cve} · ${filtered[0].hopsToDomainAdmin ?? "?"} hops to domain admin`
                    : "No findings to graph yet."}
                </p>
              </CardHeader>
              <CardContent>
                <AttackPath path={filtered[0]?.attackPath ?? null} />
              </CardContent>
            </Card>
          )}

          {tab === "Assets" && <AssetTable />}

          {tab === "Trends" && (
            <Card className="dashboard-card tab-panel">
              <CardHeader>
                <CardTitle>
                  Risk score trend
                  <DemoBadge />
                </CardTitle>
                <p className="text-xs text-slate-500">
                  There is no historical time-series endpoint yet -- this chart is placeholder data.
                </p>
              </CardHeader>
              <CardContent>
                <div className="h-[380px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={demoTrend}>
                      <XAxis dataKey="day" tick={{ fill: "#64748b", fontSize: 10 }} tickLine={false} axisLine={false} />
                      <YAxis domain={[60, 90]} tick={{ fill: "#64748b", fontSize: 10 }} tickLine={false} axisLine={false} />
                      <Tooltip contentStyle={{ background: "#111827", border: "1px solid #263247", fontSize: 11 }} />
                      <Line type="monotone" dataKey="score" stroke="#60a5fa" strokeWidth={2} dot={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>
          )}
        </section>

        <aside className="action-panel">
          <Card className="dashboard-card">
            <CardHeader className="pb-2">
              <CardTitle>Needs your attention</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-2">
              {filtered.slice(0, 3).map((f) => (
                <div className="attention-item" key={f.cve}>
                  <div className="flex items-center justify-between gap-2">
                    <Badge className={severityClass(f.severity)}>{f.severity}</Badge>
                    <span className="font-mono text-[10px] text-blue-300">{f.cve}</span>
                  </div>
                  <p>{f.description.slice(0, 58)}...</p>
                  {f.ticket ? (
                    <span className="ticket-link">
                      <span className="font-mono">{f.ticket.ticket_id}</span> · {f.ticket.status}
                    </span>
                  ) : (
                    <span className="ticket-link text-slate-500">No ticket yet</span>
                  )}
                </div>
              ))}
              {filtered.length === 0 && <p className="text-xs text-slate-500">Nothing needs attention right now.</p>}
            </CardContent>
          </Card>

          <Card className="dashboard-card">
            <CardHeader className="pb-2">
              <CardTitle>Recent activity</CardTitle>
              <DemoBadge />
            </CardHeader>
            <CardContent className="activity-feed">
              {[
                "Ticket XENTRA-241 created",
                "Finding CVE-2019-0708 resolved",
                "Production scan completed",
                "Alex joined Security Engineering",
              ].map((a, i) => (
                <div key={a}>
                  <span className="activity-line" />
                  <Activity />
                  <div>
                    <p>{a}</p>
                    <small>{i * 12 + 4} min ago</small>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card className="dashboard-card">
            <CardHeader className="pb-2">
              <CardTitle>Top risky identities</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              {identityRisk.length === 0 && <p className="text-xs text-slate-500">No identity data yet.</p>}
              {identityRisk.map((id) => (
                <div key={id.name}>
                  <div className="flex justify-between text-[11px]">
                    <span>{id.name}</span>
                    <span className="text-slate-500">{id.risk}</span>
                  </div>
                  <div className="mt-1 h-1 rounded bg-slate-800">
                    <div
                      className={`h-full rounded ${id.risk > 80 ? "bg-red-500" : "bg-orange-500"}`}
                      style={{ width: `${id.risk}%` }}
                    />
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </aside>
      </div>
    </div>
  );
}

function DashboardPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const active = searchParams.get("tab") || "Overview";

  const setActive = (label: string) => {
    router.push(`?tab=${encodeURIComponent(label)}`, { scroll: false });
  };

  const [tab, setTab] = useState("Findings");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<DisplayFinding | null>(null);
  const [filterOpen, setFilterOpen] = useState(false);
  const [alertsOpen, setAlertsOpen] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const { findings, identityRisk, identityCount, openTickets, loading, error } = useDashboardData();

  const filtered = useMemo(
    () =>
      findings.filter((f) =>
        [f.cve, f.host, f.owner, f.severity].join(" ").toLowerCase().includes(query.toLowerCase())
      ),
    [findings, query]
  );

  const riskScore = findings.length
    ? Math.round((findings.reduce((sum, f) => sum + f.unifiedRiskScore, 0) / findings.length) * 100)
    : 0;

  return (
    <div className="min-h-screen bg-[#080c14] text-slate-200">
      <Sidebar
        active={active}
        setActive={setActive}
        sidebarOpen={sidebarOpen}
        setSidebarOpen={setSidebarOpen}
        findingsCount={findings.length}
      />

      <main className="lg:pl-[224px]">
        <TopBar active={active} alertsOpen={alertsOpen} setAlertsOpen={setAlertsOpen} setSidebarOpen={setSidebarOpen} />

        {loading ? (
          <div className="dashboard-content">
            <p className="text-sm text-slate-500">Loading live data from the backend...</p>
          </div>
        ) : error ? (
          <div className="dashboard-content">
            <Card className="dashboard-card">
              <CardContent className="p-6 text-sm text-red-400">{error}</CardContent>
            </Card>
          </div>
        ) : active === "Overview" ? (
          <OverviewContent
            tab={tab}
            setTab={setTab}
            query={query}
            setQuery={setQuery}
            filterOpen={filterOpen}
            setFilterOpen={setFilterOpen}
            filtered={filtered}
            setSelected={setSelected}
            identityRisk={identityRisk}
            identityCount={identityCount}
            openTickets={openTickets}
            riskScore={riskScore}
          />
        ) : active === "Vulnerabilities" ? (
          <VulnerabilitiesContent findings={findings} setSelected={setSelected} />
        ) : active === "Assets" ? (
          <div className="dashboard-content">
            <PageIntro title="Asset inventory" subtitle="Hosts, ownership, and exposure across production." />
            <AssetTable />
          </div>
        ) : active === "Reports" ? (
          <Reports />
        ) : active === "Settings" ? (
          <SettingsPage />
        ) : (
          <div className="dashboard-content">
            <PageIntro title={active} subtitle="This section is not built yet." />
            <Card className="dashboard-card">
              <CardContent className="p-8 text-sm text-slate-400">
                {active} isn't wired up to a backend endpoint yet -- this page is a placeholder until that work is done.
              </CardContent>
            </Card>
          </div>
        )}
      </main>

      {selected && <DetailPanel finding={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

export default function Page() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-[#080c14]" />}>
      <DashboardPage />
    </Suspense>
  );
}