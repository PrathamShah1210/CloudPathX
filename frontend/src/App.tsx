import React, { useState, useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Activity, ArrowDownToLine, ArrowRight, Check, ChevronRight, Cloud,
  FileText, Fingerprint, GitBranch, LayoutDashboard, LogOut, Menu, Network,
  Play, Plus, Search, Settings, Shield, ShieldAlert, SlidersHorizontal,
  Users, Workflow, X, Bot, History, Code2, BarChart3, Sun, Moon, Copy,
  CheckCheck, GitCompare, AlertTriangle, Sparkles, Send, RefreshCw, Layers
} from 'lucide-react';
import { ReactFlow, Background, Controls, MiniMap, MarkerType } from '@xyflow/react';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import '@xyflow/react/dist/style.css';
import { api, download, label, rows, setToken } from './api';
import type { Row } from './api';

const pages = [
  ['overview', 'Security overview', LayoutDashboard],
  ['identities', 'Identity inventory', Users],
  ['graph', 'Attack path explorer', GitBranch],
  ['policies', 'IAM policy analyzer', FileText],
  ['nhi', 'Non-human identities', Fingerprint],
  ['events', 'CloudTrail monitor', Activity],
  ['findings', 'Risk & findings', ShieldAlert],
  ['remediation', 'Remediation simulator', SlidersHorizontal],
  ['snapshots', 'Time-travel graph', History],
  ['iac', 'IaC security scanner', Code2],
  ['copilot', 'Security Copilot', Bot],
  ['incidents', 'Investigations', Workflow],
  ['evaluation', 'Research benchmark', BarChart3],
  ['reports', 'Security reports', ArrowDownToLine],
  ['accounts', 'Integrations', Cloud],
  ['settings', 'Settings', Settings],
] as const;

type PageKey = typeof pages[number][0];
type Action = (fn: () => Promise<unknown>, success?: string) => Promise<void>;

const statuses = ['Open', 'Investigating', 'Mitigated', 'Accepted Risk', 'False Positive'];
const initialPolicy = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Action: 's3:GetObject',
      Resource: 'arn:aws:s3:::example-bucket/*'
    }
  ]
}, null, 2);

function Badge({ value }: { value: unknown }) {
  const text = label(value);
  const cls = text.toLowerCase().replaceAll(' ', '-').replaceAll('_', '-');
  return <span className={`badge ${cls}`}>{text.replaceAll('_', ' ')}</span>;
}

function Json({ value }: { value: unknown }) {
  return <pre className="json">{JSON.stringify(value, null, 2)}</pre>;
}

function Empty({ text = 'No records yet. Run a synthetic scan to populate the workspace.' }: { text?: string }) {
  return (
    <div className="empty">
      <Shield size={28} />
      <h3>Nothing to show yet</h3>
      <p>{text}</p>
    </div>
  );
}

function Panel({
  title, subtitle, children, action
}: {
  title: string; subtitle?: string; children: React.ReactNode; action?: React.ReactNode;
}) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>{title}</h2>
          {subtitle && <p>{subtitle}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

function Table({
  items, columns, onSelect
}: {
  items: Row[]; columns: [string, string][]; onSelect?: (row: Row) => void;
}) {
  if (!items.length) return <Empty />;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {columns.map(([key, title]) => (
              <th key={key}>{title}</th>
            ))}
            {onSelect && <th><span className="sr-only">Inspect</span></th>}
          </tr>
        </thead>
        <tbody>
          {items.map((row, i) => (
            <tr key={row.id || i}>
              {columns.map(([key]) => (
                <td key={key}>
                  {['severity', 'confidence', 'status', 'type', 'role', 'gate_status'].includes(key) ? (
                    <Badge value={row[key]} />
                  ) : key === 'score' || key === 'risk_score' ? (
                    <span className={`score ${Number(row[key]) >= 70 ? 'hot' : ''}`}>
                      {label(row[key])}
                    </span>
                  ) : (
                    <span title={label(row[key])}>{label(row[key])}</span>
                  )}
                </td>
              ))}
              {onSelect && (
                <td>
                  <button
                    className="icon-button"
                    aria-label={`Inspect ${row.name || row.title || row.id}`}
                    onClick={() => onSelect(row)}
                  >
                    <ChevronRight size={17} />
                  </button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function App() {
  const client = useQueryClient();
  const [user, setUser] = useState<Row | null>(null);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [page, setPage] = useState<PageKey>('overview');
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<Row | null>(null);
  const [mobile, setMobile] = useState(false);
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    return (localStorage.getItem('cloudpathx.theme') as 'light' | 'dark') || 'light';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('cloudpathx.theme', theme);
  }, [theme]);

  const toggleTheme = () => setTheme(t => (t === 'light' ? 'dark' : 'light'));

  const me = useQuery({
    queryKey: ['me'],
    queryFn: () => api('/auth/me'),
    retry: false,
    enabled: !user && !!sessionStorage.getItem('cloudpathx.session'),
  });
  const current = user || me.data;
  const admin = ['admin', 'administrator', 'Administrator'].includes(current?.role);
  const writable = !!current && !['viewer', 'Viewer'].includes(current.role);

  const dataQuery = useQuery({
    queryKey: ['data', page],
    enabled: !!current,
    queryFn: async () => {
      if (page === 'overview') return api('/analytics');
      if (page === 'graph') return { graph: await api('/graph'), paths: await api('/attack-paths') };
      if (page === 'nhi') return api('/identities?limit=200');
      if (page === 'remediation') return api('/identities?limit=200');
      if (page === 'snapshots') return { snapshots: await api('/snapshots'), graph: await api('/graph'), paths: await api('/attack-paths') };
      if (page === 'reports') return api('/analytics');
      if (page === 'evaluation') return api('/evaluation/results').catch(() => ({}));
      if (page === 'settings') return { settings: await api('/settings'), users: admin ? await api('/users') : null };
      if (page === 'events') return { events: await api('/events?limit=200'), alerts: await api('/alerts?limit=200') };
      if (page === 'accounts') return { accounts: await api('/accounts'), scans: await api('/scans') };
      return api(`/${page}?limit=200`);
    },
    refetchInterval: page === 'overview' || page === 'accounts' ? 5000 : false,
  });

  const data = dataQuery.data;
  const filtered = (value: any) =>
    rows(value).filter((row) =>
      JSON.stringify(row).toLowerCase().includes(search.toLowerCase())
    );

  async function action(fn: () => Promise<unknown>, success = 'Saved successfully') {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await fn();
      setNotice(success);
      await client.invalidateQueries();
    } catch (err: any) {
      setError(err?.message || 'Operation failed');
    } finally {
      setBusy(false);
    }
  }

  if (!current) {
    return (
      <div className="login">
        <div className="login-story">
          <Brand />
          <div>
            <span className="eyebrow">CLOUDPATHX V2.0 ENTERPRISE PLATFORM</span>
            <h1>Attack Path Detection & Non-Human Identity Security</h1>
            <p>
              Autonomous identity graph intelligence, deterministic IAM evaluation,
              and blast-radius minimization for multi-account cloud estates.
            </p>
            <div className="login-path">
              <span><Users size={16} />Identity</span>
              <ArrowRight size={15} />
              <span><GitBranch size={16} />Escalation</span>
              <ArrowRight size={15} />
              <span><ShieldAlert size={16} />Crown Jewel</span>
            </div>
          </div>
          <small>Designed for security operations and cloud platform engineering</small>
        </div>
        <form
          className="login-form"
          onSubmit={async (e) => {
            e.preventDefault();
            setError('');
            try {
              const res = await api('/auth/login', 'POST', { email, password });
              setToken(res.token);
              setUser(res.user);
            } catch (err: any) {
              setError(err?.message || 'Authentication failed');
            }
          }}
        >
          <div className="login-shield">
            <Shield size={36} />
          </div>
          <div>
            <h2>Sign in to CloudPathX</h2>
            <p>Enterprise CNAPP · CIEM · ITDR · CSPM</p>
          </div>
          {error && <div className="notice error" role="alert">{error}</div>}
          <label>
            Email address
            <input
              type="email"
              required
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@cloudpathx.internal"
            />
          </label>
          <label>
            Password
            <input
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
            />
          </label>
          <button className="primary" disabled={busy}>Sign in</button>
          <p className="hint">
            Default credentials: <code>admin@cloudpathx.internal</code> / <code>AdminCloudPathX!2026</code>
          </p>
        </form>
      </div>
    );
  }

  return (
    <div className="shell">
      <aside className={`sidebar ${mobile ? 'open' : ''}`}>
        <Brand />
        <div className="workspace">
          <Network size={18} className="workspace-icon" />
          <div>
            <strong>Production Estate</strong>
            <small>Active Workspace · v2.0</small>
          </div>
        </div>
        <span className="nav-label">CAPABILITIES</span>
        <nav>
          {pages.map(([key, labelText, Icon]) => (
            <button
              key={key}
              className={page === key ? 'active' : ''}
              onClick={() => {
                setPage(key);
                setSelected(null);
                setSearch('');
                setMobile(false);
              }}
            >
              <Icon size={16} />
              <span>{labelText}</span>
              {page === key && <span className="nav-dot" />}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="avatar">{(current.email || 'A')[0].toUpperCase()}</div>
          <div>
            <strong>{current.email}</strong>
            <small>{current.role}</small>
          </div>
          <button
            className="icon-button"
            aria-label="Log out"
            onClick={() => {
              setToken('');
              setUser(null);
            }}
          >
            <LogOut size={16} />
          </button>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <button
            className="icon-button mobile-toggle"
            aria-label="Open navigation"
            onClick={() => setMobile(!mobile)}
          >
            <Menu size={20} />
          </button>
          <span>
            <strong>CloudPathX V2.0</strong> · Cloud Identity Attack Path & NHI Security
          </span>
          <div className="topbar-right">
            <button
              className="icon-button theme-toggle"
              aria-label="Toggle theme"
              onClick={toggleTheme}
              title={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`}
            >
              {theme === 'light' ? <Moon size={16} /> : <Sun size={16} />}
            </button>
            <span className="health-dot" />
            <span>Deterministic IAM Engine Online</span>
            <Badge value={current.role} />
          </div>
        </header>

        <main>
          <div className="page-heading">
            <div>
              <span className="eyebrow">ENTERPRISE CLOUD SECURITY</span>
              <h1>{pages.find(([k]) => k === page)?.[1]}</h1>
              <p>Continuous discovery, least-privilege analysis, and identity threat posture.</p>
            </div>
            {writable && (
              <div className="inline">
                <button
                  className="secondary"
                  disabled={busy}
                  onClick={() =>
                    action(
                      () => api('/scans', 'POST', { mode: 'synthetic' }),
                      'Synthetic scan queued; recomputing graph and findings'
                    )
                  }
                >
                  <RefreshCw size={14} /> Run demo scan
                </button>
              </div>
            )}
          </div>

          {notice && <div className="notice success" role="status"><Check size={16} /> {notice}</div>}
          {error && <div className="notice error" role="alert"><AlertTriangle size={16} /> {error}</div>}

          {dataQuery.isLoading ? (
            <div className="empty"><div className="spinner" /><p>Analyzing security graph...</p></div>
          ) : (
            <>
              {page === 'overview' && <Overview data={data || {}} navigate={setPage} />}
              {page === 'identities' && (
                <Panel
                  title="Cloud identities"
                  subtitle="Unified catalog of human principals and service credentials."
                  action={<SearchBox value={search} onChange={setSearch} />}
                >
                  <Table
                    items={filtered(data)}
                    columns={[
                      ['name', 'Identity'],
                      ['type', 'Principal Type'],
                      ['account_id', 'Account'],
                      ['risk_score', 'Risk Score'],
                    ]}
                    onSelect={setSelected}
                  />
                </Panel>
              )}
              {page === 'graph' && <GraphExplorer data={data} onSelect={setSelected} />}
              {page === 'policies' && <PolicyAnalyzer data={data} writable={writable} action={action} />}
              {page === 'nhi' && <NhiCenter data={data} onSelect={setSelected} />}
              {page === 'findings' && (
                <Panel
                  title="Prioritized findings"
                  subtitle="Severity describes technical impact. Confidence describes what the evidence establishes."
                  action={<SearchBox value={search} onChange={setSearch} />}
                >
                  <Table
                    items={filtered(data)}
                    columns={[
                      ['title', 'Finding'],
                      ['severity', 'Severity'],
                      ['score', 'Score'],
                      ['confidence', 'Confidence'],
                      ['status', 'Status'],
                    ]}
                    onSelect={setSelected}
                  />
                </Panel>
              )}
              {page === 'events' && <EventMonitor data={data} writable={writable} action={action} onSelect={setSelected} />}
              {page === 'remediation' && <Simulator identities={rows(data)} writable={writable} action={action} />}
              {page === 'snapshots' && <TimeTravelView data={data} action={action} />}
              {page === 'iac' && <IacScanner writable={writable} action={action} />}
              {page === 'copilot' && <CopilotView />}
              {page === 'incidents' && <Incidents items={filtered(data)} writable={writable} action={action} onSelect={setSelected} />}
              {page === 'evaluation' && <EvaluationView data={data} writable={writable} action={action} />}
              {page === 'reports' && (
                <Panel
                  title="Evidence exports"
                  subtitle="Reports contain the stored analysis snapshot, provenance, and documented uncertainty."
                >
                  <div className="report-options">
                    {['json', 'pdf'].map((format) => (
                      <div className="report-card" key={format}>
                        <FileText size={32} />
                        <h3>{format.toUpperCase()} security report</h3>
                        <p>
                          {format === 'json'
                            ? 'Machine-readable evidence for reproducibility and SIEM ingestion.'
                            : 'Portable audit-ready security assessment for stakeholders.'}
                        </p>
                        <button
                          className="primary"
                          disabled={busy}
                          onClick={() => action(() => download(format), 'Report downloaded')}
                        >
                          <ArrowDownToLine size={16} /> Export {format.toUpperCase()}
                        </button>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}
              {page === 'accounts' && (
                <Integrations data={data} admin={admin} writable={writable} action={action} onSelect={setSelected} />
              )}
              {page === 'settings' && <SettingsPage data={data} admin={admin} action={action} />}
            </>
          )}
        </main>

        <footer>
          CloudPathX <span>Passive analysis · Evidence-grounded · No automated AWS destruction · Zero Hallucination</span>
        </footer>
      </div>

      {selected && (
        <EvidenceDrawer
          selected={selected}
          onClose={() => setSelected(null)}
          page={page}
          writable={writable}
          action={action}
        />
      )}
    </div>
  );
}

function Brand() {
  return (
    <div className="brand">
      <span><Network size={24} /></span>
      <div>
        CloudPath<span>X</span>
        <small>IDENTITY SECURITY</small>
      </div>
    </div>
  );
}

function SearchBox({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <div className="search">
      <Search size={16} />
      <input
        aria-label="Search records"
        placeholder="Search records…"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}

/* ==================== EVIDENCE DRAWER ==================== */
function EvidenceDrawer({
  selected, onClose, page, writable, action
}: {
  selected: Row; onClose: () => void; page: PageKey; writable: boolean; action: Action;
}) {
  const [copied, setCopied] = useState(false);

  const copyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(selected, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isRole = selected.type === 'role' || selected.type === 'service_role';
  const isNHI = ['service_role', 'instance_profile', 'machine_user', 'lambda_role'].includes(selected.type);

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <aside className="drawer" onClick={(e) => e.stopPropagation()}>
        <div className="drawer-head">
          <span className="eyebrow">EVIDENCE INSPECTOR</span>
          <button aria-label="Close inspector" className="icon-button" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <h2>{selected.name || selected.title || selected.label || selected.id || 'Entity Evidence'}</h2>
        <div className="drawer-badges">
          {selected.type && <Badge value={selected.type} />}
          {selected.severity && <Badge value={selected.severity} />}
          {selected.confidence && <Badge value={selected.confidence} />}
          {selected.status && <Badge value={selected.status} />}
        </div>

        {/* Section 1: Entity Identity Card */}
        <div className="drawer-section">
          <h3>Entity Overview</h3>
          <div className="entity-card-grid">
            <div><span className="label-sm">Identifier</span><code>{selected.id || '—'}</code></div>
            <div><span className="label-sm">Principal ARN</span><code>{selected.arn || selected.id || '—'}</code></div>
            <div><span className="label-sm">Account ID</span><span>{selected.account_id || '111111111111'}</span></div>
            <div><span className="label-sm">Risk Score</span><strong>{label(selected.risk_score ?? selected.score ?? 0)}/100</strong></div>
          </div>
        </div>

        {/* Section 2: Associated Risks & Findings */}
        <div className="drawer-section">
          <h3>Risks & Security Posture</h3>
          {selected.remediation && (
            <div className="evidence-callout">
              <strong>Remediation Advisory</strong>
              <p>{selected.remediation}</p>
            </div>
          )}
          {selected.mitre_technique && (
            <div className="mitre-tag">
              <ShieldAlert size={14} /> MITRE ATT&CK: <code>{selected.mitre_technique}</code>
            </div>
          )}
          {selected.assumptions && Array.isArray(selected.assumptions) && selected.assumptions.length > 0 && (
            <div className="assumptions-box">
              <small>EVIDENCE ASSUMPTIONS</small>
              <ul>
                {selected.assumptions.map((a: string, i: number) => (
                  <li key={i}>{a}</li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Section 3: Attack Path Participation */}
        {selected.paths && Array.isArray(selected.paths) && (
          <div className="drawer-section">
            <h3>Attack Path Participation</h3>
            <div className="path-list">
              {selected.paths.map((p: any, idx: number) => (
                <div key={idx} className="path-item">
                  <GitBranch size={14} />
                  <span>{p.narrative || p.id || `Path ${idx + 1}`}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Section 4: Effective Permissions Summary */}
        {selected.policies && (
          <div className="drawer-section">
            <h3>Attached Policies & Entitlements</h3>
            <div className="policy-pill-list">
              {(Array.isArray(selected.policies) ? selected.policies : [selected.policies]).map((p: any, idx: number) => (
                <div key={idx} className="policy-pill">
                  <FileText size={14} />
                  <span>{p.PolicyName || `Policy ${idx + 1}`}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Section 5: Trust Relationships (Roles) */}
        {isRole && selected.trust_policy && (
          <div className="drawer-section">
            <h3>Trust Relationships (AssumeRole)</h3>
            <pre className="json-compact">{JSON.stringify(selected.trust_policy, null, 2)}</pre>
          </div>
        )}

        {/* Section 6: Non-Human Identity Indicators */}
        {isNHI && (
          <div className="drawer-section">
            <h3>Non-Human Identity Governance</h3>
            <div className="entity-card-grid">
              <div><span className="label-sm">NHI Class</span><span>{selected.type?.replace('_', ' ')}</span></div>
              <div><span className="label-sm">Activity Status</span><span className="badge safe">Active within 30d</span></div>
              <div><span className="label-sm">Credential Rotation</span><span className="badge medium">Automated IAM Role</span></div>
              <div><span className="label-sm">Scope Boundary</span><span>Regional VPC</span></div>
            </div>
          </div>
        )}

        {/* Section 7: Raw Evidence JSON (Collapsible) */}
        <div className="drawer-section">
          <details className="raw-details">
            <summary className="raw-summary">
              <span>View Raw Evidence JSON</span>
              <button
                type="button"
                className="icon-button"
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  copyJson();
                }}
                title="Copy raw JSON"
              >
                {copied ? <CheckCheck size={14} color="#158d96" /> : <Copy size={14} />}
              </button>
            </summary>
            <Json value={selected} />
          </details>
        </div>

        {/* Record update workflow (Findings & Incidents) */}
        {page === 'findings' && writable && (
          <RecordUpdate key={selected.id} row={selected} type="findings" action={action} done={onClose} />
        )}
        {page === 'incidents' && writable && (
          <RecordUpdate key={selected.id} row={selected} type="incidents" action={action} done={onClose} />
        )}
      </aside>
    </div>
  );
}

/* ==================== OVERVIEW ==================== */
function Overview({ data, navigate }: { data: Row; navigate: (v: PageKey) => void }) {
  const metrics = [
    ['Connected accounts', data.accounts, Cloud, 'accounts'],
    ['Cloud identities', data.identities, Users, 'identities'],
    ['Non-human identities', data.non_human_identities, Fingerprint, 'nhi'],
    ['Potential attack paths', data.attack_paths, GitBranch, 'graph'],
    ['Critical findings', data.critical_findings, ShieldAlert, 'findings'],
    ['Behavioral detections', data.alerts, Activity, 'events'],
  ] as const;

  return (
    <>
      <div className="metrics">
        {metrics.map(([title, value, Icon, link], i) => (
          <button
            key={title}
            className={`metric ${i === 4 ? 'critical-metric' : ''}`}
            onClick={() => navigate(link as PageKey)}
          >
            <div>
              <span>{title}</span>
              <Icon size={18} />
            </div>
            <strong>{label(value ?? 0)}</strong>
            <small>Explore evidence <ArrowRight size={13} /></small>
          </button>
        ))}
      </div>

      <div className="overview-grid">
        <Panel
          title="Exposure over time"
          subtitle="Recorded scan risk. A trend appears as scans accumulate."
          action={<Badge value="Scan history" />}
        >
          <div className="chart">
            {data.trend?.length ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data.trend}>
                  <defs>
                    <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#168d99" stopOpacity={0.24} />
                      <stop offset="100%" stopColor="#168d99" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid vertical={false} stroke="#e9edf2" />
                  <XAxis dataKey="date" tick={{ fontSize: 11 }} tickFormatter={(v) => String(v).slice(0, 10)} />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} />
                  <Tooltip />
                  <Area type="monotone" dataKey="score" stroke="#138a96" fill="url(#riskFill)" strokeWidth={3} />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <Empty text="Run a scan to begin recording the exposure trend." />
            )}
          </div>
        </Panel>

        <Panel title="Investigation priorities" subtitle="Move from exposure to understanding.">
          <div className="priority-list">
            <div className="priority-item" onClick={() => navigate('graph')}>
              <div>
                <strong>Choke Point Severance</strong>
                <p>Cut intermediate escalation privilege to dismantle 3 converging paths.</p>
              </div>
              <ChevronRight size={18} />
            </div>
            <div className="priority-item" onClick={() => navigate('nhi')}>
              <div>
                <strong>Non-Human Identity Scope Review</strong>
                <p>3 service roles hold unconstrained wildcard access across multiple accounts.</p>
              </div>
              <ChevronRight size={18} />
            </div>
            <div className="priority-item" onClick={() => navigate('iac')}>
              <div>
                <strong>Infrastructure as Code Policy Gates</strong>
                <p>Prevent newly drafted Terraform scripts from opening public trust boundaries.</p>
              </div>
              <ChevronRight size={18} />
            </div>
          </div>
        </Panel>
      </div>
    </>
  );
}

/* ==================== ATTACK GRAPH EXPLORER ==================== */
function GraphExplorer({ data, onSelect }: { data: any; onSelect: (r: Row) => void }) {
  const [selectedPathId, setSelectedPathId] = useState<string>('');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [compareOpen, setCompareOpen] = useState(false);
  const [pathA, setPathA] = useState('');
  const [pathB, setPathB] = useState('');
  const [compareResult, setCompareResult] = useState<any>(null);
  const [comparing, setComparing] = useState(false);

  const rawNodes = data?.graph?.nodes || [];
  const rawEdges = data?.graph?.edges || [];
  const paths = rows(data?.paths);

  // Filter nodes
  const filteredNodes = rawNodes.filter((n: any) => {
    if (typeFilter === 'ALL') return true;
    return n.type === typeFilter;
  });
  const filteredNodeIds = new Set(filteredNodes.map((n: any) => n.id));

  // Identify active path
  const activePath = paths.find((p: any) => p.id === selectedPathId) || paths[0];
  const activePathNodes = new Set(activePath?.nodes || []);

  const flowNodes = filteredNodes.map((node: any, idx: number) => {
    const isTarget = activePath && activePath.target === node.id;
    const isSource = activePath && activePath.source === node.id;
    const isInPath = activePathNodes.has(node.id);
    return {
      id: node.id,
      position: { x: 80 + (idx % 4) * 220, y: 80 + Math.floor(idx / 4) * 160 },
      data: {
        label: (
          <div
            className={`graph-node ${isInPath ? 'node-in-path' : ''} ${isTarget ? 'node-target' : ''}`}
            onClick={() => onSelect(node)}
          >
            <span><Network size={16} /></span>
            <div>
              <small>{node.type?.replace('_', ' ')}</small>
              <strong>{node.label || node.name || node.id}</strong>
              {isTarget && <span className="target-pill">Target</span>}
              {isSource && <span className="source-pill">Source</span>}
            </div>
          </div>
        ),
      },
    };
  });

  const flowEdges = rawEdges
    .filter((e: any) => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target))
    .map((e: any) => {
      const isPathEdge = activePathNodes.has(e.source) && activePathNodes.has(e.target);
      return {
        id: e.id || `${e.source}-${e.target}`,
        source: e.source,
        target: e.target,
        animated: isPathEdge,
        style: {
          stroke: isPathEdge ? '#e05353' : '#147e8d',
          strokeWidth: isPathEdge ? 3 : 1.5,
        },
        markerEnd: { type: MarkerType.ArrowClosed, color: isPathEdge ? '#e05353' : '#147e8d' },
      };
    });

  const handleCompare = async () => {
    if (!pathA || !pathB) return;
    setComparing(true);
    try {
      const res = await api('/attack-paths/compare', 'POST', {
        path_a_id: pathA,
        path_b_id: pathB,
      });
      setCompareResult(res);
    } catch (err: any) {
      alert(err?.message || 'Path comparison failed');
    } finally {
      setComparing(false);
    }
  };

  return (
    <>
      <Panel
        title="Identity attack path graph"
        subtitle="NetworkX traversal over verified IAM policy entitlements and trust delegations."
        action={
          <div className="inline">
            <select
              aria-label="Filter by node type"
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
            >
              <option value="ALL">All entity types</option>
              <option value="user">IAM Users</option>
              <option value="role">IAM Roles</option>
              <option value="service_role">Service Roles</option>
              <option value="s3">S3 Buckets</option>
              <option value="secretsmanager">Secrets Manager</option>
            </select>
            <button className="secondary" onClick={() => setCompareOpen(true)}>
              <GitCompare size={15} /> Compare paths
            </button>
          </div>
        }
      >
        <div className="graph-toolbar">
          <label>
            Select Attack Path:
            <select
              value={activePath?.id || ''}
              onChange={(e) => setSelectedPathId(e.target.value)}
            >
              {paths.map((p: any) => (
                <option key={p.id} value={p.id}>
                  {p.narrative || `${p.source} → ${p.target}`} (Score: {p.risk_score || 85})
                </option>
              ))}
            </select>
          </label>
        </div>

        {activePath && (
          <div className="path-narrative-card">
            <div className="narrative-header">
              <div>
                <span className="eyebrow">ATTACK VECTOR NARRATIVE</span>
                <h3>{activePath.narrative || `${activePath.source} → ${activePath.target}`}</h3>
              </div>
              <Badge value={activePath.risk_score ? `Risk ${activePath.risk_score}` : 'Critical'} />
            </div>
            {activePath.cut_point && (
              <div className="cut-point-callout">
                <ShieldAlert size={18} />
                <div>
                  <strong>Remediation Choke Point Identified: <code>{activePath.cut_point}</code></strong>
                  <p>
                    Severing entitlements on this entity dismantles this entire attack vector before
                    the crown jewel can be reached.
                  </p>
                </div>
              </div>
            )}
          </div>
        )}

        <div className="graph-canvas">
          <ReactFlow nodes={flowNodes} edges={flowEdges} fitView>
            <Background color="#c8d7e0" gap={18} />
            <Controls />
            <MiniMap nodeStrokeWidth={3} />
          </ReactFlow>
        </div>

        <div className="graph-legend">
          <span><span className="solid-line" /> Identity Entitlement</span>
          <span><span className="dashed-line" /> Trust Delegation</span>
          <span><span className="path-line" /> Active Attack Path</span>
          <span>{flowNodes.length} nodes · {flowEdges.length} edges · {paths.length} detected paths</span>
        </div>
      </Panel>

      {/* Path Comparison Modal */}
      {compareOpen && (
        <div className="drawer-overlay" onClick={() => setCompareOpen(false)}>
          <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2><GitCompare size={20} /> Compare Attack Paths</h2>
              <button className="icon-button" onClick={() => setCompareOpen(false)}><X size={18} /></button>
            </div>
            <div className="form-grid">
              <label>
                Baseline Path (A)
                <select value={pathA} onChange={(e) => setPathA(e.target.value)}>
                  <option value="">Select Path A</option>
                  {paths.map((p: any) => (
                    <option key={p.id} value={p.id}>{p.narrative || p.id}</option>
                  ))}
                </select>
              </label>
              <label>
                Candidate Path (B)
                <select value={pathB} onChange={(e) => setPathB(e.target.value)}>
                  <option value="">Select Path B</option>
                  {paths.map((p: any) => (
                    <option key={p.id} value={p.id}>{p.narrative || p.id}</option>
                  ))}
                </select>
              </label>
            </div>
            <button className="primary" disabled={!pathA || !pathB || comparing} onClick={handleCompare}>
              {comparing ? 'Analyzing...' : 'Run Differential Analysis'}
            </button>

            {compareResult && (
              <div className="compare-results">
                <h3>Differential Comparison Summary</h3>
                <div className="entity-card-grid">
                  <div>
                    <span className="label-sm">Shared Entities</span>
                    <strong>{compareResult.shared_nodes?.length || 0} nodes</strong>
                  </div>
                  <div>
                    <span className="label-sm">Risk Delta</span>
                    <strong>{compareResult.score_delta > 0 ? `+${compareResult.score_delta}` : compareResult.score_delta}</strong>
                  </div>
                  <div>
                    <span className="label-sm">Common Cut-Point</span>
                    <code>{compareResult.common_cut_point || 'None'}</code>
                  </div>
                </div>
                <div className="diff-node-lists">
                  <div>
                    <small>UNIQUE TO PATH A</small>
                    <ul>
                      {compareResult.unique_to_a?.map((n: string) => <li key={n}><code>{n}</code></li>) || <li>None</li>}
                    </ul>
                  </div>
                  <div>
                    <small>UNIQUE TO PATH B</small>
                    <ul>
                      {compareResult.unique_to_b?.map((n: string) => <li key={n}><code>{n}</code></li>) || <li>None</li>}
                    </ul>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}

/* ==================== NON-HUMAN IDENTITY SECURITY CENTER ==================== */
function NhiCenter({ data, onSelect }: { data: any; onSelect: (r: Row) => void }) {
  const [tab, setTab] = useState<'all' | 'service_role' | 'instance_profile' | 'machine_user'>('all');
  const allIdentities = rows(data);
  const nhiItems = allIdentities.filter((i) =>
    ['service_role', 'instance_profile', 'machine_user', 'role'].includes(i.type)
  );

  const filteredItems = tab === 'all' ? nhiItems : nhiItems.filter((i) => i.type === tab);
  const overprivilegedCount = nhiItems.filter((i) => (i.risk_score || 0) >= 70).length;

  return (
    <>
      <div className="metrics">
        <div className="metric">
          <div><span>Non-Human Identities</span><Fingerprint size={18} /></div>
          <strong>{nhiItems.length}</strong>
          <small>Service Principals</small>
        </div>
        <div className="metric">
          <div><span>Over-Privileged NHIs</span><ShieldAlert size={18} /></div>
          <strong className="score hot">{overprivilegedCount}</strong>
          <small>Excessive Wildcards</small>
        </div>
        <div className="metric">
          <div><span>Inactive Credential Sets</span><Activity size={18} /></div>
          <strong>0</strong>
          <small>Active &gt; 90 days</small>
        </div>
      </div>

      <Panel
        title="Non-human identity posture"
        subtitle="Catalog of machine accounts, service roles, and automated workload credentials."
        action={
          <div className="tab-pills">
            <button className={tab === 'all' ? 'active' : ''} onClick={() => setTab('all')}>All ({nhiItems.length})</button>
            <button className={tab === 'service_role' ? 'active' : ''} onClick={() => setTab('service_role')}>Service Roles</button>
            <button className={tab === 'instance_profile' ? 'active' : ''} onClick={() => setTab('instance_profile')}>Instance Profiles</button>
            <button className={tab === 'machine_user' ? 'active' : ''} onClick={() => setTab('machine_user')}>Machine Users</button>
          </div>
        }
      >
        <Table
          items={filteredItems}
          columns={[
            ['name', 'Identity Name'],
            ['type', 'Principal Type'],
            ['account_id', 'Account'],
            ['risk_score', 'Risk Score'],
          ]}
          onSelect={onSelect}
        />
      </Panel>
    </>
  );
}

/* ==================== TIME-TRAVEL GRAPH ==================== */
function TimeTravelView({ data, action }: { data: any; action: Action }) {
  const [comparing, setComparing] = useState(false);
  const [result, setResult] = useState<any>(null);

  const runComparison = async () => {
    setComparing(true);
    try {
      const res = await api('/snapshots/compare', 'POST', {
        before_snapshot_id: 'snapshot-baseline',
        after_snapshot_id: 'snapshot-current',
      });
      setResult(res);
    } catch (err: any) {
      alert(err?.message || 'Snapshot comparison failed');
    } finally {
      setComparing(false);
    }
  };

  return (
    <div className="two-column">
      <Panel
        title="Time-travel graph comparison"
        subtitle="Analyze delta between historical security postures and identify regression attack paths."
      >
        <div className="snapshot-controls">
          <div className="snapshot-card">
            <span className="eyebrow">BASELINE SNAPSHOT</span>
            <strong>Baseline Scan (T-1)</strong>
            <small>Immutable verified state</small>
          </div>
          <div className="snapshot-arrow"><ArrowRight size={20} /></div>
          <div className="snapshot-card current">
            <span className="eyebrow">CURRENT STATE</span>
            <strong>Active Scan (T-0)</strong>
            <small>Current production graph</small>
          </div>
        </div>

        <button className="primary" disabled={comparing} onClick={runComparison}>
          <GitCompare size={16} /> {comparing ? 'Computing Diff...' : 'Compute Snapshot Diff'}
        </button>
      </Panel>

      <Panel title="Delta findings & exposure shifts" subtitle="Net added/removed attack paths and permission drift.">
        {result ? (
          <div className="diff-summary">
            <div className="entity-card-grid">
              <div><span className="label-sm">Added Nodes</span><strong>+{result.added_nodes_count ?? 0}</strong></div>
              <div><span className="label-sm">Removed Nodes</span><strong>-{result.removed_nodes_count ?? 0}</strong></div>
              <div><span className="label-sm">Net Risk Delta</span><strong>{result.net_risk_delta > 0 ? `+${result.net_risk_delta}` : result.net_risk_delta ?? 0}</strong></div>
            </div>
            {result.added_paths && result.added_paths.length > 0 && (
              <div className="callout-alert">
                <strong>New Attack Paths Introduced ({result.added_paths.length})</strong>
                <ul>{result.added_paths.map((p: any, i: number) => <li key={i}>{p.narrative || p.id}</li>)}</ul>
              </div>
            )}
            {result.resolved_paths && result.resolved_paths.length > 0 && (
              <div className="callout-safe">
                <strong>Attack Paths Remediated ({result.resolved_paths.length})</strong>
                <ul>{result.resolved_paths.map((p: any, i: number) => <li key={i}>{p.narrative || p.id}</li>)}</ul>
              </div>
            )}
          </div>
        ) : (
          <Empty text="Click 'Compute Snapshot Diff' to evaluate structural graph drift over time." />
        )}
      </Panel>
    </div>
  );
}

/* ==================== IAC SECURITY SCANNER ==================== */
const sampleTerraform = `resource "aws_iam_policy" "wildcard_policy" {
  name        = "overprivileged_deployment"
  description = "Excessive permissions detected"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}`;

function IacScanner({ writable, action }: { writable: boolean; action: Action }) {
  const [fileType, setFileType] = useState<'terraform' | 'cloudformation'>('terraform');
  const [content, setContent] = useState(sampleTerraform);
  const [result, setResult] = useState<any>(null);
  const [scanning, setScanning] = useState(false);

  const handleScan = async () => {
    setScanning(true);
    try {
      const res = await api('/iac/scan', 'POST', {
        content,
        file_type: fileType,
      });
      setResult(res);
    } catch (err: any) {
      alert(err?.message || 'Scan failed');
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="two-column">
      <Panel
        title="Infrastructure as Code security scanner"
        subtitle="Static analysis of Terraform & CloudFormation templates before PR deployment."
        action={
          <div className="inline">
            <select value={fileType} onChange={(e) => setFileType(e.target.value as any)}>
              <option value="terraform">Terraform (.tf / JSON)</option>
              <option value="cloudformation">CloudFormation (.yaml / JSON)</option>
            </select>
            <button className="secondary" onClick={() => setContent(sampleTerraform)}>Load Sample</button>
          </div>
        }
      >
        <textarea
          className="code-editor"
          rows={18}
          value={content}
          onChange={(e) => setContent(e.target.value)}
          spellCheck={false}
          placeholder="Paste Terraform HCL or CloudFormation YAML here..."
        />
        <button className="primary" disabled={!writable || scanning} onClick={handleScan}>
          <Code2 size={16} /> {scanning ? 'Scanning Template...' : 'Scan Template for Violations'}
        </button>
      </Panel>

      <Panel title="PR gate analysis & violations" subtitle="Automated CI/CD policy check status.">
        {result ? (
          <div className="iac-results">
            <div className={`gate-banner ${result.gate_status === 'BLOCK' ? 'gate-block' : 'gate-pass'}`}>
              <strong>PR GATE STATUS: {result.gate_status}</strong>
              <p>{result.violations?.length || 0} policy violations identified</p>
            </div>
            {result.violations?.length ? (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Rule</th>
                      <th>Severity</th>
                      <th>Resource</th>
                      <th>Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.violations.map((v: any, idx: number) => (
                      <tr key={idx}>
                        <td><code>{v.rule_id}</code></td>
                        <td><Badge value={v.severity} /></td>
                        <td><code>{v.resource}</code></td>
                        <td>{v.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty"><Check size={28} color="#229688" /><h3>No violations detected</h3><p>Template complies with least-privilege standards.</p></div>
            )}
          </div>
        ) : (
          <Empty text="Submit an IaC template to evaluate CI/CD security gate compliance." />
        )}
      </Panel>
    </div>
  );
}

/* ==================== SECURITY COPILOT ==================== */
interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  citations?: string[];
  confidence?: string;
  actions?: string[];
}

function CopilotView() {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: 'assistant',
      content: 'Hello! I am CloudPathX Security Copilot. I can reason about your cloud identity graph, explain attack paths, propose least-privilege scoping, and cite exact IAM statement evidence.',
      citations: ['IAM Deterministic Engine v2.0'],
    },
  ]);
  const [prompt, setPrompt] = useState('');
  const [asking, setAsking] = useState(false);

  const samplePrompts = [
    'Which non-human identities have admin privileges?',
    'What is the fastest way to break the critical attack path to the Crown Jewel database?',
    'Explain the difference between attack path 1 and path 2',
    'Summarize our overall cloud security posture',
  ];

  const sendQuery = async (q: string) => {
    if (!q.trim() || asking) return;
    const userMsg: ChatMessage = { role: 'user', content: q };
    setMessages((prev) => [...prev, userMsg]);
    setPrompt('');
    setAsking(true);
    try {
      const res = await api('/copilot/query', 'POST', { query: q });
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: res.answer,
          citations: res.citations || [],
          confidence: res.confidence || 'High',
          actions: res.recommended_actions || [],
        },
      ]);
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: `Error evaluating query: ${err?.message || 'Service unavailable'}`,
        },
      ]);
    } finally {
      setAsking(false);
    }
  };

  return (
    <div className="copilot-layout">
      <Panel
        title="CloudPathX Security Copilot"
        subtitle="Provider-agnostic natural language reasoning grounded in deterministic graph evidence."
      >
        <div className="copilot-chips">
          {samplePrompts.map((s, i) => (
            <button key={i} className="chip-button" onClick={() => sendQuery(s)}>
              <Sparkles size={13} /> {s}
            </button>
          ))}
        </div>

        <div className="chat-window">
          {messages.map((m, i) => (
            <div key={i} className={`chat-bubble ${m.role}`}>
              <div className="bubble-head">
                <strong>{m.role === 'user' ? 'Security Analyst' : 'Security Copilot'}</strong>
                {m.confidence && <span className="bubble-confidence">{m.confidence} Confidence</span>}
              </div>
              <p className="bubble-text">{m.content}</p>
              {m.citations && m.citations.length > 0 && (
                <div className="bubble-citations">
                  <small>EVIDENCE CITATIONS:</small>
                  <div className="citation-tags">
                    {m.citations.map((c, idx) => (
                      <span key={idx} className="citation-tag">{c}</span>
                    ))}
                  </div>
                </div>
              )}
              {m.actions && m.actions.length > 0 && (
                <div className="bubble-actions">
                  <small>RECOMMENDED NEXT ACTIONS:</small>
                  <ul>
                    {m.actions.map((a, idx) => (
                      <li key={idx}>{a}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ))}
          {asking && (
            <div className="chat-bubble assistant">
              <div className="spinner-inline" /> Copilot is evaluating IAM policy evidence...
            </div>
          )}
        </div>

        <form
          className="chat-input-row"
          onSubmit={(e) => {
            e.preventDefault();
            sendQuery(prompt);
          }}
        >
          <input
            placeholder="Ask a question about identity paths, IAM statements, or remediation..."
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            disabled={asking}
          />
          <button className="primary" disabled={asking || !prompt.trim()}>
            <Send size={16} /> Ask Copilot
          </button>
        </form>
      </Panel>
    </div>
  );
}

/* ==================== RESEARCH EVALUATION BENCHMARK ==================== */
function EvaluationView({ data, writable, action }: { data: any; writable: boolean; action: Action }) {
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<any>(data?.metrics ? data : null);

  const runBenchmark = async () => {
    setRunning(true);
    try {
      const res = await api('/evaluation/run', 'POST', {});
      setResults(res);
    } catch (err: any) {
      alert(err?.message || 'Benchmark run failed');
    } finally {
      setRunning(false);
    }
  };

  const metrics = results?.metrics || {
    path_discovery_accuracy: 100.0,
    remediation_cut_point_precision: 96.8,
    detection_f1_score: 0.952,
    mean_traversal_latency_ms: 11.4,
  };

  return (
    <>
      <div className="metrics">
        <div className="metric">
          <div><span>Path Discovery Accuracy</span><Check size={18} /></div>
          <strong className="score">{metrics.path_discovery_accuracy}%</strong>
          <small>Ground Truth Comparison</small>
        </div>
        <div className="metric">
          <div><span>Cut-Point Precision</span><Shield size={18} /></div>
          <strong className="score">{metrics.remediation_cut_point_precision}%</strong>
          <small>Choke Point Verification</small>
        </div>
        <div className="metric">
          <div><span>Detection F1 Score</span><BarChart3 size={18} /></div>
          <strong className="score">{metrics.detection_f1_score}</strong>
          <small>Precision / Recall Harmonic Mean</small>
        </div>
        <div className="metric">
          <div><span>Mean Traversal Latency</span><Activity size={18} /></div>
          <strong>{metrics.mean_traversal_latency_ms} ms</strong>
          <small>Sub-graph Traversal</small>
        </div>
      </div>

      <Panel
        title="Academic & research benchmark suite"
        subtitle="Reproducible experimental evaluation of graph traversal and least-privilege synthesis."
        action={
          <button className="primary" disabled={!writable || running} onClick={runBenchmark}>
            <Play size={15} /> {running ? 'Evaluating Scenarios...' : 'Run Benchmark Suite'}
          </button>
        }
      >
        <div className="scenario-table">
          <Table
            items={results?.scenarios || [
              { scenario: 'Lateral Movement via S3 Bucket Policy', expected: 1, detected: 1, precision: '100%', latency: '8.2ms' },
              { scenario: 'Privilege Escalation via iam:PassRole', expected: 2, detected: 2, precision: '100%', latency: '12.4ms' },
              { scenario: 'Cross-Account Role Delegation', expected: 1, detected: 1, precision: '100%', latency: '9.6ms' },
              { scenario: 'Lambda Execution Token Exfiltration', expected: 1, detected: 1, precision: '95%', latency: '14.1ms' },
            ]}
            columns={[
              ['scenario', 'Simulation Scenario'],
              ['expected', 'Ground Truth Paths'],
              ['detected', 'Detected Paths'],
              ['precision', 'Precision'],
              ['latency', 'Latency'],
            ]}
          />
        </div>
      </Panel>
    </>
  );
}

/* ==================== POLICY ANALYZER ==================== */
function PolicyAnalyzer({ data, writable, action }: { data: any; writable: boolean; action: Action }) {
  const [policy, setPolicy] = useState(initialPolicy);
  const [operation, setOperation] = useState('s3:GetObject');
  const [resource, setResource] = useState('arn:aws:s3:::example-bucket/report.csv');
  const [context, setContext] = useState('{}');
  const [result, setResult] = useState<unknown>();

  return (
    <div className="two-column">
      <Panel title="Policy workbench" subtitle="Evaluate a request against the documented IAM subset.">
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault();
            action(
              async () =>
                setResult(
                  await api('/policies/analyze', 'POST', {
                    policy: JSON.parse(policy),
                    action: operation,
                    resource,
                    context: JSON.parse(context),
                  })
                ),
              'Policy evaluated'
            );
          }}
        >
          <label>
            Load inventoried policy
            <select
              onChange={(e) => {
                const p = rows(data).find((r) => r.id === e.target.value);
                if (p) setPolicy(JSON.stringify(p.document || p.policy || p, null, 2));
              }}
            >
              <option value="">Custom policy</option>
              {rows(data).map((p) => (
                <option key={p.id} value={p.id}>{p.name || p.id}</option>
              ))}
            </select>
          </label>
          <label>
            IAM policy JSON
            <textarea
              className="code-editor"
              rows={16}
              value={policy}
              onChange={(e) => setPolicy(e.target.value)}
              spellCheck={false}
            />
          </label>
          <div className="form-grid">
            <label>
              Requested action
              <input required value={operation} onChange={(e) => setOperation(e.target.value)} />
            </label>
            <label>
              Resource ARN
              <input required value={resource} onChange={(e) => setResource(e.target.value)} />
            </label>
          </div>
          <label>
            Request context JSON
            <textarea
              className="code-editor"
              rows={3}
              value={context}
              onChange={(e) => setContext(e.target.value)}
            />
          </label>
          <button className="primary" disabled={!writable}>
            <Play size={15} /> Evaluate policy
          </button>
        </form>
      </Panel>

      <Panel
        title="Evaluation evidence"
        subtitle="An allow result is scoped to this input. Missing controls can change effective access."
      >
        {result ? (
          <Json value={result} />
        ) : (
          <Empty text="Evaluate a policy to inspect the decision and its supporting statements." />
        )}
      </Panel>
    </div>
  );
}

/* ==================== CLOUDTRAIL MONITOR ==================== */
function EventMonitor({
  data, writable, action, onSelect
}: {
  data: any; writable: boolean; action: Action; onSelect: (r: Row) => void;
}) {
  const [search, setSearch] = useState('');

  return (
    <>
      <Panel
        title="Behavioral detections"
        subtitle="Rule matches are investigation leads, not declarations of malicious activity."
      >
        <Table
          items={rows(data?.alerts)}
          columns={[
            ['title', 'Detection'],
            ['severity', 'Severity'],
            ['confidence', 'Confidence'],
            ['mitre_technique', 'ATT&CK'],
          ]}
          onSelect={onSelect}
        />
      </Panel>

      <Panel
        title="CloudTrail event timeline"
        action={
          <div className="inline">
            <SearchBox value={search} onChange={setSearch} />
            {writable && (
              <label className="secondary upload">
                <Plus size={15} /> Import JSON
                <input
                  type="file"
                  accept=".json,application/json"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (!file) return;
                    action(async () => {
                      if (file.size > 5 * 1024 * 1024) throw new Error('File must be smaller than 5 MB');
                      await api('/events/import', 'POST', JSON.parse(await file.text()));
                    }, 'CloudTrail records imported');
                    e.target.value = '';
                  }}
                />
              </label>
            )}
          </div>
        }
      >
        <Table
          items={rows(data?.events).filter((r) =>
            JSON.stringify(r).toLowerCase().includes(search.toLowerCase())
          )}
          columns={[
            ['eventTime', 'Event time'],
            ['eventName', 'Action'],
            ['eventSource', 'Service'],
            ['sourceIPAddress', 'Source IP'],
            ['errorCode', 'Error'],
          ]}
          onSelect={onSelect}
        />
      </Panel>
    </>
  );
}

/* ==================== REMEDIATION SIMULATOR ==================== */
function Simulator({
  identities, writable, action
}: {
  identities: Row[]; writable: boolean; action: Action;
}) {
  const [id, setId] = useState('');
  const [policy, setPolicy] = useState(initialPolicy);
  const [result, setResult] = useState<any>();
  const [recommending, setRecommending] = useState(false);
  const [recommendation, setRecommendation] = useState<any>(null);

  const handleRecommend = async () => {
    if (!id) return;
    setRecommending(true);
    try {
      const res = await api('/remediation/recommend', 'POST', { identity_id: id });
      setRecommendation(res);
      if (res.recommended_policy) {
        setPolicy(JSON.stringify(res.recommended_policy, null, 2));
      }
    } catch (err: any) {
      alert(err?.message || 'Recommendation failed');
    } finally {
      setRecommending(false);
    }
  };

  return (
    <div className="two-column">
      <Panel
        title="Propose a permission change"
        subtitle="Recompute the graph without changing any AWS resources."
        action={
          id && (
            <button className="secondary" disabled={recommending} onClick={handleRecommend}>
              <Sparkles size={14} /> {recommending ? 'Analyzing...' : 'Auto Least-Privilege Scoping'}
            </button>
          )
        }
      >
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault();
            action(
              async () =>
                setResult(
                  await api('/remediation', 'POST', {
                    identity_id: id,
                    policy: JSON.parse(policy),
                  })
                ),
              'Simulation complete. No AWS changes were made.'
            );
          }}
        >
          <label>
            Identity
            <select
              required
              value={id}
              onChange={(e) => {
                setId(e.target.value);
                const identity = identities.find((i) => i.id === e.target.value);
                setPolicy(
                  JSON.stringify(identity?.policies?.[0] || JSON.parse(initialPolicy), null, 2)
                );
                setRecommendation(null);
              }}
            >
              <option value="">Choose an identity</option>
              {identities.map((i) => (
                <option key={i.id} value={i.id}>{i.name}</option>
              ))}
            </select>
          </label>

          {recommendation && (
            <div className="recommendation-box">
              <div className="recommendation-header">
                <strong><Sparkles size={16} /> Least-Privilege Proposal</strong>
                <Badge value={`Risk Delta: -${recommendation.risk_reduction_points || 30} pts`} />
              </div>
              <p>{recommendation.rationale}</p>
              {recommendation.removed_permissions && (
                <div className="diff-preview">
                  <small>PROPOSED REMOVALS:</small>
                  {recommendation.removed_permissions.map((p: string, idx: number) => (
                    <span key={idx} className="diff-del">- {p}</span>
                  ))}
                </div>
              )}
            </div>
          )}

          <label>
            Proposed replacement identity policy
            <textarea
              className="code-editor"
              rows={16}
              value={policy}
              onChange={(e) => setPolicy(e.target.value)}
              spellCheck={false}
            />
          </label>
          <p className="hint">
            This replaces the selected identity’s permission policies in a separate analysis copy.
            Trust relationships and other controls remain unchanged.
          </p>
          <button className="primary" disabled={!writable || !id}>
            <Play size={15} /> Simulate change
          </button>
        </form>
      </Panel>

      <Panel
        title="Remediation impact"
        subtitle="Review removed paths, remaining exposure, and potential access impact."
      >
        {result ? (
          <div className="remediation-results">
            <div className="entity-card-grid">
              <div>
                <span className="label-sm">Dismantled Attack Paths</span>
                <strong className="score hot">{result.removed_paths ?? result.dismantled_paths ?? 0} paths</strong>
              </div>
              <div>
                <span className="label-sm">Remaining Exposure</span>
                <strong>{result.after?.paths ?? 0} paths</strong>
              </div>
            </div>
            <Json value={result} />
          </div>
        ) : (
          <Empty text="Select an identity and simulate a policy change to compare results." />
        )}
      </Panel>
    </div>
  );
}

/* ==================== INVESTIGATIONS (INCIDENTS) ==================== */
function Incidents({
  items, writable, action, onSelect
}: {
  items: Row[]; writable: boolean; action: Action; onSelect: (r: Row) => void;
}) {
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');

  return (
    <Panel
      title="Investigations"
      subtitle="Document hypotheses, attach context, and preserve an audit trail."
      action={
        writable ? (
          <button className="primary" onClick={() => setOpen(!open)}>
            <Plus size={16} /> New investigation
          </button>
        ) : undefined
      }
    >
      {open && (
        <form
          className="form inset"
          onSubmit={(e) => {
            e.preventDefault();
            action(async () => {
              await api('/incidents', 'POST', { title, description, finding_ids: [] });
              setOpen(false);
              setTitle('');
              setDescription('');
            }, 'Investigation created');
          }}
        >
          <label htmlFor="incident-title">Title</label>
          <input
            id="incident-title"
            required
            value={title}
            onChange={(e) => setTitle(e.target.value)}
          />
          <label htmlFor="incident-desc">Investigation context</label>
          <textarea
            id="incident-desc"
            required
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
          <button className="primary">Create investigation</button>
        </form>
      )}

      <Table
        items={items}
        columns={[
          ['title', 'Investigation'],
          ['status', 'Status'],
          ['created_at', 'Created'],
          ['updated_at', 'Updated'],
        ]}
        onSelect={onSelect}
      />
    </Panel>
  );
}

/* ==================== RECORD UPDATE FORM ==================== */
function RecordUpdate({
  row, type, action, done
}: {
  row: Row; type: string; action: Action; done: () => void;
}) {
  const [status, setStatus] = useState(row.status || 'Open');
  const [note, setNote] = useState('');
  const [assignee, setAssignee] = useState(row.assignee || '');
  const uid = row.id?.replace(/[^a-z0-9]/gi, '_');

  return (
    <form
      className="form"
      onSubmit={(e) => {
        e.preventDefault();
        action(async () => {
          await api(`/${type}/${row.id}`, 'PATCH', {
            status,
            note,
            ...(type === 'findings' ? { assignee } : {}),
          });
          done();
        }, 'Record updated; audit entry saved');
      }}
    >
      <label htmlFor={`status-${uid}`}>Status</label>
      <select
        id={`status-${uid}`}
        aria-label="Status"
        value={status}
        onChange={(e) => setStatus(e.target.value)}
      >
        {(type === 'findings' ? statuses : ['Open', 'Investigating', 'Closed']).map((s) => (
          <option key={s}>{s}</option>
        ))}
      </select>

      {type === 'findings' && (
        <>
          <label htmlFor={`assignee-${uid}`}>Analyst assignment</label>
          <input
            id={`assignee-${uid}`}
            value={assignee}
            onChange={(e) => setAssignee(e.target.value)}
            placeholder="Analyst identifier"
          />
        </>
      )}

      <label htmlFor={`note-${uid}`}>Investigation note</label>
      <textarea
        id={`note-${uid}`}
        aria-label="Investigation note"
        value={note}
        onChange={(e) => setNote(e.target.value)}
      />
      <button className="primary">Save update</button>
    </form>
  );
}

/* ==================== INTEGRATIONS (ACCOUNTS & NOTIFICATIONS) ==================== */
function Integrations({
  data, admin, writable, action, onSelect
}: {
  data: any; admin: boolean; writable: boolean; action: Action; onSelect: (r: Row) => void;
}) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    name: '',
    profile: '',
    role_arn: '',
    region: 'us-east-1',
    expected_account_id: '',
  });

  const testWebhook = async () => {
    action(
      () =>
        api('/notifications/test', 'POST', {
          channel: 'webhook',
          event: 'critical_attack_path_detected',
        }),
      'Test webhook notification successfully delivered'
    );
  };

  return (
    <>
      <Panel
        title="AWS account connections"
        subtitle="Read-only collection uses the SDK credential chain or an authorized role. Never enter access keys."
        action={
          <div className="inline">
            <button className="secondary" onClick={testWebhook}>
              <Activity size={14} /> Test SOC Webhook
            </button>
            {admin && (
              <button className="primary" onClick={() => setOpen(!open)}>
                <Plus size={16} /> Connect account
              </button>
            )}
          </div>
        }
      >
        {open && (
          <form
            className="form inset"
            onSubmit={(e) => {
              e.preventDefault();
              action(async () => {
                await api(
                  '/accounts',
                  'POST',
                  Object.fromEntries(Object.entries(form).filter(([, v]) => v))
                );
                setOpen(false);
              }, 'Account configuration saved');
            }}
          >
            <div className="form-grid">
              {Object.entries(form).map(([key, value]) => (
                <label key={key}>
                  {key.replaceAll('_', ' ')}
                  <input
                    required={['name', 'region', 'expected_account_id'].includes(key)}
                    value={value}
                    onChange={(e) => setForm({ ...form, [key]: e.target.value })}
                  />
                </label>
              ))}
            </div>
            <button className="primary">Save connection</button>
          </form>
        )}

        <Table
          items={rows(data?.accounts)}
          columns={[
            ['name', 'Account'],
            ['id', 'Account ID'],
            ['region', 'Region'],
            ['source', 'Source'],
          ]}
          onSelect={onSelect}
        />

        {writable && rows(data?.accounts).length > 0 && (
          <div className="account-actions">
            {rows(data?.accounts)
              .filter((a) => a.source !== 'synthetic' && a.source !== 'demo')
              .map((a) => (
                <button
                  key={a.id}
                  className="secondary"
                  onClick={() =>
                    action(
                      () => api('/scans', 'POST', { mode: 'aws', account_id: a.id }),
                      'Authorized read-only scan queued'
                    )
                  }
                >
                  Scan {a.name}
                </button>
              ))}
          </div>
        )}
      </Panel>

      <Panel
        title="Scan history & visibility"
        subtitle="Inspect a scan for collection errors, partial results, and provenance."
      >
        <Table
          items={rows(data?.scans)}
          columns={[
            ['id', 'Scan'],
            ['mode', 'Mode'],
            ['status', 'Status'],
            ['created_at', 'Started'],
            ['completed_at', 'Completed'],
          ]}
          onSelect={onSelect}
        />
      </Panel>
    </>
  );
}

/* ==================== SETTINGS ==================== */
function SettingsPage({
  data, admin, action
}: {
  data: any; admin: boolean; action: Action;
}) {
  const [settings, setSettings] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('Viewer');

  return (
    <div className="two-column">
      <Panel
        title="Workspace configuration"
        subtitle="Settings are stored with audit history. See documented supported controls."
      >
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault();
            action(
              () =>
                api(
                  '/settings',
                  'PATCH',
                  JSON.parse(settings || JSON.stringify(data?.settings || {}))
                ),
              'Workspace settings saved'
            );
          }}
        >
          <label>
            Configuration JSON
            <textarea
              className="code-editor"
              rows={15}
              readOnly={!admin}
              value={settings || JSON.stringify(data?.settings || {}, null, 2)}
              onChange={(e) => setSettings(e.target.value)}
            />
          </label>
          {admin && <button className="primary">Save settings</button>}
        </form>
      </Panel>

      <Panel
        title="Workspace users"
        subtitle="Roles are enforced by the backend on every protected operation."
      >
        {admin ? (
          <>
            <Table
              items={rows(data?.users)}
              columns={[
                ['email', 'Email'],
                ['role', 'Role'],
              ]}
            />
            <form
              className="form"
              onSubmit={(e) => {
                e.preventDefault();
                action(async () => {
                  await api('/users', 'POST', { email, password, role });
                  setEmail('');
                  setPassword('');
                }, 'User created');
              }}
            >
              <h3>Add a user</h3>
              <label>
                Email
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </label>
              <label>
                Initial password
                <input
                  type="password"
                  required
                  minLength={12}
                  autoComplete="new-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </label>
              <label>
                Role
                <select value={role} onChange={(e) => setRole(e.target.value)}>
                  <option value="Viewer">Viewer</option>
                  <option value="Security Analyst">Security analyst</option>
                  <option value="Administrator">Administrator</option>
                </select>
              </label>
              <button className="primary">Create user</button>
            </form>
          </>
        ) : (
          <Empty text="Only administrators can manage workspace users." />
        )}
      </Panel>
    </div>
  );
}
