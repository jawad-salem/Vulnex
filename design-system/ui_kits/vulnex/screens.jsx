// Vulnex UI-kit screens — compose the DS primitives into real product views.
const DS = window.VulnexDesignSystem_3350b3;
const { Button, Badge, Card, StatCard, Input, Select, Tabs, Breadcrumbs, KpiStrip, PhaseStepper, EmptyState, ProgressBar, Avatar } = DS;
const PHASES = ['Planning', 'Recon', 'Scanning', 'Exploitation', 'Reporting', 'Completed'];

/* ── Login ─────────────────────────────────────────────── */
function LoginScreen({ go }) {
  const VIcon = window.VIcon;
  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-brand">
          <div style={{ display:'flex', justifyContent:'center', color:'#a28ff0' }}><VIcon name="shield" size={40} /></div>
          <h1>Vulnex</h1>
          <p>Penetration testing workflow platform</p>
        </div>
        <form onSubmit={(e)=>{e.preventDefault();go('dashboard');}}>
          <Input label="Username" defaultValue="demo-pentester" />
          <Input label="Password" type="password" defaultValue="demo-password" />
          <Button variant="primary" fullWidth type="submit">Log in</Button>
        </form>
        <p className="auth-footer">Contact your administrator for an account.</p>
      </div>
    </div>
  );
}

/* ── Dashboard ─────────────────────────────────────────── */
function DashboardScreen({ go }) {
  const data = window.VULNEX_DATA;
  const sev = { critical:0, high:0, medium:0, low:0, info:0 };
  data.findings.forEach(f => sev[f.severity]++);
  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-subtitle">Welcome back, demo-pentester</p>
        </div>
        <Button variant="primary" onClick={()=>go('engagements')}>+ New engagement</Button>
      </div>
      <div className="stats-grid">
        <StatCard label="Risk score" value="7.8" valueColor="#f09236" sub="High" subTone="#f09236" />
        <StatCard label="Active engagements" value="2" />
        <StatCard label="Total findings" value={data.findings.length} />
        <StatCard label="Critical / High" value={sev.critical} valueTone="critical" sub={sev.high + ' high'} subTone="high" />
        <StatCard label="Overdue findings" value="1" valueTone="critical" sub="1 due soon" subTone="high" />
        <StatCard label="Assigned to me" value="5" sub="0 overdue" />
      </div>
      <div className="grid-2 mb-4">
        <Card title="Severity distribution">
          <DonutLegend rows={[['Critical',sev.critical,'#f05853'],['High',sev.high,'#f09236'],['Medium',sev.medium,'#e3b341'],['Low',sev.low,'#58a6ff']]} />
        </Card>
        <Card title="Findings over time">
          <Sparkline />
        </Card>
      </div>
      <Card title="Urgent findings" actions={<Button size="sm" onClick={()=>{go('engagement','red');}}>View engagement</Button>}>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Finding</th><th>Severity</th><th>Engagement</th><th>CVSS</th></tr></thead>
            <tbody>
              {data.findings.filter(f=>['critical','high'].includes(f.severity)).slice(0,4).map(f => (
                <tr key={f.id} style={{cursor:'pointer'}} onClick={()=>go('finding', f.eng, f.id)}>
                  <td><a href="#" onClick={(e)=>e.preventDefault()}><strong>{f.title}</strong></a></td>
                  <td><Badge tone={f.severity}>{f.sevLabel}</Badge></td>
                  <td className="text-secondary text-sm">{f.eng === 'red' ? 'Red Team' : 'Q2 External'}</td>
                  <td className="text-mono font-semibold">{f.cvss.toFixed(1)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

/* ── Engagements list ──────────────────────────────────── */
function EngagementsScreen({ go }) {
  const data = window.VULNEX_DATA;
  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Engagements</h1>
          <p className="page-subtitle">{data.engagements.length} active</p>
        </div>
        <Button variant="primary">+ New engagement</Button>
      </div>
      <Card>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Type</th><th>Status</th><th>Findings</th><th>Window</th></tr></thead>
            <tbody>
              {data.engagements.map(e => (
                <tr key={e.id} style={{cursor:'pointer'}} onClick={()=>go('engagement', e.id)}>
                  <td><a href="#" onClick={(ev)=>ev.preventDefault()}><strong>{e.name}</strong></a></td>
                  <td className="text-sm text-secondary">{e.type}</td>
                  <td><Badge tone={e.status}>{e.statusLabel}</Badge></td>
                  <td className="text-mono">{e.findingCount}</td>
                  <td className="text-sm text-secondary">{e.window}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

/* ── Engagement detail ─────────────────────────────────── */
function EngagementScreen({ go, engagement }) {
  const data = window.VULNEX_DATA;
  const e = engagement;
  const findings = data.findings.filter(f => f.eng === e.id);
  const [tab, setTab] = React.useState('overview');
  const crit = findings.filter(f=>f.severity==='critical').length;
  return (
    <div>
      <Breadcrumbs items={[{label:'Engagements', href:'#'}, {label:e.name}]} />
      <div className="eng-hero">
        <div className="eng-hero-main">
          <div className="eng-hero-title">{e.name}</div>
          <div className="eng-hero-meta">
            <span className="eng-meta-item eng-meta-client">{e.client}</span>
            <span className="eng-meta-item">{e.type}</span>
            <span className="eng-meta-item">{e.window}</span>
            <span className="eng-meta-item">Lead: {e.lead}</span>
          </div>
        </div>
        <div className="eng-hero-actions">
          <Badge tone={e.status} size="lg">{e.statusLabel}</Badge>
          <Button onClick={()=>go('findings')}>View findings</Button>
        </div>
      </div>
      <PhaseStepper current={e.phase} steps={PHASES} />
      <KpiStrip items={[
        { label:'Findings', value:e.findingCount, sub: crit + ' critical' },
        { label:'Open', value: findings.filter(f=>f.status==='open').length },
        { label:'Overdue', value: findings.filter(f=>f.sla==='overdue').length, sub:'SLA' },
        { label:'Phase', value:e.statusLabel },
      ]} />
      <Tabs value={tab} onChange={setTab} tabs={[
        {id:'overview',label:'Overview'},{id:'findings',label:'Findings',count:e.findingCount},
        {id:'members',label:'Members'},{id:'notes',label:'Notes'},
      ]} />
      {tab === 'overview' ? (
        <div className="overview-grid">
          <Card title="Scope" fit>
            {e.scope.map((s,i)=><div className="scope-target" key={i}>{s}</div>)}
          </Card>
          <Card title="Quick actions" fit>
            <div className="quick-actions">
              <a href="#" className="quick-action qa-primary" onClick={(ev)=>{ev.preventDefault();go('findings');}}>
                <span className="qa-icon"><window.VIcon name="plus" /></span>
                <span className="qa-text"><span className="qa-label">Add finding</span><span className="qa-sub">Document a new vulnerability</span></span>
              </a>
              <a href="#" className="quick-action" onClick={(ev)=>ev.preventDefault()}>
                <span className="qa-icon"><window.VIcon name="upload" /></span>
                <span className="qa-text"><span className="qa-label">Import from scanner</span><span className="qa-sub">Nuclei, Burp, Nessus, Nmap…</span></span>
              </a>
              <a href="#" className="quick-action" onClick={(ev)=>ev.preventDefault()}>
                <span className="qa-icon"><window.VIcon name="reports" /></span>
                <span className="qa-text"><span className="qa-label">Generate report</span><span className="qa-sub">Executive or technical PDF</span></span>
              </a>
            </div>
          </Card>
        </div>
      ) : tab === 'findings' ? <FindingsTable findings={findings} go={go} /> : (
        <Card><EmptyState icon={<window.VIcon name="check-square" size={22}/>} title="Nothing here yet" subtitle="This tab is part of the demo shell." /></Card>
      )}
    </div>
  );
}

/* ── Findings list ─────────────────────────────────────── */
function FindingsScreen({ go, engagement }) {
  const data = window.VULNEX_DATA;
  const findings = data.findings.filter(f => f.eng === engagement.id);
  const [sev, setSev] = React.useState('');
  const shown = sev ? findings.filter(f=>f.severity===sev) : findings;
  return (
    <div>
      <Breadcrumbs items={[{label:'Engagements', href:'#'}, {label:engagement.name, href:'#'}, {label:'Findings'}]} />
      <div className="page-header">
        <div>
          <h1 className="page-title">Findings</h1>
          <p className="page-subtitle">{engagement.name} &middot; {findings.length} total</p>
        </div>
        <div className="btn-group">
          <Button variant="primary"><window.VIcon name="plus" size={15} /> Add finding</Button>
          <Button><window.VIcon name="upload" size={15} /> Import</Button>
          <Button><window.VIcon name="download" size={15} /> Export CSV</Button>
        </div>
      </div>
      <div className="filter-bar">
        <Input placeholder="Search findings..." className="search-input" />
        <Select compact value={sev} onChange={(e)=>setSev(e.target.value)}
          options={[{value:'',label:'All severities'},{value:'critical',label:'Critical'},{value:'high',label:'High'},{value:'medium',label:'Medium'},{value:'low',label:'Low'}]} />
        <Button variant="primary">Filter</Button>
      </div>
      <Card><FindingsTable findings={shown} go={go} /></Card>
    </div>
  );
}

function FindingsTable({ findings, go }) {
  if (!findings.length) return <EmptyState icon={<window.VIcon name="shield-off" size={22}/>} title="No findings match" subtitle="Try clearing the severity filter." />;
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Title</th><th>Host</th><th>Severity</th><th>CVSS</th><th>Status</th><th>Review</th><th>Assignee</th><th>Due</th></tr></thead>
        <tbody>
          {findings.map(f => (
            <tr key={f.id} style={{cursor:'pointer'}} onClick={()=>go('finding', f.eng, f.id)}>
              <td><a href="#" onClick={(e)=>e.preventDefault()}><strong>{f.title}</strong></a></td>
              <td className="text-mono text-sm">{f.host}{f.port ? <span className="text-muted">:{f.port}</span> : null}</td>
              <td><Badge tone={f.severity}>{f.sevLabel}</Badge></td>
              <td className="text-mono font-semibold">{f.cvss.toFixed(1)}</td>
              <td><Badge tone={f.status}>{f.statusLabel}</Badge></td>
              <td><Badge tone={f.review}>{f.reviewLabel}</Badge></td>
              <td className="text-sm">{f.assignee || <span className="text-muted">Unassigned</span>}</td>
              <td className="text-sm">
                {f.sla === 'closed' ? <span className="text-muted">—</span>
                  : f.sla === 'overdue' ? <Badge tone="overdue">Overdue</Badge>
                  : f.sla === 'due_soon' ? <Badge tone="due_soon">{f.due}</Badge>
                  : <span className="text-secondary">{f.due}</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ── Finding detail ────────────────────────────────────── */
function FindingDetailScreen({ go, engagement, finding }) {
  const f = finding;
  const [tab, setTab] = React.useState('overview');
  return (
    <div>
      <Breadcrumbs items={[{label:'Engagements', href:'#'}, {label:engagement.name, href:'#'}, {label:'Findings', href:'#'}, {label:f.title}]} />
      <div className="eng-hero">
        <div className="eng-hero-main">
          <div className="eng-hero-title">{f.title}</div>
          <div className="eng-hero-meta">
            <span className="eng-meta-item eng-meta-client">{engagement.name}</span>
            <span className="eng-meta-item text-mono">{f.host}{f.port?(':'+f.port):''}</span>
            <span className="eng-meta-item">{f.date}</span>
          </div>
        </div>
        <div className="eng-hero-actions">
          <Badge tone={f.severity} size="lg">{f.sevLabel}</Badge>
          <Badge tone={f.status} size="lg">{f.statusLabel}</Badge>
          <Badge tone={f.review} size="lg">{f.reviewLabel}</Badge>
          <Button>Edit</Button>
          <Button variant="danger">Delete</Button>
        </div>
      </div>
      <div className="kpi-strip" style={{marginBottom:24}}>
        <div className="kpi-item"><span className="kpi-label">CVSS score</span><span className="kpi-value" style={{color:'#f09236'}}>{f.cvss.toFixed(1)}</span><span className="kpi-sub">{f.sevLabel}</span></div>
        <div className="kpi-item"><span className="kpi-label">Status</span><span className="kpi-value" style={{fontSize:18}}>{f.statusLabel}</span><span className="kpi-sub">{f.date}</span></div>
        <div className="kpi-item"><span className="kpi-label">SLA</span><span className="kpi-value" style={{fontSize:18}}>{f.due || '—'}</span><span className="kpi-sub">{f.sla.replace('_',' ')}</span></div>
        <div className="kpi-item"><span className="kpi-label">Assigned to</span><span className="kpi-value" style={{fontSize:18}}>{f.assignee || 'Unassigned'}</span><span className="kpi-sub">{f.assignee ? 'owner' : 'no owner yet'}</span></div>
      </div>
      <Tabs value={tab} onChange={setTab} tabs={[
        {id:'overview',label:'Overview'},{id:'evidence',label:'Evidence'},{id:'cvss',label:'CVSS'},
        {id:'retest',label:'Retest'},{id:'review',label:'Review'},{id:'comments',label:'Comments'},
      ]} />
      {tab === 'overview' ? (
        <Card title="Description">
          <div className="prose">
            <p>A service account <code>svc-sql</code> is configured with an SPN and a weak, crackable password, allowing any authenticated domain user to request a Kerberos service ticket and crack it offline (Kerberoasting).</p>
            <h3>Impact</h3>
            <p>Recovery of the plaintext credential grants access to the backing SQL host and lateral movement toward domain compromise.</p>
            <h3>Remediation</h3>
            <ul>
              <li>Rotate the service account password to a 25+ character random value.</li>
              <li>Migrate to a Group Managed Service Account (gMSA) where possible.</li>
              <li>Restrict SPNs to only required services.</li>
            </ul>
          </div>
        </Card>
      ) : tab === 'review' ? (
        <Card title="Review &amp; approval" actions={<Badge tone="approved" size="lg">Approved</Badge>}>
          <p className="text-secondary" style={{color:'#3fb950'}}>This finding is approved and visible to the client.</p>
        </Card>
      ) : (
        <Card><EmptyState icon={<window.VIcon name="check-square" size={22}/>} title="Demo shell" subtitle={'The ' + tab + ' tab is part of the interactive demo.'} /></Card>
      )}
    </div>
  );
}

/* ── tiny chart stand-ins (Chart.js is used in the real product) ── */
function DonutLegend({ rows }) {
  const total = rows.reduce((a,[,n])=>a+n,0) || 1;
  let acc = 0;
  const segs = rows.map(([,n,c]) => { const start = acc/total*360; acc+=n; return `${c} ${start}deg ${acc/total*360}deg`; }).join(', ');
  return (
    <div style={{display:'flex', alignItems:'center', gap:28, padding:'8px 4px'}}>
      <div style={{width:130, height:130, borderRadius:'50%', background:`conic-gradient(${segs})`, WebkitMask:'radial-gradient(circle 40px at center, transparent 98%, #000 100%)', mask:'radial-gradient(circle 40px at center, transparent 98%, #000 100%)'}} />
      <div style={{display:'flex', flexDirection:'column', gap:8}}>
        {rows.map(([label,n,c]) => (
          <div key={label} style={{display:'flex', alignItems:'center', gap:8, fontSize:13}}>
            <span style={{width:10,height:10,borderRadius:2,background:c}} />
            <span className="text-secondary" style={{width:70}}>{label}</span>
            <span className="text-mono font-semibold">{n}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
function Sparkline() {
  const pts = [1,2,2,3,4,4,5,6,6,8];
  const w=320,h=130,max=8;
  const d = pts.map((p,i)=>`${i/(pts.length-1)*w},${h-10-(p/max)*(h-30)}`).join(' ');
  return (
    <svg viewBox={`0 0 ${w} ${h}`} style={{width:'100%',height:130}}>
      <polyline points={d} fill="none" stroke="#7a60e0" strokeWidth="2.5" />
      <polyline points={`0,${h} ${d} ${w},${h}`} fill="rgba(122,96,224,0.12)" stroke="none" />
      {pts.map((p,i)=><circle key={i} cx={i/(pts.length-1)*w} cy={h-10-(p/max)*(h-30)} r="3" fill="#7a60e0" />)}
    </svg>
  );
}

Object.assign(window, { LoginScreen, DashboardScreen, EngagementsScreen, EngagementScreen, FindingsScreen, FindingDetailScreen });
