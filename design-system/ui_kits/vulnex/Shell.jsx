// Vulnex app shell: fixed sidebar + main content, matching the product layout.
const { Avatar } = window.VulnexDesignSystem_3350b3;

function Sidebar({ route, go, engagement }) {
  const VIcon = window.VIcon;
  const top = [
    ['dashboard', 'Dashboard', 'dashboard'],
    ['engagements', 'Engagements', 'engagements'],
    ['clients', 'Clients', 'clients'],
    ['users', 'Users', 'users'],
    ['audit', 'Audit log', 'audit'],
    ['reports', 'Report templates', 'reports'],
  ];
  const isActive = (id) =>
    route === id || (id === 'engagements' && (route === 'engagement' || route === 'findings' || route === 'finding'));
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <VIcon name="shield" size={24} />
        <span>Vulnex</span>
      </div>
      <nav className="sidebar-nav">
        {top.map(([id, label, icon]) => (
          <a key={id} href="#" className={'nav-item' + (isActive(id) ? ' active' : '')}
             onClick={(e) => { e.preventDefault(); go(id === 'engagements' ? 'engagements' : id); }}>
            <VIcon name={icon} /> {label}
          </a>
        ))}
      </nav>
      {engagement ? (
        <div className="sidebar-section">
          <div className="sidebar-section-title">Engagement</div>
          <div className="sidebar-section-name" title={engagement.name}>{engagement.name}</div>
          <a href="#" className={'nav-item sub' + (route === 'engagement' ? ' active' : '')} onClick={(e)=>{e.preventDefault();go('engagement');}}>Overview</a>
          <a href="#" className={'nav-item sub' + (route === 'findings' || route === 'finding' ? ' active' : '')} onClick={(e)=>{e.preventDefault();go('findings');}}>Findings</a>
          <a href="#" className="nav-item sub" onClick={(e)=>e.preventDefault()}>Recon</a>
          <a href="#" className="nav-item sub" onClick={(e)=>e.preventDefault()}>Credentials</a>
          <a href="#" className="nav-item sub" onClick={(e)=>e.preventDefault()}>Methodology</a>
          <a href="#" className="nav-item sub" onClick={(e)=>e.preventDefault()}>Reports</a>
        </div>
      ) : null}
      <div className="sidebar-bottom">
        <a href="#" className="nav-item" onClick={(e)=>e.preventDefault()}>
          <Avatar name="A D" initials="AD" color="#7a60e0" /> admin
        </a>
        <a href="#" className="nav-item logout-btn" onClick={(e)=>{e.preventDefault();go('login');}}>
          <VIcon name="logout" /> Log out
        </a>
      </div>
    </aside>
  );
}

function Shell({ route, go, engagement, children }) {
  const VIcon = window.VIcon;
  return (
    <div className="layout">
      <Sidebar route={route} go={go} engagement={engagement} />
      <main className="main-content">
        <form className="global-search" onSubmit={(e)=>e.preventDefault()}>
          <span className="global-search-icon"><VIcon name="search" size={16} /></span>
          <input className="global-search-input" placeholder="Search findings, engagements, hosts…  (press /)" />
        </form>
        {children}
      </main>
    </div>
  );
}

window.Sidebar = Sidebar;
window.Shell = Shell;
