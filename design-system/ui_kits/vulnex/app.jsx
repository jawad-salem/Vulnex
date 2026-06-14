// Vulnex UI-kit app — minimal in-memory router across the core screens.
function App() {
  const data = window.VULNEX_DATA;
  const [state, setState] = React.useState({ route: 'login', engId: null, findingId: null });
  const go = (route, engId, findingId) => setState((s) => ({
    route,
    engId: engId !== undefined ? engId : s.engId,
    findingId: findingId !== undefined ? findingId : s.findingId,
  }));

  const engagement = data.engagements.find((e) => e.id === state.engId) || null;
  const finding = data.findings.find((f) => f.id === state.findingId) || null;

  if (state.route === 'login') return <window.LoginScreen go={go} />;

  let screen;
  switch (state.route) {
    case 'dashboard': screen = <window.DashboardScreen go={go} />; break;
    case 'engagements': screen = <window.EngagementsScreen go={go} />; break;
    case 'engagement': screen = <window.EngagementScreen go={go} engagement={engagement} />; break;
    case 'findings': screen = <window.FindingsScreen go={go} engagement={engagement} />; break;
    case 'finding': screen = <window.FindingDetailScreen go={go} engagement={engagement} finding={finding} />; break;
    case 'clients': case 'users': case 'audit': case 'reports':
      screen = <SimplePlaceholder route={state.route} />; break;
    default: screen = <window.DashboardScreen go={go} />;
  }
  return <window.Shell route={state.route} go={go} engagement={state.route==='dashboard'||state.route==='engagements'?null:engagement}>{screen}</window.Shell>;
}

function SimplePlaceholder({ route }) {
  const { Card, EmptyState } = window.VulnexDesignSystem_3350b3;
  const titles = { clients:'Clients', users:'Users & roles', audit:'Audit log', reports:'Report templates' };
  return (
    <div>
      <div className="page-header"><h1 className="page-title">{titles[route]}</h1></div>
      <Card><EmptyState icon={<window.VIcon name="shield" size={22}/>} title={titles[route]} subtitle="This area exists in the product — left as a stub in the interactive demo." /></Card>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
