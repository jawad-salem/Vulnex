// Vulnex inline stroke icons — Feather/Lucide style, 24 grid, 2px, currentColor.
// Faithful to the SVGs used in the product's base template.
const VIcon = ({ name, size = 18, sw = 2, ...rest }) => {
  const p = {
    width: size, height: size, viewBox: '0 0 24 24', fill: 'none',
    stroke: 'currentColor', strokeWidth: sw, strokeLinecap: 'round', strokeLinejoin: 'round', ...rest,
  };
  switch (name) {
    case 'shield': return <svg {...p}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>;
    case 'dashboard': return <svg {...p}><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>;
    case 'engagements': return <svg {...p}><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>;
    case 'clients': return <svg {...p}><path d="M3 21h18"/><path d="M5 21V7l7-4 7 4v14"/><path d="M9 9h1M9 13h1M9 17h1M14 9h1M14 13h1M14 17h1"/></svg>;
    case 'users': return <svg {...p}><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>;
    case 'audit': return <svg {...p}><path d="M12 2l3 7h7l-5.5 4.5L18 21l-6-4-6 4 1.5-7.5L2 9h7z"/></svg>;
    case 'reports': return <svg {...p}><path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/><path d="M7 8h10M7 12h6"/></svg>;
    case 'search': return <svg {...p}><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>;
    case 'logout': return <svg {...p}><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>;
    case 'radar': return <svg {...p}><path d="M19.07 4.93A10 10 0 1 0 22 12"/><path d="M16.24 7.76A6 6 0 1 0 18 12"/><path d="M12 12l8-8"/><circle cx="12" cy="12" r="1.5" fill="currentColor" stroke="none"/></svg>;
    case 'key': return <svg {...p}><circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.5 12.5L20 3"/><path d="M16 7l3 3"/><path d="M14 9l3 3"/></svg>;
    case 'check-square': return <svg {...p}><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/></svg>;
    case 'plus': return <svg {...p}><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>;
    case 'upload': return <svg {...p}><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>;
    case 'download': return <svg {...p}><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="3" x2="12" y2="15"/></svg>;
    case 'chevron-down': return <svg {...p}><polyline points="6 9 12 15 18 9"/></svg>;
    case 'git-branch': return <svg {...p}><line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 01-9 9"/></svg>;
    case 'clock': return <svg {...p}><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>;
    case 'alert-triangle': return <svg {...p}><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>;
    case 'shield-off': return <svg {...p}><path d="M19.69 14a6.9 6.9 0 00.31-2V5l-8-3-3.16 1.18"/><path d="M4.73 4.73L4 5v7c0 6 8 10 8 10a20.29 20.29 0 005.62-4.38"/><line x1="1" y1="1" x2="23" y2="23"/></svg>;
    default: return <svg {...p}><circle cx="12" cy="12" r="10"/></svg>;
  }
};
window.VIcon = VIcon;
