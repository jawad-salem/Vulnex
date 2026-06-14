import React from 'react';

/**
 * Vulnex Breadcrumbs — trail of links ending in the current page.
 * items: [{label, href}] — the last item renders as current (no link).
 */
export function Breadcrumbs({ items = [], className = '' }) {
  return (
    <nav className={['breadcrumbs', className].filter(Boolean).join(' ')} aria-label="Breadcrumb">
      {items.map((it, i) => {
        const last = i === items.length - 1;
        return (
          <React.Fragment key={i}>
            {last || !it.href
              ? <span className="bc-current">{it.label}</span>
              : <a href={it.href}>{it.label}</a>}
            {!last ? <span className="bc-sep">&#8250;</span> : null}
          </React.Fragment>
        );
      })}
    </nav>
  );
}
