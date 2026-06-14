import React from 'react';

/**
 * Vulnex EmptyState — centered icon + title + subtitle + optional action.
 * Matches .empty-state with the accent .empty-state__icon treatment.
 */
export function EmptyState({ icon, title, subtitle, action, className = '', children }) {
  return (
    <div className={['empty-state', className].filter(Boolean).join(' ')}>
      {icon ? <div className="empty-state__icon">{icon}</div> : null}
      {title ? <p className="empty-state__title">{title}</p> : null}
      {subtitle ? <p className="empty-state__subtitle">{subtitle}</p> : null}
      {children}
      {action ? <div className="btn-group" style={{ justifyContent: 'center', marginTop: 16 }}>{action}</div> : null}
    </div>
  );
}
