import React from 'react';

/**
 * Vulnex StatCard — KPI tile with uppercase label, big mono value and an
 * optional sub-label. Used across the dashboard stats grid.
 */
export function StatCard({ label, value, valueTone, sub, subTone, valueColor, className = '', ...rest }) {
  const valClasses = ['stat-value', valueTone, className && null].filter(Boolean).join(' ');
  return (
    <div className={['stat-card', className].filter(Boolean).join(' ')} {...rest}>
      <div className="stat-label">{label}</div>
      <div className={valClasses} style={valueColor ? { color: valueColor } : undefined}>{value}</div>
      {sub != null ? (
        <div className={['stat-sublabel', subTone].filter(Boolean).join(' ')} style={subTone && !['high','critical'].includes(subTone) ? { color: subTone } : undefined}>{sub}</div>
      ) : null}
    </div>
  );
}
