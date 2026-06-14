import React from 'react';

/**
 * Vulnex Badge — pill that carries severity, finding status, review state,
 * SLA, engagement phase, scan state, etc. `tone` maps to the product's
 * .badge-* modifier classes.
 */
export function Badge({ tone = 'info', size, className = '', children, ...rest }) {
  const classes = [
    'badge',
    `badge-${tone}`,
    size === 'lg' && 'badge-lg',
    className,
  ].filter(Boolean).join(' ');
  return <span className={classes} {...rest}>{children}</span>;
}
