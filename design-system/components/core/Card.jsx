import React from 'react';

/**
 * Vulnex Card — bordered surface panel. Optional header with title + actions.
 * Matches the product's .card.
 */
export function Card({ title, actions, headerRight, fit = false, className = '', children, ...rest }) {
  const classes = ['card', fit && 'card-fit', className].filter(Boolean).join(' ');
  const header = title || actions || headerRight;
  return (
    <div className={classes} {...rest}>
      {header ? (
        <div className="card-header">
          {title ? <h2 className="card-title">{title}</h2> : <span />}
          {actions || headerRight || null}
        </div>
      ) : null}
      {children}
    </div>
  );
}
