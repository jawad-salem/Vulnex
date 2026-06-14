import React from 'react';

/**
 * Vulnex Alert — inline toast/message banner. tone: success | error | warning | info.
 * Optional dismiss button.
 */
export function Alert({ tone = 'info', onClose, dismissible = false, className = '', children, ...rest }) {
  return (
    <div className={['alert', `alert-${tone}`, className].filter(Boolean).join(' ')} role="alert" {...rest}>
      <span>{children}</span>
      {(dismissible || onClose) ? (
        <button type="button" className="alert-close" aria-label="Dismiss" onClick={onClose}>&times;</button>
      ) : null}
    </div>
  );
}
