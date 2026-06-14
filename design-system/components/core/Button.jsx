import React from 'react';

/**
 * Vulnex Button — primary actions, secondary controls, destructive ops.
 * Maps to the product's .btn family. Renders an <a> when `href` is set,
 * otherwise a <button>.
 */
export function Button({
  variant = 'secondary',
  size = 'md',
  href,
  icon,
  iconRight,
  disabled = false,
  loading = false,
  fullWidth = false,
  type = 'button',
  className = '',
  children,
  ...rest
}) {
  const classes = [
    'btn',
    variant === 'primary' && 'btn-primary',
    variant === 'danger' && 'btn-danger',
    size === 'sm' && 'btn-sm',
    fullWidth && 'btn-full',
    loading && 'loading',
    className,
  ].filter(Boolean).join(' ');

  const content = (
    <>
      {icon ? <span className="btn-icon" aria-hidden="true">{icon}</span> : null}
      {children}
      {iconRight ? <span className="btn-icon" aria-hidden="true">{iconRight}</span> : null}
    </>
  );

  if (href && !disabled) {
    return <a href={href} className={classes} {...rest}>{content}</a>;
  }
  return (
    <button type={type} className={classes} disabled={disabled || loading} {...rest}>
      {content}
    </button>
  );
}
