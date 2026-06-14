import React from 'react';

const PALETTE = ['#7a60e0', '#f05853', '#f09236', '#3fb950', '#58a6ff', '#e3b341', '#38b6b6'];

function initialsFrom(name = '') {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return '?';
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

function colorFor(seed = '') {
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) | 0;
  return PALETTE[Math.abs(h) % PALETTE.length];
}

/**
 * Vulnex Avatar — initials chip with a deterministic color per user.
 * Matches the product's .avatar-sm (sidebar, table user cells).
 */
export function Avatar({ name = '', initials, color, size = 28, className = '', ...rest }) {
  const text = initials || initialsFrom(name);
  const bg = color || colorFor(name || text);
  return (
    <div
      className={['avatar-sm', className].filter(Boolean).join(' ')}
      style={{ background: bg, width: size, height: size, fontSize: Math.round(size * 0.4) }}
      title={name || undefined}
      {...rest}
    >
      {text}
    </div>
  );
}
