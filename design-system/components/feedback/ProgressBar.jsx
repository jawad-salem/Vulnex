import React from 'react';

/**
 * Vulnex ProgressBar — thin accent-filled track. Use `mini` for the inline
 * table variant (e.g. methodology coverage).
 */
export function ProgressBar({ value = 0, max = 100, mini = false, className = '', ...rest }) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100));
  return (
    <div className={[mini ? 'progress-bar-mini' : 'progress-bar', className].filter(Boolean).join(' ')}
         role="progressbar" aria-valuenow={value} aria-valuemin={0} aria-valuemax={max} {...rest}>
      <div className="progress-fill" style={{ width: `${pct}%` }} />
    </div>
  );
}
