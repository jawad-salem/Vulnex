import React from 'react';

/**
 * Vulnex Select — native dropdown with the product's custom chevron.
 * Pass `options` as [{value, label}] or strings, or provide <option> children.
 */
export function Select({ label, id, options, value, defaultValue, compact = false, className = '', children, ...rest }) {
  const selId = id || (label ? `sel-${String(label).toLowerCase().replace(/\s+/g, '-')}` : undefined);
  const cls = ['form-input', compact && 'form-input--compact', className].filter(Boolean).join(' ');
  const opts = (options || []).map((o) =>
    typeof o === 'string' ? { value: o, label: o } : o
  );
  const select = (
    <select id={selId} className={cls} value={value} defaultValue={defaultValue} {...rest}>
      {children || opts.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  );
  if (!label) return select;
  return (
    <div className="form-group">
      <label htmlFor={selId}>{label}</label>
      {select}
    </div>
  );
}
