import React from 'react';

/**
 * Vulnex Input — labelled text field. Matches .form-group + .form-input.
 * Supports help text and an error message.
 */
export function Input({
  label, id, type = 'text', textarea = false, help, error,
  compact = false, className = '', ...rest
}) {
  const inputId = id || (label ? `in-${String(label).toLowerCase().replace(/\s+/g, '-')}` : undefined);
  const cls = ['form-input', compact && 'form-input--compact', className].filter(Boolean).join(' ');
  const Field = textarea ? 'textarea' : 'input';
  return (
    <div className="form-group">
      {label ? <label htmlFor={inputId}>{label}</label> : null}
      <Field id={inputId} className={cls} {...(textarea ? {} : { type })} {...rest} />
      {help ? <small className="form-help">{help}</small> : null}
      {error ? <small className="field-error">{error}</small> : null}
    </div>
  );
}
