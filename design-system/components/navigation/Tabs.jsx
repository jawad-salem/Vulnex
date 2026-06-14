import React from 'react';

/**
 * Vulnex Tabs — underline tab bar. Controlled via `value` + `onChange`, or
 * uncontrolled with `defaultValue`. Tabs: [{id, label, count}].
 */
export function Tabs({ tabs = [], value, defaultValue, onChange, className = '' }) {
  const [internal, setInternal] = React.useState(defaultValue ?? (tabs[0] && tabs[0].id));
  const active = value !== undefined ? value : internal;
  const select = (id) => {
    if (value === undefined) setInternal(id);
    onChange && onChange(id);
  };
  return (
    <div className={['tab-nav', className].filter(Boolean).join(' ')} role="tablist">
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          role="tab"
          aria-selected={active === t.id}
          className={['tab-btn', active === t.id && 'active'].filter(Boolean).join(' ')}
          onClick={() => select(t.id)}
        >
          {t.label}
          {t.count != null ? <span className="tab-count">{t.count}</span> : null}
        </button>
      ))}
    </div>
  );
}
