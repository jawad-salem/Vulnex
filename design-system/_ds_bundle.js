/* @ds-bundle: {"format":3,"namespace":"VulnexDesignSystem_3350b3","components":[{"name":"Avatar","sourcePath":"components/core/Avatar.jsx"},{"name":"Badge","sourcePath":"components/core/Badge.jsx"},{"name":"Button","sourcePath":"components/core/Button.jsx"},{"name":"Card","sourcePath":"components/core/Card.jsx"},{"name":"StatCard","sourcePath":"components/core/StatCard.jsx"},{"name":"KpiStrip","sourcePath":"components/data/KpiStrip.jsx"},{"name":"PhaseStepper","sourcePath":"components/data/PhaseStepper.jsx"},{"name":"Alert","sourcePath":"components/feedback/Alert.jsx"},{"name":"EmptyState","sourcePath":"components/feedback/EmptyState.jsx"},{"name":"ProgressBar","sourcePath":"components/feedback/ProgressBar.jsx"},{"name":"Input","sourcePath":"components/forms/Input.jsx"},{"name":"Select","sourcePath":"components/forms/Select.jsx"},{"name":"Breadcrumbs","sourcePath":"components/navigation/Breadcrumbs.jsx"},{"name":"Tabs","sourcePath":"components/navigation/Tabs.jsx"}],"sourceHashes":{"components/core/Avatar.jsx":"232e49108967","components/core/Badge.jsx":"819b813d8011","components/core/Button.jsx":"06390dedead5","components/core/Card.jsx":"03e887acae9f","components/core/StatCard.jsx":"8f2e779dc559","components/data/KpiStrip.jsx":"84256c4304ec","components/data/PhaseStepper.jsx":"4c8158044701","components/feedback/Alert.jsx":"c01a331347e9","components/feedback/EmptyState.jsx":"2b983201b3e1","components/feedback/ProgressBar.jsx":"ccb8700a8d0b","components/forms/Input.jsx":"7a724a4e1d32","components/forms/Select.jsx":"7887aca70af3","components/navigation/Breadcrumbs.jsx":"b5ace3bfb39c","components/navigation/Tabs.jsx":"56b82f1a89a3","static/js/attack_path.js":"88ba7f9d42cc","static/js/markdown_preview.js":"e345a6ef1a46","ui_kits/vulnex/Shell.jsx":"228d3d7185c0","ui_kits/vulnex/app.jsx":"d8667778b689","ui_kits/vulnex/data.jsx":"d2a20c407423","ui_kits/vulnex/icons.jsx":"121c1563a35d","ui_kits/vulnex/screens.jsx":"7b5f660083fe"},"inlinedExternals":[],"unexposedExports":[]} */

(() => {

const __ds_ns = (window.VulnexDesignSystem_3350b3 = window.VulnexDesignSystem_3350b3 || {});

const __ds_scope = {};

(__ds_ns.__errors = __ds_ns.__errors || []);

// components/core/Avatar.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
const PALETTE = ['#7a60e0', '#f05853', '#f09236', '#3fb950', '#58a6ff', '#e3b341', '#38b6b6'];
function initialsFrom(name = '') {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return '?';
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}
function colorFor(seed = '') {
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = h * 31 + seed.charCodeAt(i) | 0;
  return PALETTE[Math.abs(h) % PALETTE.length];
}

/**
 * Vulnex Avatar — initials chip with a deterministic color per user.
 * Matches the product's .avatar-sm (sidebar, table user cells).
 */
function Avatar({
  name = '',
  initials,
  color,
  size = 28,
  className = '',
  ...rest
}) {
  const text = initials || initialsFrom(name);
  const bg = color || colorFor(name || text);
  return /*#__PURE__*/React.createElement("div", _extends({
    className: ['avatar-sm', className].filter(Boolean).join(' '),
    style: {
      background: bg,
      width: size,
      height: size,
      fontSize: Math.round(size * 0.4)
    },
    title: name || undefined
  }, rest), text);
}
Object.assign(__ds_scope, { Avatar });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/Avatar.jsx", error: String((e && e.message) || e) }); }

// components/core/Badge.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * Vulnex Badge — pill that carries severity, finding status, review state,
 * SLA, engagement phase, scan state, etc. `tone` maps to the product's
 * .badge-* modifier classes.
 */
function Badge({
  tone = 'info',
  size,
  className = '',
  children,
  ...rest
}) {
  const classes = ['badge', `badge-${tone}`, size === 'lg' && 'badge-lg', className].filter(Boolean).join(' ');
  return /*#__PURE__*/React.createElement("span", _extends({
    className: classes
  }, rest), children);
}
Object.assign(__ds_scope, { Badge });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/Badge.jsx", error: String((e && e.message) || e) }); }

// components/core/Button.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * Vulnex Button — primary actions, secondary controls, destructive ops.
 * Maps to the product's .btn family. Renders an <a> when `href` is set,
 * otherwise a <button>.
 */
function Button({
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
  const classes = ['btn', variant === 'primary' && 'btn-primary', variant === 'danger' && 'btn-danger', size === 'sm' && 'btn-sm', fullWidth && 'btn-full', loading && 'loading', className].filter(Boolean).join(' ');
  const content = /*#__PURE__*/React.createElement(React.Fragment, null, icon ? /*#__PURE__*/React.createElement("span", {
    className: "btn-icon",
    "aria-hidden": "true"
  }, icon) : null, children, iconRight ? /*#__PURE__*/React.createElement("span", {
    className: "btn-icon",
    "aria-hidden": "true"
  }, iconRight) : null);
  if (href && !disabled) {
    return /*#__PURE__*/React.createElement("a", _extends({
      href: href,
      className: classes
    }, rest), content);
  }
  return /*#__PURE__*/React.createElement("button", _extends({
    type: type,
    className: classes,
    disabled: disabled || loading
  }, rest), content);
}
Object.assign(__ds_scope, { Button });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/Button.jsx", error: String((e && e.message) || e) }); }

// components/core/Card.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * Vulnex Card — bordered surface panel. Optional header with title + actions.
 * Matches the product's .card.
 */
function Card({
  title,
  actions,
  headerRight,
  fit = false,
  className = '',
  children,
  ...rest
}) {
  const classes = ['card', fit && 'card-fit', className].filter(Boolean).join(' ');
  const header = title || actions || headerRight;
  return /*#__PURE__*/React.createElement("div", _extends({
    className: classes
  }, rest), header ? /*#__PURE__*/React.createElement("div", {
    className: "card-header"
  }, title ? /*#__PURE__*/React.createElement("h2", {
    className: "card-title"
  }, title) : /*#__PURE__*/React.createElement("span", null), actions || headerRight || null) : null, children);
}
Object.assign(__ds_scope, { Card });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/Card.jsx", error: String((e && e.message) || e) }); }

// components/core/StatCard.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * Vulnex StatCard — KPI tile with uppercase label, big mono value and an
 * optional sub-label. Used across the dashboard stats grid.
 */
function StatCard({
  label,
  value,
  valueTone,
  sub,
  subTone,
  valueColor,
  className = '',
  ...rest
}) {
  const valClasses = ['stat-value', valueTone, className && null].filter(Boolean).join(' ');
  return /*#__PURE__*/React.createElement("div", _extends({
    className: ['stat-card', className].filter(Boolean).join(' ')
  }, rest), /*#__PURE__*/React.createElement("div", {
    className: "stat-label"
  }, label), /*#__PURE__*/React.createElement("div", {
    className: valClasses,
    style: valueColor ? {
      color: valueColor
    } : undefined
  }, value), sub != null ? /*#__PURE__*/React.createElement("div", {
    className: ['stat-sublabel', subTone].filter(Boolean).join(' '),
    style: subTone && !['high', 'critical'].includes(subTone) ? {
      color: subTone
    } : undefined
  }, sub) : null);
}
Object.assign(__ds_scope, { StatCard });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/StatCard.jsx", error: String((e && e.message) || e) }); }

// components/data/KpiStrip.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * Vulnex KpiStrip — joined row of compact metrics with hairline dividers.
 * Used on the engagement detail header. items: [{label, value, sub}].
 */
function KpiStrip({
  items = [],
  className = '',
  ...rest
}) {
  return /*#__PURE__*/React.createElement("div", _extends({
    className: ['kpi-strip', className].filter(Boolean).join(' ')
  }, rest), items.map((it, i) => /*#__PURE__*/React.createElement("div", {
    className: "kpi-item",
    key: i
  }, /*#__PURE__*/React.createElement("span", {
    className: "kpi-label"
  }, it.label), /*#__PURE__*/React.createElement("span", {
    className: "kpi-value"
  }, it.value), it.sub != null ? /*#__PURE__*/React.createElement("span", {
    className: "kpi-sub"
  }, it.sub) : null)));
}
Object.assign(__ds_scope, { KpiStrip });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/data/KpiStrip.jsx", error: String((e && e.message) || e) }); }

// components/data/PhaseStepper.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * Vulnex PhaseStepper — engagement lifecycle stepper. steps: string[] or
 * [{label}]. `current` = index of the active phase; earlier phases render done.
 */
function PhaseStepper({
  steps = [],
  current = 0,
  className = '',
  ...rest
}) {
  const items = steps.map(s => typeof s === 'string' ? {
    label: s
  } : s);
  return /*#__PURE__*/React.createElement("div", _extends({
    className: ['phase-stepper', className].filter(Boolean).join(' ')
  }, rest), items.map((s, i) => {
    const state = i < current ? 'phase-done' : i === current ? 'phase-active' : '';
    return /*#__PURE__*/React.createElement("div", {
      className: ['phase-step', state].filter(Boolean).join(' '),
      key: i
    }, /*#__PURE__*/React.createElement("div", {
      className: "phase-dot"
    }, i < current ? '✓' : i + 1), /*#__PURE__*/React.createElement("div", {
      className: "phase-label"
    }, s.label));
  }));
}
Object.assign(__ds_scope, { PhaseStepper });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/data/PhaseStepper.jsx", error: String((e && e.message) || e) }); }

// components/feedback/Alert.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * Vulnex Alert — inline toast/message banner. tone: success | error | warning | info.
 * Optional dismiss button.
 */
function Alert({
  tone = 'info',
  onClose,
  dismissible = false,
  className = '',
  children,
  ...rest
}) {
  return /*#__PURE__*/React.createElement("div", _extends({
    className: ['alert', `alert-${tone}`, className].filter(Boolean).join(' '),
    role: "alert"
  }, rest), /*#__PURE__*/React.createElement("span", null, children), dismissible || onClose ? /*#__PURE__*/React.createElement("button", {
    type: "button",
    className: "alert-close",
    "aria-label": "Dismiss",
    onClick: onClose
  }, "\xD7") : null);
}
Object.assign(__ds_scope, { Alert });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/feedback/Alert.jsx", error: String((e && e.message) || e) }); }

// components/feedback/EmptyState.jsx
try { (() => {
/**
 * Vulnex EmptyState — centered icon + title + subtitle + optional action.
 * Matches .empty-state with the accent .empty-state__icon treatment.
 */
function EmptyState({
  icon,
  title,
  subtitle,
  action,
  className = '',
  children
}) {
  return /*#__PURE__*/React.createElement("div", {
    className: ['empty-state', className].filter(Boolean).join(' ')
  }, icon ? /*#__PURE__*/React.createElement("div", {
    className: "empty-state__icon"
  }, icon) : null, title ? /*#__PURE__*/React.createElement("p", {
    className: "empty-state__title"
  }, title) : null, subtitle ? /*#__PURE__*/React.createElement("p", {
    className: "empty-state__subtitle"
  }, subtitle) : null, children, action ? /*#__PURE__*/React.createElement("div", {
    className: "btn-group",
    style: {
      justifyContent: 'center',
      marginTop: 16
    }
  }, action) : null);
}
Object.assign(__ds_scope, { EmptyState });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/feedback/EmptyState.jsx", error: String((e && e.message) || e) }); }

// components/feedback/ProgressBar.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * Vulnex ProgressBar — thin accent-filled track. Use `mini` for the inline
 * table variant (e.g. methodology coverage).
 */
function ProgressBar({
  value = 0,
  max = 100,
  mini = false,
  className = '',
  ...rest
}) {
  const pct = Math.max(0, Math.min(100, value / max * 100));
  return /*#__PURE__*/React.createElement("div", _extends({
    className: [mini ? 'progress-bar-mini' : 'progress-bar', className].filter(Boolean).join(' '),
    role: "progressbar",
    "aria-valuenow": value,
    "aria-valuemin": 0,
    "aria-valuemax": max
  }, rest), /*#__PURE__*/React.createElement("div", {
    className: "progress-fill",
    style: {
      width: `${pct}%`
    }
  }));
}
Object.assign(__ds_scope, { ProgressBar });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/feedback/ProgressBar.jsx", error: String((e && e.message) || e) }); }

// components/forms/Input.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * Vulnex Input — labelled text field. Matches .form-group + .form-input.
 * Supports help text and an error message.
 */
function Input({
  label,
  id,
  type = 'text',
  textarea = false,
  help,
  error,
  compact = false,
  className = '',
  ...rest
}) {
  const inputId = id || (label ? `in-${String(label).toLowerCase().replace(/\s+/g, '-')}` : undefined);
  const cls = ['form-input', compact && 'form-input--compact', className].filter(Boolean).join(' ');
  const Field = textarea ? 'textarea' : 'input';
  return /*#__PURE__*/React.createElement("div", {
    className: "form-group"
  }, label ? /*#__PURE__*/React.createElement("label", {
    htmlFor: inputId
  }, label) : null, /*#__PURE__*/React.createElement(Field, _extends({
    id: inputId,
    className: cls
  }, textarea ? {} : {
    type
  }, rest)), help ? /*#__PURE__*/React.createElement("small", {
    className: "form-help"
  }, help) : null, error ? /*#__PURE__*/React.createElement("small", {
    className: "field-error"
  }, error) : null);
}
Object.assign(__ds_scope, { Input });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/forms/Input.jsx", error: String((e && e.message) || e) }); }

// components/forms/Select.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * Vulnex Select — native dropdown with the product's custom chevron.
 * Pass `options` as [{value, label}] or strings, or provide <option> children.
 */
function Select({
  label,
  id,
  options,
  value,
  defaultValue,
  compact = false,
  className = '',
  children,
  ...rest
}) {
  const selId = id || (label ? `sel-${String(label).toLowerCase().replace(/\s+/g, '-')}` : undefined);
  const cls = ['form-input', compact && 'form-input--compact', className].filter(Boolean).join(' ');
  const opts = (options || []).map(o => typeof o === 'string' ? {
    value: o,
    label: o
  } : o);
  const select = /*#__PURE__*/React.createElement("select", _extends({
    id: selId,
    className: cls,
    value: value,
    defaultValue: defaultValue
  }, rest), children || opts.map(o => /*#__PURE__*/React.createElement("option", {
    key: o.value,
    value: o.value
  }, o.label)));
  if (!label) return select;
  return /*#__PURE__*/React.createElement("div", {
    className: "form-group"
  }, /*#__PURE__*/React.createElement("label", {
    htmlFor: selId
  }, label), select);
}
Object.assign(__ds_scope, { Select });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/forms/Select.jsx", error: String((e && e.message) || e) }); }

// components/navigation/Breadcrumbs.jsx
try { (() => {
/**
 * Vulnex Breadcrumbs — trail of links ending in the current page.
 * items: [{label, href}] — the last item renders as current (no link).
 */
function Breadcrumbs({
  items = [],
  className = ''
}) {
  return /*#__PURE__*/React.createElement("nav", {
    className: ['breadcrumbs', className].filter(Boolean).join(' '),
    "aria-label": "Breadcrumb"
  }, items.map((it, i) => {
    const last = i === items.length - 1;
    return /*#__PURE__*/React.createElement(React.Fragment, {
      key: i
    }, last || !it.href ? /*#__PURE__*/React.createElement("span", {
      className: "bc-current"
    }, it.label) : /*#__PURE__*/React.createElement("a", {
      href: it.href
    }, it.label), !last ? /*#__PURE__*/React.createElement("span", {
      className: "bc-sep"
    }, "\u203A") : null);
  }));
}
Object.assign(__ds_scope, { Breadcrumbs });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/navigation/Breadcrumbs.jsx", error: String((e && e.message) || e) }); }

// components/navigation/Tabs.jsx
try { (() => {
/**
 * Vulnex Tabs — underline tab bar. Controlled via `value` + `onChange`, or
 * uncontrolled with `defaultValue`. Tabs: [{id, label, count}].
 */
function Tabs({
  tabs = [],
  value,
  defaultValue,
  onChange,
  className = ''
}) {
  const [internal, setInternal] = React.useState(defaultValue ?? (tabs[0] && tabs[0].id));
  const active = value !== undefined ? value : internal;
  const select = id => {
    if (value === undefined) setInternal(id);
    onChange && onChange(id);
  };
  return /*#__PURE__*/React.createElement("div", {
    className: ['tab-nav', className].filter(Boolean).join(' '),
    role: "tablist"
  }, tabs.map(t => /*#__PURE__*/React.createElement("button", {
    key: t.id,
    type: "button",
    role: "tab",
    "aria-selected": active === t.id,
    className: ['tab-btn', active === t.id && 'active'].filter(Boolean).join(' '),
    onClick: () => select(t.id)
  }, t.label, t.count != null ? /*#__PURE__*/React.createElement("span", {
    className: "tab-count"
  }, t.count) : null)));
}
Object.assign(__ds_scope, { Tabs });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/navigation/Tabs.jsx", error: String((e && e.message) || e) }); }

// static/js/attack_path.js
try { (() => {
// Vanilla SVG renderer for the attack-path DAG. No D3 / no CDN — keeps CSP
// simple and the bundle weightless. Layout is column-based on topological
// depth; nodes inside the same depth fan out vertically.
(function () {
  'use strict';

  var canvas = document.getElementById('attack-path-canvas');
  if (!canvas) return;
  var dataUrl = canvas.dataset.pathDataUrl;
  var findingUrlPrefix = canvas.dataset.findingUrlPrefix || '/vulns/';
  var SVG_NS = 'http://www.w3.org/2000/svg';
  var KIND_COLOR = {
    entrypoint: '#0ea5e9',
    host: '#64748b',
    identity: '#a855f7',
    asset: '#f59e0b',
    objective: '#ef4444'
  };
  function fetchData() {
    fetch(dataUrl, {
      credentials: 'same-origin'
    }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }).then(render).catch(function (err) {
      canvas.textContent = 'Failed to load path: ' + err.message;
    });
  }
  function computeDepths(nodes, edges) {
    // Topological depth from any node with no incoming edges.
    var indegree = {},
      outAdj = {};
    nodes.forEach(function (n) {
      indegree[n.id] = 0;
      outAdj[n.id] = [];
    });
    edges.forEach(function (e) {
      if (indegree[e.to] !== undefined) indegree[e.to] += 1;
      if (outAdj[e.from]) outAdj[e.from].push(e.to);
    });
    var depths = {};
    var queue = [];
    nodes.forEach(function (n) {
      if (indegree[n.id] === 0) {
        depths[n.id] = 0;
        queue.push(n.id);
      }
    });
    // Fallback: if every node has incoming (cycle), seed with the first.
    if (queue.length === 0 && nodes.length) {
      depths[nodes[0].id] = 0;
      queue.push(nodes[0].id);
    }
    while (queue.length) {
      var cur = queue.shift();
      (outAdj[cur] || []).forEach(function (next) {
        var d = (depths[cur] || 0) + 1;
        if (depths[next] === undefined || d > depths[next]) {
          depths[next] = d;
          queue.push(next);
        }
      });
    }
    nodes.forEach(function (n) {
      if (depths[n.id] === undefined) depths[n.id] = 0;
    });
    return depths;
  }
  function layout(nodes, edges, width, height) {
    var depths = computeDepths(nodes, edges);
    var byDepth = {};
    nodes.forEach(function (n) {
      (byDepth[depths[n.id]] = byDepth[depths[n.id]] || []).push(n);
    });
    var depthKeys = Object.keys(byDepth).map(Number).sort(function (a, b) {
      return a - b;
    });

    // One pass of barycenter ordering: position each node by the average
    // index of its predecessors in the previous column so edges run roughly
    // parallel instead of fanning across the diagram.
    var orderIndex = {};
    depthKeys.forEach(function (d) {
      byDepth[d].forEach(function (n, i) {
        orderIndex[n.id] = i;
      });
    });
    var preds = {};
    edges.forEach(function (e) {
      (preds[e.to] = preds[e.to] || []).push(e.from);
    });
    depthKeys.forEach(function (d) {
      if (d === depthKeys[0]) return;
      byDepth[d].sort(function (a, b) {
        function bary(n) {
          var ps = preds[n.id] || [];
          if (!ps.length) return orderIndex[n.id];
          var sum = 0,
            count = 0;
          ps.forEach(function (pid) {
            if (orderIndex[pid] !== undefined) {
              sum += orderIndex[pid];
              count += 1;
            }
          });
          return count ? sum / count : orderIndex[n.id];
        }
        return bary(a) - bary(b);
      });
      byDepth[d].forEach(function (n, i) {
        orderIndex[n.id] = i;
      });
    });
    var maxDepth = depthKeys[depthKeys.length - 1] || 0;
    var colSpacing = (width - 160) / Math.max(maxDepth, 1);
    var positions = {};
    depthKeys.forEach(function (d) {
      var col = byDepth[d];
      var rowSpacing = (height - 60) / (col.length + 1);
      col.forEach(function (n, i) {
        positions[n.id] = {
          x: 80 + d * colSpacing,
          y: 30 + (i + 1) * rowSpacing
        };
      });
    });
    return positions;
  }
  function svg(name, attrs, parent) {
    var el = document.createElementNS(SVG_NS, name);
    Object.keys(attrs || {}).forEach(function (k) {
      el.setAttribute(k, attrs[k]);
    });
    if (parent) parent.appendChild(el);
    return el;
  }
  function render(data) {
    canvas.innerHTML = '';
    var nodes = data.nodes || [];
    var edges = data.edges || [];
    if (!nodes.length) {
      var p = document.createElement('p');
      p.className = 'text-secondary text-center';
      p.style.padding = '3rem';
      p.textContent = 'No nodes yet — add one in the sidebar to start mapping the kill chain.';
      canvas.appendChild(p);
      return;
    }
    var width = canvas.clientWidth || 800;
    var height = Math.max(canvas.clientHeight || 480, Math.min(900, nodes.length * 70));
    var root = svg('svg', {
      xmlns: SVG_NS,
      viewBox: '0 0 ' + width + ' ' + height,
      width: width,
      height: height,
      'class': 'attack-path-svg'
    }, canvas);

    // Arrowhead marker.
    var defs = svg('defs', {}, root);
    var marker = svg('marker', {
      id: 'ap-arrow',
      viewBox: '0 0 10 10',
      refX: 10,
      refY: 5,
      markerWidth: 8,
      markerHeight: 8,
      orient: 'auto-start-reverse'
    }, defs);
    svg('path', {
      d: 'M0,0 L10,5 L0,10 z',
      fill: '#cbd5e1'
    }, marker);
    var positions = layout(nodes, edges, width, height);

    // Edges first so nodes paint on top.
    edges.forEach(function (e) {
      var p1 = positions[e.from],
        p2 = positions[e.to];
      if (!p1 || !p2) return;
      var line = svg('line', {
        x1: p1.x,
        y1: p1.y,
        x2: p2.x,
        y2: p2.y,
        stroke: '#cbd5e1',
        'stroke-width': 1.5,
        'marker-end': 'url(#ap-arrow)',
        'class': 'ap-edge'
      }, root);
      if (e.finding_pk) {
        line.style.cursor = 'pointer';
        line.addEventListener('click', function () {
          window.location.href = findingUrlPrefix + e.finding_pk + '/';
        });
      }
      // Label near midpoint.
      var mx = (p1.x + p2.x) / 2;
      var my = (p1.y + p2.y) / 2 - 6;
      var label = e.technique;
      if (e.mitre) label += ' (' + e.mitre + ')';
      var t = svg('text', {
        x: mx,
        y: my,
        fill: '#94a3b8',
        'font-size': 11,
        'text-anchor': 'middle',
        'class': 'ap-edge-label'
      }, root);
      t.textContent = label;
      // Hover title.
      var title = svg('title', {}, line);
      var tip = e.technique;
      if (e.mitre) tip += ' [' + e.mitre + ']';
      if (e.finding_title) tip += '\nFinding: ' + e.finding_title;
      title.textContent = tip;
    });
    nodes.forEach(function (n) {
      var p = positions[n.id];
      if (!p) return;
      var color = KIND_COLOR[n.kind] || '#64748b';
      var g = svg('g', {
        'class': 'ap-node',
        transform: 'translate(' + p.x + ',' + p.y + ')'
      }, root);
      svg('circle', {
        r: 18,
        fill: color,
        stroke: '#1f2638',
        'stroke-width': 2
      }, g);
      var lbl = svg('text', {
        y: 36,
        'text-anchor': 'middle',
        'font-size': 12,
        fill: '#e6edf3',
        'class': 'ap-node-label'
      }, g);
      lbl.textContent = n.label.length > 28 ? n.label.slice(0, 27) + '…' : n.label;
      var sub = svg('text', {
        y: 50,
        'text-anchor': 'middle',
        'font-size': 10,
        fill: '#8b949e'
      }, g);
      sub.textContent = n.kind;
    });
  }
  fetchData();
})();
})(); } catch (e) { __ds_ns.__errors.push({ path: "static/js/attack_path.js", error: String((e && e.message) || e) }); }

// static/js/markdown_preview.js
try { (() => {
(function () {
  'use strict';

  var endpoint = window.MARKDOWN_PREVIEW_URL;
  var csrf = document.querySelector('input[name=csrfmiddlewaretoken]');
  if (!endpoint || !csrf) return;
  var token = csrf.value;
  function debounce(fn, ms) {
    var t = null;
    return function () {
      var args = arguments,
        ctx = this;
      clearTimeout(t);
      t = setTimeout(function () {
        fn.apply(ctx, args);
      }, ms);
    };
  }
  function setupField(wrap) {
    var ta = wrap.querySelector('textarea');
    var preview = wrap.querySelector('.md-preview-pane');
    var tabEdit = wrap.querySelector('[data-md-tab="edit"]');
    var tabPreview = wrap.querySelector('[data-md-tab="preview"]');
    if (!ta || !preview || !tabEdit || !tabPreview) return;
    function activate(name) {
      wrap.classList.toggle('md-tab-edit', name === 'edit');
      wrap.classList.toggle('md-tab-preview', name === 'preview');
      tabEdit.classList.toggle('active', name === 'edit');
      tabPreview.classList.toggle('active', name === 'preview');
      tabEdit.setAttribute('aria-selected', name === 'edit' ? 'true' : 'false');
      tabPreview.setAttribute('aria-selected', name === 'preview' ? 'true' : 'false');
      if (name === 'preview') refresh();
    }
    var refresh = debounce(function () {
      var raw = ta.value;
      if (!raw.trim()) {
        preview.innerHTML = '<p class="text-secondary text-sm">Nothing to preview yet.</p>';
        return;
      }
      preview.classList.add('md-preview-loading');
      var body = new URLSearchParams();
      body.set('text', raw);
      body.set('csrfmiddlewaretoken', token);
      fetch(endpoint, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'X-CSRFToken': token
        },
        body: body
      }).then(function (r) {
        return r.text();
      }).then(function (html) {
        preview.innerHTML = html || '<p class="text-secondary text-sm">Empty.</p>';
        preview.classList.remove('md-preview-loading');
      }).catch(function () {
        preview.innerHTML = '<p class="form-error">Preview failed.</p>';
        preview.classList.remove('md-preview-loading');
      });
    }, 250);
    tabEdit.addEventListener('click', function (e) {
      e.preventDefault();
      activate('edit');
    });
    tabPreview.addEventListener('click', function (e) {
      e.preventDefault();
      activate('preview');
    });
    ta.addEventListener('input', function () {
      if (wrap.classList.contains('md-tab-preview')) refresh();
    });
    activate('edit');
  }
  document.querySelectorAll('[data-md-field]').forEach(setupField);
})();
})(); } catch (e) { __ds_ns.__errors.push({ path: "static/js/markdown_preview.js", error: String((e && e.message) || e) }); }

// ui_kits/vulnex/Shell.jsx
try { (() => {
// Vulnex app shell: fixed sidebar + main content, matching the product layout.
const {
  Avatar
} = window.VulnexDesignSystem_3350b3;
function Sidebar({
  route,
  go,
  engagement
}) {
  const VIcon = window.VIcon;
  const top = [['dashboard', 'Dashboard', 'dashboard'], ['engagements', 'Engagements', 'engagements'], ['clients', 'Clients', 'clients'], ['users', 'Users', 'users'], ['audit', 'Audit log', 'audit'], ['reports', 'Report templates', 'reports']];
  const isActive = id => route === id || id === 'engagements' && (route === 'engagement' || route === 'findings' || route === 'finding');
  return /*#__PURE__*/React.createElement("aside", {
    className: "sidebar"
  }, /*#__PURE__*/React.createElement("div", {
    className: "sidebar-brand"
  }, /*#__PURE__*/React.createElement(VIcon, {
    name: "shield",
    size: 24
  }), /*#__PURE__*/React.createElement("span", null, "Vulnex")), /*#__PURE__*/React.createElement("nav", {
    className: "sidebar-nav"
  }, top.map(([id, label, icon]) => /*#__PURE__*/React.createElement("a", {
    key: id,
    href: "#",
    className: 'nav-item' + (isActive(id) ? ' active' : ''),
    onClick: e => {
      e.preventDefault();
      go(id === 'engagements' ? 'engagements' : id);
    }
  }, /*#__PURE__*/React.createElement(VIcon, {
    name: icon
  }), " ", label))), engagement ? /*#__PURE__*/React.createElement("div", {
    className: "sidebar-section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "sidebar-section-title"
  }, "Engagement"), /*#__PURE__*/React.createElement("div", {
    className: "sidebar-section-name",
    title: engagement.name
  }, engagement.name), /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: 'nav-item sub' + (route === 'engagement' ? ' active' : ''),
    onClick: e => {
      e.preventDefault();
      go('engagement');
    }
  }, "Overview"), /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: 'nav-item sub' + (route === 'findings' || route === 'finding' ? ' active' : ''),
    onClick: e => {
      e.preventDefault();
      go('findings');
    }
  }, "Findings"), /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "nav-item sub",
    onClick: e => e.preventDefault()
  }, "Recon"), /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "nav-item sub",
    onClick: e => e.preventDefault()
  }, "Credentials"), /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "nav-item sub",
    onClick: e => e.preventDefault()
  }, "Methodology"), /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "nav-item sub",
    onClick: e => e.preventDefault()
  }, "Reports")) : null, /*#__PURE__*/React.createElement("div", {
    className: "sidebar-bottom"
  }, /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "nav-item",
    onClick: e => e.preventDefault()
  }, /*#__PURE__*/React.createElement(Avatar, {
    name: "A D",
    initials: "AD",
    color: "#7a60e0"
  }), " admin"), /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "nav-item logout-btn",
    onClick: e => {
      e.preventDefault();
      go('login');
    }
  }, /*#__PURE__*/React.createElement(VIcon, {
    name: "logout"
  }), " Log out")));
}
function Shell({
  route,
  go,
  engagement,
  children
}) {
  const VIcon = window.VIcon;
  return /*#__PURE__*/React.createElement("div", {
    className: "layout"
  }, /*#__PURE__*/React.createElement(Sidebar, {
    route: route,
    go: go,
    engagement: engagement
  }), /*#__PURE__*/React.createElement("main", {
    className: "main-content"
  }, /*#__PURE__*/React.createElement("form", {
    className: "global-search",
    onSubmit: e => e.preventDefault()
  }, /*#__PURE__*/React.createElement("span", {
    className: "global-search-icon"
  }, /*#__PURE__*/React.createElement(VIcon, {
    name: "search",
    size: 16
  })), /*#__PURE__*/React.createElement("input", {
    className: "global-search-input",
    placeholder: "Search findings, engagements, hosts\u2026  (press /)"
  })), children));
}
window.Sidebar = Sidebar;
window.Shell = Shell;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/vulnex/Shell.jsx", error: String((e && e.message) || e) }); }

// ui_kits/vulnex/app.jsx
try { (() => {
// Vulnex UI-kit app — minimal in-memory router across the core screens.
function App() {
  const data = window.VULNEX_DATA;
  const [state, setState] = React.useState({
    route: 'login',
    engId: null,
    findingId: null
  });
  const go = (route, engId, findingId) => setState(s => ({
    route,
    engId: engId !== undefined ? engId : s.engId,
    findingId: findingId !== undefined ? findingId : s.findingId
  }));
  const engagement = data.engagements.find(e => e.id === state.engId) || null;
  const finding = data.findings.find(f => f.id === state.findingId) || null;
  if (state.route === 'login') return /*#__PURE__*/React.createElement(window.LoginScreen, {
    go: go
  });
  let screen;
  switch (state.route) {
    case 'dashboard':
      screen = /*#__PURE__*/React.createElement(window.DashboardScreen, {
        go: go
      });
      break;
    case 'engagements':
      screen = /*#__PURE__*/React.createElement(window.EngagementsScreen, {
        go: go
      });
      break;
    case 'engagement':
      screen = /*#__PURE__*/React.createElement(window.EngagementScreen, {
        go: go,
        engagement: engagement
      });
      break;
    case 'findings':
      screen = /*#__PURE__*/React.createElement(window.FindingsScreen, {
        go: go,
        engagement: engagement
      });
      break;
    case 'finding':
      screen = /*#__PURE__*/React.createElement(window.FindingDetailScreen, {
        go: go,
        engagement: engagement,
        finding: finding
      });
      break;
    case 'clients':
    case 'users':
    case 'audit':
    case 'reports':
      screen = /*#__PURE__*/React.createElement(SimplePlaceholder, {
        route: state.route
      });
      break;
    default:
      screen = /*#__PURE__*/React.createElement(window.DashboardScreen, {
        go: go
      });
  }
  return /*#__PURE__*/React.createElement(window.Shell, {
    route: state.route,
    go: go,
    engagement: state.route === 'dashboard' || state.route === 'engagements' ? null : engagement
  }, screen);
}
function SimplePlaceholder({
  route
}) {
  const {
    Card,
    EmptyState
  } = window.VulnexDesignSystem_3350b3;
  const titles = {
    clients: 'Clients',
    users: 'Users & roles',
    audit: 'Audit log',
    reports: 'Report templates'
  };
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "page-header"
  }, /*#__PURE__*/React.createElement("h1", {
    className: "page-title"
  }, titles[route])), /*#__PURE__*/React.createElement(Card, null, /*#__PURE__*/React.createElement(EmptyState, {
    icon: /*#__PURE__*/React.createElement(window.VIcon, {
      name: "shield",
      size: 22
    }),
    title: titles[route],
    subtitle: "This area exists in the product \u2014 left as a stub in the interactive demo."
  })));
}
ReactDOM.createRoot(document.getElementById('root')).render(/*#__PURE__*/React.createElement(App, null));
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/vulnex/app.jsx", error: String((e && e.message) || e) }); }

// ui_kits/vulnex/data.jsx
try { (() => {
// Demo data — mirrors the Vulnex seed_demo fixture (Acme Corp, 2 engagements, 8 findings).
window.VULNEX_DATA = {
  engagements: [{
    id: 'red',
    name: 'Acme Corp — Red Team Adversary Simulation',
    client: 'Acme Corp',
    type: 'Red team',
    status: 'exploitation',
    statusLabel: 'Exploitation',
    phase: 3,
    findingCount: 5,
    lead: 'Dana Okoye',
    window: 'Jun 2 – Jun 24, 2026',
    scope: ['*.acme.example', 'dc01.internal.acme.example', '10.10.0.0/16']
  }, {
    id: 'ext',
    name: 'Acme Corp — Q2 External Pentest',
    client: 'Acme Corp',
    type: 'External',
    status: 'reporting',
    statusLabel: 'Reporting',
    phase: 4,
    findingCount: 3,
    lead: 'Dana Okoye',
    window: 'May 12 – May 30, 2026',
    scope: ['app.acme.example', 'api.acme.example']
  }],
  findings: [{
    id: 'f1',
    eng: 'red',
    title: 'Kerberoastable service account with weak password',
    host: 'dc01.internal.acme.example',
    port: 88,
    severity: 'critical',
    sevLabel: 'Critical',
    cvss: 9.1,
    status: 'open',
    statusLabel: 'Open',
    review: 'in_review',
    reviewLabel: 'In review',
    assignee: 'Dana Okoye',
    due: 'Jun 24',
    sla: 'on_track',
    date: 'Jun 10, 2026'
  }, {
    id: 'f2',
    eng: 'red',
    title: 'Unconstrained delegation on legacy host',
    host: 'srv-print01.acme.example',
    port: 445,
    severity: 'high',
    sevLabel: 'High',
    cvss: 8.1,
    status: 'confirmed',
    statusLabel: 'Confirmed',
    review: 'approved',
    reviewLabel: 'Approved',
    assignee: 'Dana Okoye',
    due: 'Jun 28',
    sla: 'on_track',
    date: 'Jun 9, 2026'
  }, {
    id: 'f3',
    eng: 'red',
    title: 'LLMNR/NBT-NS poisoning yields NetNTLMv2 hashes',
    host: '10.10.4.0/24',
    port: null,
    severity: 'high',
    sevLabel: 'High',
    cvss: 7.4,
    status: 'open',
    statusLabel: 'Open',
    review: 'draft',
    reviewLabel: 'Draft',
    assignee: null,
    due: 'Jun 26',
    sla: 'due_soon',
    date: 'Jun 8, 2026'
  }, {
    id: 'f4',
    eng: 'red',
    title: 'Shared local admin password across workstations',
    host: '10.10.12.0/24',
    port: null,
    severity: 'medium',
    sevLabel: 'Medium',
    cvss: 6.5,
    status: 'confirmed',
    statusLabel: 'Confirmed',
    review: 'in_review',
    reviewLabel: 'In review',
    assignee: 'Dana Okoye',
    due: 'Jul 2',
    sla: 'on_track',
    date: 'Jun 7, 2026'
  }, {
    id: 'f5',
    eng: 'red',
    title: 'Verbose SMB signing disabled',
    host: 'fs01.acme.example',
    port: 445,
    severity: 'low',
    sevLabel: 'Low',
    cvss: 3.7,
    status: 'accepted',
    statusLabel: 'Accepted',
    review: 'approved',
    reviewLabel: 'Approved',
    assignee: 'Dana Okoye',
    due: null,
    sla: 'closed',
    date: 'Jun 6, 2026'
  }, {
    id: 'f6',
    eng: 'ext',
    title: 'SQL injection in invoice search parameter',
    host: 'app.acme.example',
    port: 443,
    severity: 'critical',
    sevLabel: 'Critical',
    cvss: 9.8,
    status: 'remediated',
    statusLabel: 'Remediated',
    review: 'approved',
    reviewLabel: 'Approved',
    assignee: 'Dana Okoye',
    due: null,
    sla: 'closed',
    date: 'May 18, 2026'
  }, {
    id: 'f7',
    eng: 'ext',
    title: 'Stored XSS in support ticket subject',
    host: 'app.acme.example',
    port: 443,
    severity: 'high',
    sevLabel: 'High',
    cvss: 7.2,
    status: 'confirmed',
    statusLabel: 'Confirmed',
    review: 'approved',
    reviewLabel: 'Approved',
    assignee: 'Dana Okoye',
    due: 'May 30',
    sla: 'on_track',
    date: 'May 16, 2026'
  }, {
    id: 'f8',
    eng: 'ext',
    title: 'Missing rate-limit on password reset endpoint',
    host: 'api.acme.example',
    port: 443,
    severity: 'medium',
    sevLabel: 'Medium',
    cvss: 5.3,
    status: 'open',
    statusLabel: 'Open',
    review: 'in_review',
    reviewLabel: 'In review',
    assignee: null,
    due: 'May 30',
    sla: 'overdue',
    date: 'May 15, 2026'
  }]
};
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/vulnex/data.jsx", error: String((e && e.message) || e) }); }

// ui_kits/vulnex/icons.jsx
try { (() => {
// Vulnex inline stroke icons — Feather/Lucide style, 24 grid, 2px, currentColor.
// Faithful to the SVGs used in the product's base template.
const VIcon = ({
  name,
  size = 18,
  sw = 2,
  ...rest
}) => {
  const p = {
    width: size,
    height: size,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: sw,
    strokeLinecap: 'round',
    strokeLinejoin: 'round',
    ...rest
  };
  switch (name) {
    case 'shield':
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("path", {
        d: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"
      }));
    case 'dashboard':
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("rect", {
        x: "3",
        y: "3",
        width: "7",
        height: "7"
      }), /*#__PURE__*/React.createElement("rect", {
        x: "14",
        y: "3",
        width: "7",
        height: "7"
      }), /*#__PURE__*/React.createElement("rect", {
        x: "3",
        y: "14",
        width: "7",
        height: "7"
      }), /*#__PURE__*/React.createElement("rect", {
        x: "14",
        y: "14",
        width: "7",
        height: "7"
      }));
    case 'engagements':
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("path", {
        d: "M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"
      }));
    case 'clients':
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("path", {
        d: "M3 21h18"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M5 21V7l7-4 7 4v14"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M9 9h1M9 13h1M9 17h1M14 9h1M14 13h1M14 17h1"
      }));
    case 'users':
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("path", {
        d: "M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"
      }), /*#__PURE__*/React.createElement("circle", {
        cx: "9",
        cy: "7",
        r: "4"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M23 21v-2a4 4 0 00-3-3.87"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M16 3.13a4 4 0 010 7.75"
      }));
    case 'audit':
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("path", {
        d: "M12 2l3 7h7l-5.5 4.5L18 21l-6-4-6 4 1.5-7.5L2 9h7z"
      }));
    case 'reports':
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("path", {
        d: "M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M7 8h10M7 12h6"
      }));
    case 'search':
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("circle", {
        cx: "11",
        cy: "11",
        r: "8"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "21",
        y1: "21",
        x2: "16.65",
        y2: "16.65"
      }));
    case 'logout':
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("path", {
        d: "M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"
      }), /*#__PURE__*/React.createElement("polyline", {
        points: "16 17 21 12 16 7"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "21",
        y1: "12",
        x2: "9",
        y2: "12"
      }));
    case 'radar':
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("path", {
        d: "M19.07 4.93A10 10 0 1 0 22 12"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M16.24 7.76A6 6 0 1 0 18 12"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M12 12l8-8"
      }), /*#__PURE__*/React.createElement("circle", {
        cx: "12",
        cy: "12",
        r: "1.5",
        fill: "currentColor",
        stroke: "none"
      }));
    case 'key':
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("circle", {
        cx: "7.5",
        cy: "15.5",
        r: "4.5"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M10.5 12.5L20 3"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M16 7l3 3"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M14 9l3 3"
      }));
    case 'check-square':
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("polyline", {
        points: "9 11 12 14 22 4"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"
      }));
    case 'plus':
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("line", {
        x1: "12",
        y1: "5",
        x2: "12",
        y2: "19"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "5",
        y1: "12",
        x2: "19",
        y2: "12"
      }));
    case 'upload':
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("path", {
        d: "M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"
      }), /*#__PURE__*/React.createElement("polyline", {
        points: "17 8 12 3 7 8"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "12",
        y1: "3",
        x2: "12",
        y2: "15"
      }));
    case 'download':
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("path", {
        d: "M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"
      }), /*#__PURE__*/React.createElement("polyline", {
        points: "7 10 12 15 17 10"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "12",
        y1: "3",
        x2: "12",
        y2: "15"
      }));
    case 'chevron-down':
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("polyline", {
        points: "6 9 12 15 18 9"
      }));
    case 'git-branch':
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("line", {
        x1: "6",
        y1: "3",
        x2: "6",
        y2: "15"
      }), /*#__PURE__*/React.createElement("circle", {
        cx: "18",
        cy: "6",
        r: "3"
      }), /*#__PURE__*/React.createElement("circle", {
        cx: "6",
        cy: "18",
        r: "3"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M18 9a9 9 0 01-9 9"
      }));
    case 'clock':
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("circle", {
        cx: "12",
        cy: "12",
        r: "10"
      }), /*#__PURE__*/React.createElement("polyline", {
        points: "12 6 12 12 16 14"
      }));
    case 'alert-triangle':
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("path", {
        d: "M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "12",
        y1: "9",
        x2: "12",
        y2: "13"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "12",
        y1: "17",
        x2: "12.01",
        y2: "17"
      }));
    case 'shield-off':
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("path", {
        d: "M19.69 14a6.9 6.9 0 00.31-2V5l-8-3-3.16 1.18"
      }), /*#__PURE__*/React.createElement("path", {
        d: "M4.73 4.73L4 5v7c0 6 8 10 8 10a20.29 20.29 0 005.62-4.38"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "1",
        y1: "1",
        x2: "23",
        y2: "23"
      }));
    default:
      return /*#__PURE__*/React.createElement("svg", p, /*#__PURE__*/React.createElement("circle", {
        cx: "12",
        cy: "12",
        r: "10"
      }));
  }
};
window.VIcon = VIcon;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/vulnex/icons.jsx", error: String((e && e.message) || e) }); }

// ui_kits/vulnex/screens.jsx
try { (() => {
// Vulnex UI-kit screens — compose the DS primitives into real product views.
const DS = window.VulnexDesignSystem_3350b3;
const {
  Button,
  Badge,
  Card,
  StatCard,
  Input,
  Select,
  Tabs,
  Breadcrumbs,
  KpiStrip,
  PhaseStepper,
  EmptyState,
  ProgressBar,
  Avatar
} = DS;
const PHASES = ['Planning', 'Recon', 'Scanning', 'Exploitation', 'Reporting', 'Completed'];

/* ── Login ─────────────────────────────────────────────── */
function LoginScreen({
  go
}) {
  const VIcon = window.VIcon;
  return /*#__PURE__*/React.createElement("div", {
    className: "auth-page"
  }, /*#__PURE__*/React.createElement("div", {
    className: "auth-card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "auth-brand"
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'center',
      color: '#a28ff0'
    }
  }, /*#__PURE__*/React.createElement(VIcon, {
    name: "shield",
    size: 40
  })), /*#__PURE__*/React.createElement("h1", null, "Vulnex"), /*#__PURE__*/React.createElement("p", null, "Penetration testing workflow platform")), /*#__PURE__*/React.createElement("form", {
    onSubmit: e => {
      e.preventDefault();
      go('dashboard');
    }
  }, /*#__PURE__*/React.createElement(Input, {
    label: "Username",
    defaultValue: "demo-pentester"
  }), /*#__PURE__*/React.createElement(Input, {
    label: "Password",
    type: "password",
    defaultValue: "demo-password"
  }), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    fullWidth: true,
    type: "submit"
  }, "Log in")), /*#__PURE__*/React.createElement("p", {
    className: "auth-footer"
  }, "Contact your administrator for an account.")));
}

/* ── Dashboard ─────────────────────────────────────────── */
function DashboardScreen({
  go
}) {
  const data = window.VULNEX_DATA;
  const sev = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  data.findings.forEach(f => sev[f.severity]++);
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "page-header"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    className: "page-title"
  }, "Dashboard"), /*#__PURE__*/React.createElement("p", {
    className: "page-subtitle"
  }, "Welcome back, demo-pentester")), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: () => go('engagements')
  }, "+ New engagement")), /*#__PURE__*/React.createElement("div", {
    className: "stats-grid"
  }, /*#__PURE__*/React.createElement(StatCard, {
    label: "Risk score",
    value: "7.8",
    valueColor: "#f09236",
    sub: "High",
    subTone: "#f09236"
  }), /*#__PURE__*/React.createElement(StatCard, {
    label: "Active engagements",
    value: "2"
  }), /*#__PURE__*/React.createElement(StatCard, {
    label: "Total findings",
    value: data.findings.length
  }), /*#__PURE__*/React.createElement(StatCard, {
    label: "Critical / High",
    value: sev.critical,
    valueTone: "critical",
    sub: sev.high + ' high',
    subTone: "high"
  }), /*#__PURE__*/React.createElement(StatCard, {
    label: "Overdue findings",
    value: "1",
    valueTone: "critical",
    sub: "1 due soon",
    subTone: "high"
  }), /*#__PURE__*/React.createElement(StatCard, {
    label: "Assigned to me",
    value: "5",
    sub: "0 overdue"
  })), /*#__PURE__*/React.createElement("div", {
    className: "grid-2 mb-4"
  }, /*#__PURE__*/React.createElement(Card, {
    title: "Severity distribution"
  }, /*#__PURE__*/React.createElement(DonutLegend, {
    rows: [['Critical', sev.critical, '#f05853'], ['High', sev.high, '#f09236'], ['Medium', sev.medium, '#e3b341'], ['Low', sev.low, '#58a6ff']]
  })), /*#__PURE__*/React.createElement(Card, {
    title: "Findings over time"
  }, /*#__PURE__*/React.createElement(Sparkline, null))), /*#__PURE__*/React.createElement(Card, {
    title: "Urgent findings",
    actions: /*#__PURE__*/React.createElement(Button, {
      size: "sm",
      onClick: () => {
        go('engagement', 'red');
      }
    }, "View engagement")
  }, /*#__PURE__*/React.createElement("div", {
    className: "table-wrap"
  }, /*#__PURE__*/React.createElement("table", null, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", null, "Finding"), /*#__PURE__*/React.createElement("th", null, "Severity"), /*#__PURE__*/React.createElement("th", null, "Engagement"), /*#__PURE__*/React.createElement("th", null, "CVSS"))), /*#__PURE__*/React.createElement("tbody", null, data.findings.filter(f => ['critical', 'high'].includes(f.severity)).slice(0, 4).map(f => /*#__PURE__*/React.createElement("tr", {
    key: f.id,
    style: {
      cursor: 'pointer'
    },
    onClick: () => go('finding', f.eng, f.id)
  }, /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement("a", {
    href: "#",
    onClick: e => e.preventDefault()
  }, /*#__PURE__*/React.createElement("strong", null, f.title))), /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement(Badge, {
    tone: f.severity
  }, f.sevLabel)), /*#__PURE__*/React.createElement("td", {
    className: "text-secondary text-sm"
  }, f.eng === 'red' ? 'Red Team' : 'Q2 External'), /*#__PURE__*/React.createElement("td", {
    className: "text-mono font-semibold"
  }, f.cvss.toFixed(1)))))))));
}

/* ── Engagements list ──────────────────────────────────── */
function EngagementsScreen({
  go
}) {
  const data = window.VULNEX_DATA;
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "page-header"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    className: "page-title"
  }, "Engagements"), /*#__PURE__*/React.createElement("p", {
    className: "page-subtitle"
  }, data.engagements.length, " active")), /*#__PURE__*/React.createElement(Button, {
    variant: "primary"
  }, "+ New engagement")), /*#__PURE__*/React.createElement(Card, null, /*#__PURE__*/React.createElement("div", {
    className: "table-wrap"
  }, /*#__PURE__*/React.createElement("table", null, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", null, "Name"), /*#__PURE__*/React.createElement("th", null, "Type"), /*#__PURE__*/React.createElement("th", null, "Status"), /*#__PURE__*/React.createElement("th", null, "Findings"), /*#__PURE__*/React.createElement("th", null, "Window"))), /*#__PURE__*/React.createElement("tbody", null, data.engagements.map(e => /*#__PURE__*/React.createElement("tr", {
    key: e.id,
    style: {
      cursor: 'pointer'
    },
    onClick: () => go('engagement', e.id)
  }, /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement("a", {
    href: "#",
    onClick: ev => ev.preventDefault()
  }, /*#__PURE__*/React.createElement("strong", null, e.name))), /*#__PURE__*/React.createElement("td", {
    className: "text-sm text-secondary"
  }, e.type), /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement(Badge, {
    tone: e.status
  }, e.statusLabel)), /*#__PURE__*/React.createElement("td", {
    className: "text-mono"
  }, e.findingCount), /*#__PURE__*/React.createElement("td", {
    className: "text-sm text-secondary"
  }, e.window))))))));
}

/* ── Engagement detail ─────────────────────────────────── */
function EngagementScreen({
  go,
  engagement
}) {
  const data = window.VULNEX_DATA;
  const e = engagement;
  const findings = data.findings.filter(f => f.eng === e.id);
  const [tab, setTab] = React.useState('overview');
  const crit = findings.filter(f => f.severity === 'critical').length;
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement(Breadcrumbs, {
    items: [{
      label: 'Engagements',
      href: '#'
    }, {
      label: e.name
    }]
  }), /*#__PURE__*/React.createElement("div", {
    className: "eng-hero"
  }, /*#__PURE__*/React.createElement("div", {
    className: "eng-hero-main"
  }, /*#__PURE__*/React.createElement("div", {
    className: "eng-hero-title"
  }, e.name), /*#__PURE__*/React.createElement("div", {
    className: "eng-hero-meta"
  }, /*#__PURE__*/React.createElement("span", {
    className: "eng-meta-item eng-meta-client"
  }, e.client), /*#__PURE__*/React.createElement("span", {
    className: "eng-meta-item"
  }, e.type), /*#__PURE__*/React.createElement("span", {
    className: "eng-meta-item"
  }, e.window), /*#__PURE__*/React.createElement("span", {
    className: "eng-meta-item"
  }, "Lead: ", e.lead))), /*#__PURE__*/React.createElement("div", {
    className: "eng-hero-actions"
  }, /*#__PURE__*/React.createElement(Badge, {
    tone: e.status,
    size: "lg"
  }, e.statusLabel), /*#__PURE__*/React.createElement(Button, {
    onClick: () => go('findings')
  }, "View findings"))), /*#__PURE__*/React.createElement(PhaseStepper, {
    current: e.phase,
    steps: PHASES
  }), /*#__PURE__*/React.createElement(KpiStrip, {
    items: [{
      label: 'Findings',
      value: e.findingCount,
      sub: crit + ' critical'
    }, {
      label: 'Open',
      value: findings.filter(f => f.status === 'open').length
    }, {
      label: 'Overdue',
      value: findings.filter(f => f.sla === 'overdue').length,
      sub: 'SLA'
    }, {
      label: 'Phase',
      value: e.statusLabel
    }]
  }), /*#__PURE__*/React.createElement(Tabs, {
    value: tab,
    onChange: setTab,
    tabs: [{
      id: 'overview',
      label: 'Overview'
    }, {
      id: 'findings',
      label: 'Findings',
      count: e.findingCount
    }, {
      id: 'members',
      label: 'Members'
    }, {
      id: 'notes',
      label: 'Notes'
    }]
  }), tab === 'overview' ? /*#__PURE__*/React.createElement("div", {
    className: "overview-grid"
  }, /*#__PURE__*/React.createElement(Card, {
    title: "Scope",
    fit: true
  }, e.scope.map((s, i) => /*#__PURE__*/React.createElement("div", {
    className: "scope-target",
    key: i
  }, s))), /*#__PURE__*/React.createElement(Card, {
    title: "Quick actions",
    fit: true
  }, /*#__PURE__*/React.createElement("div", {
    className: "quick-actions"
  }, /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "quick-action qa-primary",
    onClick: ev => {
      ev.preventDefault();
      go('findings');
    }
  }, /*#__PURE__*/React.createElement("span", {
    className: "qa-icon"
  }, /*#__PURE__*/React.createElement(window.VIcon, {
    name: "plus"
  })), /*#__PURE__*/React.createElement("span", {
    className: "qa-text"
  }, /*#__PURE__*/React.createElement("span", {
    className: "qa-label"
  }, "Add finding"), /*#__PURE__*/React.createElement("span", {
    className: "qa-sub"
  }, "Document a new vulnerability"))), /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "quick-action",
    onClick: ev => ev.preventDefault()
  }, /*#__PURE__*/React.createElement("span", {
    className: "qa-icon"
  }, /*#__PURE__*/React.createElement(window.VIcon, {
    name: "upload"
  })), /*#__PURE__*/React.createElement("span", {
    className: "qa-text"
  }, /*#__PURE__*/React.createElement("span", {
    className: "qa-label"
  }, "Import from scanner"), /*#__PURE__*/React.createElement("span", {
    className: "qa-sub"
  }, "Nuclei, Burp, Nessus, Nmap\u2026"))), /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "quick-action",
    onClick: ev => ev.preventDefault()
  }, /*#__PURE__*/React.createElement("span", {
    className: "qa-icon"
  }, /*#__PURE__*/React.createElement(window.VIcon, {
    name: "reports"
  })), /*#__PURE__*/React.createElement("span", {
    className: "qa-text"
  }, /*#__PURE__*/React.createElement("span", {
    className: "qa-label"
  }, "Generate report"), /*#__PURE__*/React.createElement("span", {
    className: "qa-sub"
  }, "Executive or technical PDF")))))) : tab === 'findings' ? /*#__PURE__*/React.createElement(FindingsTable, {
    findings: findings,
    go: go
  }) : /*#__PURE__*/React.createElement(Card, null, /*#__PURE__*/React.createElement(EmptyState, {
    icon: /*#__PURE__*/React.createElement(window.VIcon, {
      name: "check-square",
      size: 22
    }),
    title: "Nothing here yet",
    subtitle: "This tab is part of the demo shell."
  })));
}

/* ── Findings list ─────────────────────────────────────── */
function FindingsScreen({
  go,
  engagement
}) {
  const data = window.VULNEX_DATA;
  const findings = data.findings.filter(f => f.eng === engagement.id);
  const [sev, setSev] = React.useState('');
  const shown = sev ? findings.filter(f => f.severity === sev) : findings;
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement(Breadcrumbs, {
    items: [{
      label: 'Engagements',
      href: '#'
    }, {
      label: engagement.name,
      href: '#'
    }, {
      label: 'Findings'
    }]
  }), /*#__PURE__*/React.createElement("div", {
    className: "page-header"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    className: "page-title"
  }, "Findings"), /*#__PURE__*/React.createElement("p", {
    className: "page-subtitle"
  }, engagement.name, " \xB7 ", findings.length, " total")), /*#__PURE__*/React.createElement("div", {
    className: "btn-group"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "primary"
  }, /*#__PURE__*/React.createElement(window.VIcon, {
    name: "plus",
    size: 15
  }), " Add finding"), /*#__PURE__*/React.createElement(Button, null, /*#__PURE__*/React.createElement(window.VIcon, {
    name: "upload",
    size: 15
  }), " Import"), /*#__PURE__*/React.createElement(Button, null, /*#__PURE__*/React.createElement(window.VIcon, {
    name: "download",
    size: 15
  }), " Export CSV"))), /*#__PURE__*/React.createElement("div", {
    className: "filter-bar"
  }, /*#__PURE__*/React.createElement(Input, {
    placeholder: "Search findings...",
    className: "search-input"
  }), /*#__PURE__*/React.createElement(Select, {
    compact: true,
    value: sev,
    onChange: e => setSev(e.target.value),
    options: [{
      value: '',
      label: 'All severities'
    }, {
      value: 'critical',
      label: 'Critical'
    }, {
      value: 'high',
      label: 'High'
    }, {
      value: 'medium',
      label: 'Medium'
    }, {
      value: 'low',
      label: 'Low'
    }]
  }), /*#__PURE__*/React.createElement(Button, {
    variant: "primary"
  }, "Filter")), /*#__PURE__*/React.createElement(Card, null, /*#__PURE__*/React.createElement(FindingsTable, {
    findings: shown,
    go: go
  })));
}
function FindingsTable({
  findings,
  go
}) {
  if (!findings.length) return /*#__PURE__*/React.createElement(EmptyState, {
    icon: /*#__PURE__*/React.createElement(window.VIcon, {
      name: "shield-off",
      size: 22
    }),
    title: "No findings match",
    subtitle: "Try clearing the severity filter."
  });
  return /*#__PURE__*/React.createElement("div", {
    className: "table-wrap"
  }, /*#__PURE__*/React.createElement("table", null, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", null, "Title"), /*#__PURE__*/React.createElement("th", null, "Host"), /*#__PURE__*/React.createElement("th", null, "Severity"), /*#__PURE__*/React.createElement("th", null, "CVSS"), /*#__PURE__*/React.createElement("th", null, "Status"), /*#__PURE__*/React.createElement("th", null, "Review"), /*#__PURE__*/React.createElement("th", null, "Assignee"), /*#__PURE__*/React.createElement("th", null, "Due"))), /*#__PURE__*/React.createElement("tbody", null, findings.map(f => /*#__PURE__*/React.createElement("tr", {
    key: f.id,
    style: {
      cursor: 'pointer'
    },
    onClick: () => go('finding', f.eng, f.id)
  }, /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement("a", {
    href: "#",
    onClick: e => e.preventDefault()
  }, /*#__PURE__*/React.createElement("strong", null, f.title))), /*#__PURE__*/React.createElement("td", {
    className: "text-mono text-sm"
  }, f.host, f.port ? /*#__PURE__*/React.createElement("span", {
    className: "text-muted"
  }, ":", f.port) : null), /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement(Badge, {
    tone: f.severity
  }, f.sevLabel)), /*#__PURE__*/React.createElement("td", {
    className: "text-mono font-semibold"
  }, f.cvss.toFixed(1)), /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement(Badge, {
    tone: f.status
  }, f.statusLabel)), /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement(Badge, {
    tone: f.review
  }, f.reviewLabel)), /*#__PURE__*/React.createElement("td", {
    className: "text-sm"
  }, f.assignee || /*#__PURE__*/React.createElement("span", {
    className: "text-muted"
  }, "Unassigned")), /*#__PURE__*/React.createElement("td", {
    className: "text-sm"
  }, f.sla === 'closed' ? /*#__PURE__*/React.createElement("span", {
    className: "text-muted"
  }, "\u2014") : f.sla === 'overdue' ? /*#__PURE__*/React.createElement(Badge, {
    tone: "overdue"
  }, "Overdue") : f.sla === 'due_soon' ? /*#__PURE__*/React.createElement(Badge, {
    tone: "due_soon"
  }, f.due) : /*#__PURE__*/React.createElement("span", {
    className: "text-secondary"
  }, f.due)))))));
}

/* ── Finding detail ────────────────────────────────────── */
function FindingDetailScreen({
  go,
  engagement,
  finding
}) {
  const f = finding;
  const [tab, setTab] = React.useState('overview');
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement(Breadcrumbs, {
    items: [{
      label: 'Engagements',
      href: '#'
    }, {
      label: engagement.name,
      href: '#'
    }, {
      label: 'Findings',
      href: '#'
    }, {
      label: f.title
    }]
  }), /*#__PURE__*/React.createElement("div", {
    className: "eng-hero"
  }, /*#__PURE__*/React.createElement("div", {
    className: "eng-hero-main"
  }, /*#__PURE__*/React.createElement("div", {
    className: "eng-hero-title"
  }, f.title), /*#__PURE__*/React.createElement("div", {
    className: "eng-hero-meta"
  }, /*#__PURE__*/React.createElement("span", {
    className: "eng-meta-item eng-meta-client"
  }, engagement.name), /*#__PURE__*/React.createElement("span", {
    className: "eng-meta-item text-mono"
  }, f.host, f.port ? ':' + f.port : ''), /*#__PURE__*/React.createElement("span", {
    className: "eng-meta-item"
  }, f.date))), /*#__PURE__*/React.createElement("div", {
    className: "eng-hero-actions"
  }, /*#__PURE__*/React.createElement(Badge, {
    tone: f.severity,
    size: "lg"
  }, f.sevLabel), /*#__PURE__*/React.createElement(Badge, {
    tone: f.status,
    size: "lg"
  }, f.statusLabel), /*#__PURE__*/React.createElement(Badge, {
    tone: f.review,
    size: "lg"
  }, f.reviewLabel), /*#__PURE__*/React.createElement(Button, null, "Edit"), /*#__PURE__*/React.createElement(Button, {
    variant: "danger"
  }, "Delete"))), /*#__PURE__*/React.createElement("div", {
    className: "kpi-strip",
    style: {
      marginBottom: 24
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "kpi-item"
  }, /*#__PURE__*/React.createElement("span", {
    className: "kpi-label"
  }, "CVSS score"), /*#__PURE__*/React.createElement("span", {
    className: "kpi-value",
    style: {
      color: '#f09236'
    }
  }, f.cvss.toFixed(1)), /*#__PURE__*/React.createElement("span", {
    className: "kpi-sub"
  }, f.sevLabel)), /*#__PURE__*/React.createElement("div", {
    className: "kpi-item"
  }, /*#__PURE__*/React.createElement("span", {
    className: "kpi-label"
  }, "Status"), /*#__PURE__*/React.createElement("span", {
    className: "kpi-value",
    style: {
      fontSize: 18
    }
  }, f.statusLabel), /*#__PURE__*/React.createElement("span", {
    className: "kpi-sub"
  }, f.date)), /*#__PURE__*/React.createElement("div", {
    className: "kpi-item"
  }, /*#__PURE__*/React.createElement("span", {
    className: "kpi-label"
  }, "SLA"), /*#__PURE__*/React.createElement("span", {
    className: "kpi-value",
    style: {
      fontSize: 18
    }
  }, f.due || '—'), /*#__PURE__*/React.createElement("span", {
    className: "kpi-sub"
  }, f.sla.replace('_', ' '))), /*#__PURE__*/React.createElement("div", {
    className: "kpi-item"
  }, /*#__PURE__*/React.createElement("span", {
    className: "kpi-label"
  }, "Assigned to"), /*#__PURE__*/React.createElement("span", {
    className: "kpi-value",
    style: {
      fontSize: 18
    }
  }, f.assignee || 'Unassigned'), /*#__PURE__*/React.createElement("span", {
    className: "kpi-sub"
  }, f.assignee ? 'owner' : 'no owner yet'))), /*#__PURE__*/React.createElement(Tabs, {
    value: tab,
    onChange: setTab,
    tabs: [{
      id: 'overview',
      label: 'Overview'
    }, {
      id: 'evidence',
      label: 'Evidence'
    }, {
      id: 'cvss',
      label: 'CVSS'
    }, {
      id: 'retest',
      label: 'Retest'
    }, {
      id: 'review',
      label: 'Review'
    }, {
      id: 'comments',
      label: 'Comments'
    }]
  }), tab === 'overview' ? /*#__PURE__*/React.createElement(Card, {
    title: "Description"
  }, /*#__PURE__*/React.createElement("div", {
    className: "prose"
  }, /*#__PURE__*/React.createElement("p", null, "A service account ", /*#__PURE__*/React.createElement("code", null, "svc-sql"), " is configured with an SPN and a weak, crackable password, allowing any authenticated domain user to request a Kerberos service ticket and crack it offline (Kerberoasting)."), /*#__PURE__*/React.createElement("h3", null, "Impact"), /*#__PURE__*/React.createElement("p", null, "Recovery of the plaintext credential grants access to the backing SQL host and lateral movement toward domain compromise."), /*#__PURE__*/React.createElement("h3", null, "Remediation"), /*#__PURE__*/React.createElement("ul", null, /*#__PURE__*/React.createElement("li", null, "Rotate the service account password to a 25+ character random value."), /*#__PURE__*/React.createElement("li", null, "Migrate to a Group Managed Service Account (gMSA) where possible."), /*#__PURE__*/React.createElement("li", null, "Restrict SPNs to only required services.")))) : tab === 'review' ? /*#__PURE__*/React.createElement(Card, {
    title: "Review & approval",
    actions: /*#__PURE__*/React.createElement(Badge, {
      tone: "approved",
      size: "lg"
    }, "Approved")
  }, /*#__PURE__*/React.createElement("p", {
    className: "text-secondary",
    style: {
      color: '#3fb950'
    }
  }, "This finding is approved and visible to the client.")) : /*#__PURE__*/React.createElement(Card, null, /*#__PURE__*/React.createElement(EmptyState, {
    icon: /*#__PURE__*/React.createElement(window.VIcon, {
      name: "check-square",
      size: 22
    }),
    title: "Demo shell",
    subtitle: 'The ' + tab + ' tab is part of the interactive demo.'
  })));
}

/* ── tiny chart stand-ins (Chart.js is used in the real product) ── */
function DonutLegend({
  rows
}) {
  const total = rows.reduce((a, [, n]) => a + n, 0) || 1;
  let acc = 0;
  const segs = rows.map(([, n, c]) => {
    const start = acc / total * 360;
    acc += n;
    return `${c} ${start}deg ${acc / total * 360}deg`;
  }).join(', ');
  return /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: 28,
      padding: '8px 4px'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 130,
      height: 130,
      borderRadius: '50%',
      background: `conic-gradient(${segs})`,
      WebkitMask: 'radial-gradient(circle 40px at center, transparent 98%, #000 100%)',
      mask: 'radial-gradient(circle 40px at center, transparent 98%, #000 100%)'
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: 8
    }
  }, rows.map(([label, n, c]) => /*#__PURE__*/React.createElement("div", {
    key: label,
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: 8,
      fontSize: 13
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 10,
      height: 10,
      borderRadius: 2,
      background: c
    }
  }), /*#__PURE__*/React.createElement("span", {
    className: "text-secondary",
    style: {
      width: 70
    }
  }, label), /*#__PURE__*/React.createElement("span", {
    className: "text-mono font-semibold"
  }, n)))));
}
function Sparkline() {
  const pts = [1, 2, 2, 3, 4, 4, 5, 6, 6, 8];
  const w = 320,
    h = 130,
    max = 8;
  const d = pts.map((p, i) => `${i / (pts.length - 1) * w},${h - 10 - p / max * (h - 30)}`).join(' ');
  return /*#__PURE__*/React.createElement("svg", {
    viewBox: `0 0 ${w} ${h}`,
    style: {
      width: '100%',
      height: 130
    }
  }, /*#__PURE__*/React.createElement("polyline", {
    points: d,
    fill: "none",
    stroke: "#7a60e0",
    strokeWidth: "2.5"
  }), /*#__PURE__*/React.createElement("polyline", {
    points: `0,${h} ${d} ${w},${h}`,
    fill: "rgba(122,96,224,0.12)",
    stroke: "none"
  }), pts.map((p, i) => /*#__PURE__*/React.createElement("circle", {
    key: i,
    cx: i / (pts.length - 1) * w,
    cy: h - 10 - p / max * (h - 30),
    r: "3",
    fill: "#7a60e0"
  })));
}
Object.assign(window, {
  LoginScreen,
  DashboardScreen,
  EngagementsScreen,
  EngagementScreen,
  FindingsScreen,
  FindingDetailScreen
});
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/vulnex/screens.jsx", error: String((e && e.message) || e) }); }

__ds_ns.Avatar = __ds_scope.Avatar;

__ds_ns.Badge = __ds_scope.Badge;

__ds_ns.Button = __ds_scope.Button;

__ds_ns.Card = __ds_scope.Card;

__ds_ns.StatCard = __ds_scope.StatCard;

__ds_ns.KpiStrip = __ds_scope.KpiStrip;

__ds_ns.PhaseStepper = __ds_scope.PhaseStepper;

__ds_ns.Alert = __ds_scope.Alert;

__ds_ns.EmptyState = __ds_scope.EmptyState;

__ds_ns.ProgressBar = __ds_scope.ProgressBar;

__ds_ns.Input = __ds_scope.Input;

__ds_ns.Select = __ds_scope.Select;

__ds_ns.Breadcrumbs = __ds_scope.Breadcrumbs;

__ds_ns.Tabs = __ds_scope.Tabs;

})();
