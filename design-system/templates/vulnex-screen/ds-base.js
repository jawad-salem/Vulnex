// ds-base.js — load the Vulnex design system (styles + compiled component bundle)
// for a template page. One file, one line to repoint when copied into a
// consuming project (change `base`).
(() => {
  const base = '../..'; // → project root of the Vulnex design system
  for (const p of ['styles.css']) {
    const l = document.createElement('link');
    l.rel = 'stylesheet';
    l.href = base + '/' + p;
    document.head.appendChild(l);
  }
  const s = document.createElement('script');
  s.src = base + '/_ds_bundle.js';
  s.onerror = () => console.error(
    'ds-base.js: failed to load ' + s.src +
    ' — in a consuming project point `base` at the bound _ds/<folder> tree relative to this page; ' +
    'in a fresh design system this just means the bundle is not compiled yet.'
  );
  document.head.appendChild(s);
})();
