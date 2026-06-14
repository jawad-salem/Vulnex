Page trail with chevron separators; the last item renders as the current page.

```jsx
<Breadcrumbs items={[
  { label:'Engagements', href:'#' },
  { label:'Acme Corp', href:'#' },
  { label:'Findings' },
]} />
```

Each crumb is `{label, href?}`. Omit `href` on the final item (or any non-link crumb).
