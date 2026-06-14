Filled-violet / bordered / red-outline action button — use `primary` for the one main action per view, `secondary` for the rest, `danger` for destructive ops.

```jsx
<div className="btn-group">
  <Button variant="primary">+ New engagement</Button>
  <Button>Import</Button>
  <Button variant="danger">Delete</Button>
</div>
```

Variants: `primary` (filled), `secondary` (bordered, default), `danger` (red outline). Sizes: `md`, `sm`. Pass `href` to render an `<a>`, `loading` for a spinner, `fullWidth` for auth forms, and `icon` / `iconRight` for leading/trailing glyphs.
