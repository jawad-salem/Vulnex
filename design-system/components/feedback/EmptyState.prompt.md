Centered zero-data state with an accent icon tile, title, subtitle and optional action.

```jsx
<EmptyState
  icon={<i data-lucide="search-x" />}
  title="No findings yet"
  subtitle="Add a finding manually or import from a scanner."
  action={<Button variant="primary">Add first finding</Button>}
/>
```

Place inside a `<Card>`. Provide your own icon node (e.g. a Lucide element).
