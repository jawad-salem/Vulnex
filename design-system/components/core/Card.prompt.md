Bordered surface panel — the default content container across the product.

```jsx
<Card title="Recent engagements" actions={<Button size="sm">View all</Button>}>
  <table>…</table>
</Card>
```

Pass `title` and `actions` for a header row; omit both for a plain panel. Use `fit` to stop it stretching to row height inside a grid.
